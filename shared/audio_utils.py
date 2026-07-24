import logging
import queue
import struct
import threading
import time
from collections import deque

import shared.constants as consts
from shared.opus_utils import OpusEncoder, OpusDecoder

logger = logging.getLogger(__name__)

# audioop was removed in Python 3.13, use struct-based fallback
try:
    import audioop
    _has_audioop = True
except ModuleNotFoundError:
    _has_audioop = False
    logger.info("audioop not available (Python 3.13+), using struct-based mixing")

# Pre-compiled struct for 16-bit mono mixing (CHUNK=512 samples)
_SAMPLE_COUNT = consts.CHUNK
_STRUCT_UNPACK = struct.Struct(f'<{_SAMPLE_COUNT}h')
_STRUCT_PACK = struct.Struct(f'<{_SAMPLE_COUNT}h')


def _mix_add_16bit(data1: bytes, data2: bytes) -> bytes:
    """Mix two 16-bit little-endian PCM buffers with clipping."""
    if _has_audioop:
        return audioop.add(data1, data2, 2)

    s1 = _STRUCT_UNPACK.unpack(data1)
    s2 = _STRUCT_UNPACK.unpack(data2)
    mixed = [max(-32768, min(32767, a + b)) for a, b in zip(s1, s2)]
    return _STRUCT_PACK.pack(*mixed)


def _mix_mul_16bit(data: bytes, factor: float) -> bytes:
    """Scale 16-bit little-endian PCM buffer by factor with clipping."""
    if _has_audioop:
        return audioop.mul(data, 2, factor)

    samples = _STRUCT_UNPACK.unpack(data)
    scaled = [max(-32768, min(32767, int(s * factor))) for s in samples]
    return _STRUCT_PACK.pack(*scaled)


class AudioCompressor:
    """Opus audio compressor/decompressor for low-bitrate voice transmission.

    Replaces the previous zlib-based compression with the Opus codec,
    achieving ~32 kbps per user instead of ~183 kbps (5.7x bandwidth reduction).

    IMPORTANT: Opus is a stateful codec. Each sender's audio stream must be
    decoded with its own decoder instance. This class maintains a per-user
    decoder pool so that interleaved frames from different users do not
    corrupt each other's decoder state.

    Args:
        level: Kept for backward compatibility. In Opus mode, this is
               ignored - use bitrate parameter instead.
        bitrate: Opus target bitrate in bps (default: 32000 = 32 kbps).
    """
    def __init__(self, level=6, bitrate=32000):
        self.level = level  # Deprecated, kept for interface compatibility
        self.bitrate = bitrate
        self._frame_size = consts.CHUNK  # 320 samples = 20ms at 16kHz
        self._encoder = OpusEncoder(
            sample_rate=consts.RATE,
            channels=consts.CHANNELS,
            bitrate=bitrate
        )
        # Per-user decoders — Opus is stateful, each sender needs its own decoder
        self._decoders = {}  # user_id -> OpusDecoder
        self._decoders_lock = threading.Lock()
        logger.info(
            f"Opus compression initialized: bitrate={bitrate}bps, "
            f"frame_size={self._frame_size} samples "
            f"({self._frame_size * 1000 / consts.RATE:.0f}ms)"
        )

    def compress(self, data: bytes) -> bytes:
        """Compress PCM data using Opus codec.

        Args:
            data: CHUNK * 2 bytes of 16-bit mono PCM (640 bytes at CHUNK=320).

        Returns:
            Opus-encoded bytes (typically ~80 bytes at 32kbps).
        """
        return self._encoder.encode(data, frame_size=self._frame_size)

    def decompress(self, data: bytes, user_id: int = 0) -> bytes:
        """Decompress Opus data back to PCM using per-user decoder.

        Each sender gets their own OpusDecoder instance because Opus is
        stateful — interleaving frames from different senders through a
        single decoder corrupts the decoder state and causes audio artifacts.

        Args:
            data: Opus-encoded bytes.
            user_id: Sender's user ID, used to select the correct decoder.

        Returns:
            CHUNK * 2 bytes of 16-bit mono PCM (640 bytes at CHUNK=320).
        """
        with self._decoders_lock:
            if user_id not in self._decoders:
                self._decoders[user_id] = OpusDecoder(
                    sample_rate=consts.RATE,
                    channels=consts.CHANNELS
                )
            decoder = self._decoders[user_id]
        return decoder.decode(data, frame_size=self._frame_size)

    def remove_user(self, user_id: int):
        """Release the decoder for a disconnected user."""
        with self._decoders_lock:
            decoder = self._decoders.pop(user_id, None)
        if decoder:
            decoder.destroy()

    def destroy(self):
        """Release native Opus encoder/decoder resources."""
        if self._encoder:
            self._encoder.destroy()
            self._encoder = None
        with self._decoders_lock:
            for decoder in self._decoders.values():
                decoder.destroy()
            self._decoders.clear()


class JitterBuffer:
    """Buffer to smooth out network jitter and audio clock drift.
    
    When multiple users on different machines send audio, their hardware
    clocks drift independently (USB devices: 100-500ppm). The buffer
    absorbs this drift, preventing buffer drain/overflow.
    
    Uses a minimum fill level (size/4) before starting playback to prevent
    burst-pause patterns when audio arrives unevenly (e.g., when a new
    user connects and server-side processing causes temporary delays).
    Once playback starts, it continues as long as frames are available.
    
    After a brief gap (buffer empty), enters recovery mode and waits for
    a small re-fill (size/16, min 4 frames) before resuming. This prevents
    the burst-silence-burst pattern when audio delivery is temporarily
    uneven. After a long gap (>2s), fully resets to initial priming.
    """
    def __init__(self, size=None, max_size=None):
        if size is None:
            size = consts.JITTER_BUFFER_SIZE
        if max_size is None:
            max_size = size * 4
        self.size = size
        self.max_size = max_size
        self.buffer = deque()
        self.lock = threading.Lock()
        self.dropped_count = 0
        self._min_fill = size // 4  # Must accumulate this many frames before playing
        self._recover_fill = max(4, size // 16)  # Small re-fill after brief gap
        self._primed = False  # Whether min_fill has been reached at least once
        self._last_pop_time = 0.0  # Last time pop() returned data (for re-prime grace)
        self._in_recovery = False  # True when buffer was empty and recovering

    def push(self, data):
        with self.lock:
            self.buffer.append(data)
            while len(self.buffer) > self.max_size:
                self.buffer.popleft()
                self.dropped_count += 1

    def pop(self):
        with self.lock:
            now = time.time()
            
            if not self._primed:
                # Initial fill: accumulate frames until min_fill to absorb
                # bursty delivery caused by network jitter or server-side delays
                if len(self.buffer) >= self._min_fill:
                    self._primed = True
                    self._last_pop_time = now
                    self._in_recovery = False
                    return self.buffer.popleft()
                return None
            
            # Recovery mode: buffer was empty, frames are arriving again.
            # Wait for a small re-fill to prevent burst-silence-burst pattern.
            if self._in_recovery:
                if len(self.buffer) >= self._recover_fill:
                    self._in_recovery = False
                    self._last_pop_time = now
                    return self.buffer.popleft()
                return None
            
            # Playing: return frames as available.
            if len(self.buffer) > 0:
                self._last_pop_time = now
                return self.buffer.popleft()
            
            # Buffer is empty. Enter recovery mode.
            # Only fully reset _primed after a long gap (real disconnection).
            self._in_recovery = True
            if now - self._last_pop_time > 2.0:
                self._primed = False
                self._in_recovery = False
            
            return None


class AudioPlayer:
    """Multi-stream audio playback with per-user jitter buffers and async mixing.
    
    Each user gets their own JitterBuffer to prevent one user's audio
    from starving another's. The mixer is clocked by the play loop via
    an event: the player signals the mixer before consuming a frame,
    so the mixer produces at exactly the audio hardware clock rate.
    This eliminates clock drift between mixer and player.
    
    The queue (16 slots) absorbs transient timing differences between
    the two threads.
    """
    def __init__(self, p, volume=1.0, output_device=None):
        kwargs = {
            'format': consts.FORMAT,
            'channels': consts.CHANNELS,
            'rate': consts.RATE,
            'output': True,
            'frames_per_buffer': consts.CHUNK
        }
        if output_device is not None:
            kwargs['output_device_index'] = output_device
        self.stream = p.open(**kwargs)
        self.volume = volume
        self._buffers = {}
        self._buffers_lock = threading.Lock()
        self._silence = b'\x00' * (consts.CHUNK * 2)
        self._mix_queue = queue.Queue(maxsize=16)
        self._play_done = threading.Event()
        self.running = True
        self._mix_thread = threading.Thread(target=self._mix_loop, daemon=True)
        self._mix_thread.start()
        self.play_thread = threading.Thread(target=self._play_loop, daemon=True)
        self.play_thread.start()

    def _get_or_create_buffer(self, user_id):
        with self._buffers_lock:
            if user_id not in self._buffers:
                self._buffers[user_id] = JitterBuffer()
            return self._buffers[user_id]

    def _mix_all_buffers(self):
        with self._buffers_lock:
            buffers = list(self._buffers.items())

        if not buffers:
            return None

        mixed = None
        for uid, buf in buffers:
            data = buf.pop()
            if data is None:
                continue

            if mixed is None:
                mixed = data
            else:
                mixed = _mix_add_16bit(mixed, data)

        if mixed is not None and self.volume != 1.0:
            mixed = _mix_mul_16bit(mixed, self.volume)

        return mixed

    def _mix_loop(self):
        """Background thread: mix all user buffers into a single frame.
        
        Clocked by the play loop via an event. The player signals
        before consuming a frame, so the mixer pops JitterBuffers at
        exactly the audio hardware clock rate. This eliminates clock
        drift between mixer and player, preventing progressive buffer
        drain/overflow.
        """
        while self.running:
            self._play_done.wait()
            self._play_done.clear()
            
            try:
                mixed = self._mix_all_buffers()
            except Exception:
                logger.error("Mix loop error", exc_info=True)
                mixed = None
            
            try:
                self._mix_queue.put_nowait(mixed)
            except queue.Full:
                pass

    def _play_loop(self):
        """Play thread: consume mixed frames at the audio hardware rate.
        
        stream.write() blocks for ~32ms, which is the audio clock.
        The player signals the mixer before each write, so the mixer
        produces the next frame while the player is writing.
        """
        while self.running:
            self._play_done.set()
            
            try:
                mixed = self._mix_queue.get(timeout=0.05)
            except queue.Empty:
                mixed = None
            
            try:
                if mixed is not None:
                    self.stream.write(mixed)
                else:
                    self.stream.write(self._silence)
            except Exception:
                logger.error("Play loop error", exc_info=True)
                time.sleep(0.01)
                continue

    def push(self, user_id, data):
        """Push audio data to the jitter buffer for a specific user."""
        self._get_or_create_buffer(user_id).push(data)

    def remove_user(self, user_id):
        """Remove a user's jitter buffer (e.g. on disconnect)."""
        with self._buffers_lock:
            self._buffers.pop(user_id, None)

    def stop(self):
        """Stop playback and close audio stream."""
        self.running = False
        if self._mix_thread.is_alive():
            self._mix_thread.join(timeout=1.0)
        if self.play_thread.is_alive():
            self.play_thread.join(timeout=1.0)
        self.stream.stop_stream()
        self.stream.close()