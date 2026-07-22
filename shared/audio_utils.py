import array
import logging
import threading
import time
import zlib

import shared.constants as consts

logger = logging.getLogger(__name__)


class AudioCompressor:
    """zlib compressor/decompressor for audio data."""
    def __init__(self, level=6):
        self.level = level
        logger.info(f"zlib compression initialized (level: {level})")

    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, self.level)

    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)


class JitterBuffer:
    """Buffer to smooth out network jitter. Waits until full before outputting."""
    def __init__(self, size=None):
        if size is None:
            size = consts.JITTER_BUFFER_SIZE
        self.size = size
        self.buffer = []
        self.lock = threading.Lock()
        self.is_full = False

    def push(self, data):
        with self.lock:
            self.buffer.append(data)
            if not self.is_full and len(self.buffer) >= self.size:
                self.is_full = True

    def pop(self):
        with self.lock:
            if not self.is_full:
                return None

            if len(self.buffer) > 0:
                return self.buffer.pop(0)
            else:
                return b'\x00' * (consts.CHUNK * 2)


class AudioPlayer:
    """Audio playback with jitter buffer and volume control."""
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
        self.jitter_buffer = JitterBuffer()
        self.running = True
        self.play_thread = threading.Thread(target=self._play_loop, daemon=True)
        self.play_thread.start()

    def _play_loop(self):
        """Continuously pull audio from jitter buffer and play."""
        while self.running:
            data = self.jitter_buffer.pop()
            if data:
                if self.volume != 1.0:
                    samples = array.array('h', data)
                    samples = array.array('h', [max(-32768, min(32767, int(s * self.volume))) for s in samples])
                    data = samples.tobytes()
                self.stream.write(data)
            else:
                time.sleep(0.001)

    def push(self, data):
        """Push audio data to jitter buffer."""
        self.jitter_buffer.push(data)

    def stop(self):
        """Stop playback and close audio stream."""
        self.running = False
        if self.play_thread.is_alive():
            self.play_thread.join(timeout=1.0)
        self.stream.stop_stream()
        self.stream.close()