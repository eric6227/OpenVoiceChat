"""Opus audio codec wrapper using ctypes.

Cross-platform: loads libopus-0.dll (Windows) or libopus.so.0 (Linux).
The library is loaded lazily on first use — importing this module does NOT
trigger a load, so code that doesn't use Opus (e.g., server) won't crash.

Supported frame sizes at 16kHz: 160 (10ms), 320 (20ms), 640 (40ms), 960 (60ms).
"""

import ctypes
import logging
import os
import sys
from ctypes import c_int, c_int32, c_int16, c_ubyte, POINTER, byref

logger = logging.getLogger(__name__)

# --- Opus constants ---
OPUS_APPLICATION_VOIP = 2048
OPUS_APPLICATION_AUDIO = 2049
OPUS_APPLICATION_RESTRICTED_LOWDELAY = 2051

# CTL requests
OPUS_SET_BITRATE_REQUEST = 4002
OPUS_GET_BITRATE_REQUEST = 4003
OPUS_SET_COMPLEXITY_REQUEST = 4010
OPUS_SET_SIGNAL_REQUEST = 4024
OPUS_SET_VBR_REQUEST = 4006
OPUS_SET_VBR_CONSTRAINT_REQUEST = 4020

# Signal types
OPUS_SIGNAL_VOICE = 3001
OPUS_SIGNAL_MUSIC = 3002

# Error codes
OPUS_OK = 0
OPUS_BAD_ARG = -1
OPUS_BUFFER_TOO_SMALL = -2
OPUS_INTERNAL_ERROR = -3
OPUS_INVALID_PACKET = -4
OPUS_UNIMPLEMENTED = -5
OPUS_INVALID_STATE = -6
OPUS_ALLOC_FAIL = -7

# --- Lazy-loaded library handle ---
_opus = None


def _is_windows():
    return sys.platform == 'win32'


def _get_opus_lib_path():
    """Get the path to the Opus shared library for the current platform.

    Windows:
      1. PyInstaller bundle: sys._MEIPASS/libopus-0.dll
      2. Project root: ../libopus-0.dll (relative to this file)

    Linux:
      1. System library: libopus.so.0 (via ldconfig)
      2. Project root: ../libopus.so.0 (bundled with the app)
      3. Common paths: /usr/lib/libopus.so.0, /usr/local/lib/libopus.so.0
    """
    if _is_windows():
        lib_name = 'libopus-0.dll'
    else:
        lib_name = 'libopus.so.0'

    if getattr(sys, 'frozen', False):
        # PyInstaller bundle — DLL is extracted to temp dir
        return os.path.join(sys._MEIPASS, lib_name)

    # Running as script — look in project root first, then system paths
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bundled = os.path.join(project_root, lib_name)
    if os.path.exists(bundled):
        return bundled

    if not _is_windows():
        # On Linux, try system install with just the soname
        return lib_name

    return bundled


def _load_opus_lib():
    """Load the Opus shared library. Lazy — only called on first use."""
    lib_path = _get_opus_lib_path()
    try:
        lib = ctypes.cdll.LoadLibrary(lib_path)
        logger.info(f"Loaded Opus library: {lib_path}")
        return lib
    except OSError as e:
        if _is_windows():
            hint = (
                "Please place libopus-0.dll in the project root directory "
                "or download it from https://github.com/zfkun/opus/releases"
            )
        else:
            hint = (
                "On Linux/Docker, install the Opus library:\n"
                "  apt-get update && apt-get install -y libopus0\n"
                "Or place libopus.so.0 in the project root directory."
            )
        raise RuntimeError(
            f"Cannot load Opus library.\n"
            f"Expected path: {lib_path}\n"
            f"Error: {e}\n"
            f"{hint}"
        )


def _get_opus():
    """Get the lazy-loaded Opus library handle, setting up signatures on first call."""
    global _opus
    if _opus is None:
        _opus = _load_opus_lib()
        _setup_signatures(_opus)
    return _opus


def _setup_signatures(lib):
    """Set up ctypes function signatures for the Opus library."""
    # OpusEncoder *opus_encoder_create(opus_int32 Fs, int channels, int application, int *error);
    lib.opus_encoder_create.argtypes = [c_int32, c_int, c_int, POINTER(c_int)]
    lib.opus_encoder_create.restype = ctypes.c_void_p

    # int opus_encode(OpusEncoder *st, const opus_int16 *pcm, int frame_size,
    #                  unsigned char *data, opus_int32 max_data_bytes);
    lib.opus_encode.argtypes = [
        ctypes.c_void_p, POINTER(c_int16), c_int,
        ctypes.c_void_p, c_int32
    ]
    lib.opus_encode.restype = c_int32

    # void opus_encoder_destroy(OpusEncoder *st);
    lib.opus_encoder_destroy.argtypes = [ctypes.c_void_p]
    lib.opus_encoder_destroy.restype = None

    # OpusDecoder *opus_decoder_create(opus_int32 Fs, int channels, int *error);
    lib.opus_decoder_create.argtypes = [c_int32, c_int, POINTER(c_int)]
    lib.opus_decoder_create.restype = ctypes.c_void_p

    # int opus_decode(OpusDecoder *st, const unsigned char *data, opus_int32 len,
    #                  opus_int16 *pcm, int frame_size, int decode_fec);
    lib.opus_decode.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, c_int32,
        POINTER(c_int16), c_int, c_int
    ]
    lib.opus_decode.restype = c_int32

    # void opus_decoder_destroy(OpusDecoder *st);
    lib.opus_decoder_destroy.argtypes = [ctypes.c_void_p]
    lib.opus_decoder_destroy.restype = None

    # int opus_encoder_ctl(OpusEncoder *st, int request, ...) -- variadic;
    lib.opus_encoder_ctl.argtypes = [ctypes.c_void_p, c_int]
    lib.opus_encoder_ctl.restype = c_int


def _err_str(code):
    """Convert Opus error code to human-readable string."""
    errors = {
        OPUS_OK: "OK",
        OPUS_BAD_ARG: "BAD_ARG",
        OPUS_BUFFER_TOO_SMALL: "BUFFER_TOO_SMALL",
        OPUS_INTERNAL_ERROR: "INTERNAL_ERROR",
        OPUS_INVALID_PACKET: "INVALID_PACKET",
        OPUS_UNIMPLEMENTED: "UNIMPLEMENTED",
        OPUS_INVALID_STATE: "INVALID_STATE",
        OPUS_ALLOC_FAIL: "ALLOC_FAIL",
    }
    return errors.get(code, f"UNKNOWN({code})")


class OpusEncoder:
    """Opus audio encoder for 16-bit mono PCM.

    Usage:
        encoder = OpusEncoder(sample_rate=16000, channels=1, bitrate=32000)
        opus_bytes = encoder.encode(pcm_bytes, frame_size=320)
        encoder.destroy()
    """

    def __init__(self, sample_rate=16000, channels=1, bitrate=32000,
                 complexity=5, application=OPUS_APPLICATION_VOIP):
        self.sample_rate = sample_rate
        self.channels = channels
        opus = _get_opus()

        error = c_int()
        self._encoder = opus.opus_encoder_create(
            c_int32(sample_rate), channels, application, byref(error)
        )
        if error.value != OPUS_OK:
            raise RuntimeError(f"opus_encoder_create failed: {_err_str(error.value)}")

        self._set_ctl(opus, OPUS_SET_BITRATE_REQUEST, bitrate)
        self._set_ctl(opus, OPUS_SET_COMPLEXITY_REQUEST, complexity)
        self._set_ctl(opus, OPUS_SET_SIGNAL_REQUEST, OPUS_SIGNAL_VOICE)
        # Enable constrained VBR for consistent bandwidth
        self._set_ctl(opus, OPUS_SET_VBR_REQUEST, 1)
        self._set_ctl(opus, OPUS_SET_VBR_CONSTRAINT_REQUEST, 1)

        logger.info(
            f"OpusEncoder created: {sample_rate}Hz, {channels}ch, "
            f"{bitrate}bps, complexity={complexity}"
        )

    def _set_ctl(self, opus, request, value):
        ret = opus.opus_encoder_ctl(self._encoder, request, value)
        if ret != OPUS_OK:
            logger.warning(f"opus_encoder_ctl({request}, {value}) failed: {_err_str(ret)}")

    def encode(self, pcm_bytes: bytes, frame_size: int) -> bytes:
        """Encode PCM bytes to Opus compressed bytes.

        Args:
            pcm_bytes: Raw 16-bit little-endian PCM data.
                       Must be frame_size * channels * 2 bytes.
            frame_size: Number of samples per channel (e.g., 320 for 20ms at 16kHz).

        Returns:
            Opus-encoded bytes. Typical size for 32kbps, 20ms: ~80 bytes.
        """
        opus = _get_opus()
        expected_len = frame_size * self.channels * 2
        if len(pcm_bytes) != expected_len:
            raise ValueError(
                f"PCM data length mismatch: expected {expected_len} bytes "
                f"({frame_size} samples x {self.channels} ch x 2 bytes), "
                f"got {len(pcm_bytes)} bytes"
            )

        # Prepare input buffer
        pcm_array = (c_int16 * (frame_size * self.channels))()
        ctypes.memmove(pcm_array, pcm_bytes, len(pcm_bytes))

        # Allocate output buffer (max size: 4000 bytes is more than enough for 20ms frame)
        max_bytes = 4000
        out_buffer = (c_ubyte * max_bytes)()

        num_bytes = opus.opus_encode(
            self._encoder, pcm_array, frame_size, out_buffer, max_bytes
        )
        if num_bytes < 0:
            raise RuntimeError(f"opus_encode failed: {_err_str(num_bytes)}")

        return bytes(out_buffer[:num_bytes])

    def destroy(self):
        """Destroy the encoder and free native resources."""
        if self._encoder:
            _get_opus().opus_encoder_destroy(self._encoder)
            self._encoder = None

    def __del__(self):
        self.destroy()


class OpusDecoder:
    """Opus audio decoder for 16-bit mono PCM.

    Usage:
        decoder = OpusDecoder(sample_rate=16000, channels=1)
        pcm_bytes = decoder.decode(opus_bytes, frame_size=320)
        decoder.destroy()
    """

    def __init__(self, sample_rate=16000, channels=1):
        self.sample_rate = sample_rate
        self.channels = channels
        opus = _get_opus()

        error = c_int()
        self._decoder = opus.opus_decoder_create(
            c_int32(sample_rate), channels, byref(error)
        )
        if error.value != OPUS_OK:
            raise RuntimeError(f"opus_decoder_create failed: {_err_str(error.value)}")

        logger.info(f"OpusDecoder created: {sample_rate}Hz, {channels}ch")

    def decode(self, opus_bytes: bytes, frame_size: int) -> bytes:
        """Decode Opus bytes to PCM bytes.

        Args:
            opus_bytes: Opus-encoded data.
            frame_size: Number of samples per channel expected in output.

        Returns:
            Raw 16-bit little-endian PCM data (frame_size * channels * 2 bytes).
        """
        opus = _get_opus()
        pcm_samples = frame_size * self.channels
        pcm_array = (c_int16 * pcm_samples)()

        result = opus.opus_decode(
            self._decoder,
            ctypes.cast(ctypes.create_string_buffer(opus_bytes, len(opus_bytes)),
                        ctypes.c_void_p),
            c_int32(len(opus_bytes)),
            pcm_array,
            frame_size,
            0  # decode_fec = 0 (no forward error correction)
        )
        if result < 0:
            raise RuntimeError(f"opus_decode failed: {_err_str(result)}")

        if result != frame_size:
            raise RuntimeError(
                f"opus_decode: expected {frame_size} samples, got {result}"
            )

        # Convert C array to bytes
        return bytes((c_ubyte * (pcm_samples * 2)).from_address(
            ctypes.addressof(pcm_array)
        ))

    def destroy(self):
        """Destroy the decoder and free native resources."""
        if self._decoder:
            _get_opus().opus_decoder_destroy(self._decoder)
            self._decoder = None

    def __del__(self):
        self.destroy()