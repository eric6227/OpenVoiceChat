"""Simple RMS-based noise gate for microphone input.

No external dependencies. Operates on 16-bit mono PCM frames.
"""

import array
import math
import logging

logger = logging.getLogger(__name__)


class NoiseSuppressor:
    """RMS-based noise gate for microphone audio.

    When the RMS level of an audio frame is below the threshold,
    the frame is replaced with silence. This effectively removes
    background noise (fan hum, keyboard clicks, etc.) when the
    user is not speaking.

    Args:
        threshold: 0-100, where 0 = off (pass-through) and
                   100 = most aggressive gating. Maps to an RMS
                   threshold of threshold * 327.67 (1% of full scale
                   per step). Default 0 (disabled).
    """

    def __init__(self, threshold: int = 0):
        self.threshold = threshold
        logger.info(f"NoiseSuppressor initialized: threshold={threshold}")

    @property
    def threshold(self):
        return self._threshold

    @threshold.setter
    def threshold(self, value: int):
        self._threshold = max(0, min(100, int(value)))
        # Map 0-100 to RMS threshold 0-32767 (full 16-bit scale)
        self._rms_threshold = self._threshold * 327.67

    def process(self, data: bytes) -> bytes:
        """Apply noise gate to a PCM audio frame.

        Args:
            data: 16-bit mono PCM bytes (CHUNK * 2 bytes).

        Returns:
            Original data if RMS >= threshold, silence otherwise.
        """
        if self._threshold <= 0:
            return data

        # Calculate RMS
        samples = array.array('h', data)
        if len(samples) == 0:
            return data

        sum_sq = sum(s * s for s in samples)
        rms = math.sqrt(sum_sq / len(samples))

        if rms < self._rms_threshold:
            return b'\x00' * len(data)

        return data