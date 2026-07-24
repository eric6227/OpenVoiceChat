import hashlib
import logging
import queue
import threading

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


class NoncePool:
    """Thread-safe pool of pre-generated nonces for AES-GCM encryption.
    
    get_random_bytes() is a system call that becomes expensive when called
    hundreds of times per second (e.g., when forwarding audio to multiple
    users). This pool pre-generates nonces in batches to eliminate the
    per-call system overhead.
    """
    NONCE_SIZE = 12
    DEFAULT_POOL_SIZE = 200
    REFILL_THRESHOLD = 50

    def __init__(self, pool_size=None):
        if pool_size is None:
            pool_size = self.DEFAULT_POOL_SIZE
        self._pool = queue.Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._refill_count = 0
        self._refill(pool_size)

    def _refill(self, count):
        """Generate a batch of nonces. Called with lock held or during init."""
        for _ in range(count):
            try:
                self._pool.put_nowait(get_random_bytes(self.NONCE_SIZE))
            except queue.Full:
                break

    def get(self) -> bytes:
        """Get a nonce from the pool. Refills if below threshold."""
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._pool.qsize() < self.REFILL_THRESHOLD:
                    self._refill(self.DEFAULT_POOL_SIZE - self._pool.qsize())
            try:
                return self._pool.get(timeout=0.1)
            except queue.Empty:
                return get_random_bytes(self.NONCE_SIZE)


# Global nonce pool shared across all encryptors
_global_nonce_pool = NoncePool()


class AudioEncryptor:
    """AES-256-GCM encryptor/decryptor for audio data (password-based).
    
    Uses random salt prepended to encrypted output for PBKDF2 key derivation.
    Note: This class is deprecated in favor of SessionKeyEncryptor for new code.
    """
    SALT_SIZE = 32

    def __init__(self, password: str):
        self.password = password
        logger.info("AES-256-GCM encryption initialized (password-based)")

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), salt, 100000, dklen=32)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data: returns salt(32) + nonce(12) + tag(16) + ciphertext."""
        salt = get_random_bytes(self.SALT_SIZE)
        key = self._derive_key(salt)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return salt + nonce + tag + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data: expects salt(32) + nonce(12) + tag(16) + ciphertext."""
        if len(data) < self.SALT_SIZE + 28:
            return None
        salt = data[:self.SALT_SIZE]
        nonce = data[self.SALT_SIZE:self.SALT_SIZE + 12]
        tag = data[self.SALT_SIZE + 12:self.SALT_SIZE + 28]
        ciphertext = data[self.SALT_SIZE + 28:]
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return None


class SessionKeyEncryptor:
    """AES-256-GCM encryptor/decryptor using a session key.
    
    Uses a global nonce pool to avoid expensive get_random_bytes() system
    calls on every encryption. This is critical for performance when
    encrypting audio packets at 30+ Hz for multiple recipients.
    """
    def __init__(self, session_key: bytes):
        self.key = session_key
        logger.info("Session key encryption initialized")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data: returns nonce(12) + tag(16) + ciphertext."""
        nonce = _global_nonce_pool.get()
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data: expects nonce(12) + tag(16) + ciphertext."""
        if len(data) < 28:
            return None
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return None