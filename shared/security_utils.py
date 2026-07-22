import ctypes
import hashlib
import json
import logging
import os
import sys
from ctypes import wintypes

logger = logging.getLogger(__name__)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_ubyte)),
    ]


def encrypt_password_dpapi(password: str) -> str:
    """Encrypt password using Windows DPAPI. Returns hex string or original password on non-Windows."""
    if sys.platform != 'win32':
        return password
    try:
        data = password.encode('utf-16-le')
        blob_in = DATA_BLOB(len(data), (ctypes.c_ubyte * len(data)).from_buffer_copy(data))
        blob_out = DATA_BLOB()

        ret = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out)
        )

        if ret:
            encrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return encrypted_bytes.hex()
    except Exception as e:
        logger.warning(f"DPAPI encryption failed: {e}")
    return None


def decrypt_password_dpapi(encrypted_hex: str) -> str:
    """Decrypt password using Windows DPAPI. Returns original string or unchanged on non-Windows."""
    if sys.platform != 'win32':
        return encrypted_hex
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        blob_in = DATA_BLOB(len(encrypted_bytes), (ctypes.c_ubyte * len(encrypted_bytes)).from_buffer_copy(encrypted_bytes))
        blob_out = DATA_BLOB()

        ret = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out)
        )

        if ret:
            decrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return decrypted_bytes.decode('utf-16-le')
    except Exception as e:
        logger.warning(f"DPAPI decryption failed: {e}")
    return None


def load_known_servers(known_servers_file: str) -> dict:
    """Load known server fingerprints from JSON file."""
    try:
        if os.path.exists(known_servers_file):
            with open(known_servers_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load known servers file: {e}")
    return {}


def save_known_servers(known_servers: dict, known_servers_file: str):
    """Save known server fingerprints to JSON file."""
    try:
        with open(known_servers_file, 'w', encoding='utf-8') as f:
            json.dump(known_servers, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save known servers file: {e}")


def compute_server_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of server's RSA public key."""
    return hashlib.sha256(public_key_bytes).hexdigest()


def verify_server_fingerprint(
    server_addr: str,
    public_key_bytes: bytes,
    known_servers: dict,
    known_servers_file: str,
    on_new_server: callable = None
) -> bool:
    """Verify server's RSA public key fingerprint (SSH-style trust).

    Args:
        server_addr: Server address string (host:port)
        public_key_bytes: RSA public key in DER/bytes format
        known_servers: Dict of known server fingerprints
        known_servers_file: Path to known_servers JSON file
        on_new_server: Callback for first-time connections. Called with (server_addr, fingerprint).
                       Must return True to accept, False to reject.
                       If None, auto-accepts new servers.

    Returns:
        True if fingerprint is verified/accepted, False otherwise.
    """
    fingerprint = compute_server_fingerprint(public_key_bytes)

    if server_addr in known_servers:
        if fingerprint != known_servers[server_addr]:
            logger.error(f"SECURITY WARNING: Server fingerprint mismatch for {server_addr}!")
            logger.error(f"Expected: {known_servers[server_addr]}")
            logger.error(f"Received: {fingerprint}")
            logger.error("This could be a man-in-the-middle attack!")
            return False
        logger.info(f"Server fingerprint verified for {server_addr}")
        return True

    logger.info(f"First connection to {server_addr}")
    logger.info(f"Server public key fingerprint: {fingerprint}")

    if on_new_server is not None:
        if not on_new_server(server_addr, fingerprint):
            logger.warning("User rejected server fingerprint, connection aborted")
            return False
    else:
        logger.warning("Auto-accepting server fingerprint (no callback provided)")

    known_servers[server_addr] = fingerprint
    save_known_servers(known_servers, known_servers_file)
    logger.info(f"Server fingerprint saved for {server_addr}")
    return True