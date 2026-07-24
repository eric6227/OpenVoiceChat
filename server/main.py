import socket
import select
import threading
import queue
import struct
import logging
from logging.handlers import RotatingFileHandler
import argparse
import time
import hashlib
import os
import json
import signal
import sys
import zlib
import traceback
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Add shared module to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from shared.constants import (
    MSG_TYPE_JOIN, MSG_TYPE_AUDIO, MSG_TYPE_ADMIN_JOIN,
    MSG_TYPE_USER_LIST, MSG_TYPE_USER_JOINED, MSG_TYPE_HEARTBEAT,
    MSG_TYPE_LEAVE, MSG_TYPE_AUTH_SUCCESS, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_ADMIN_BAN, MSG_TYPE_ADMIN_KICK, MSG_TYPE_BANNED,
    MSG_TYPE_ADMIN_GET_BAN_LIST, MSG_TYPE_BAN_LIST, MSG_TYPE_ADMIN_UNBAN,
    MSG_TYPE_ADMIN_NOT_ONLINE, MSG_TYPE_RECORDING_NOTICE, MSG_TYPE_RECORDING_CONSENT,
    MSG_TYPE_ADMIN_ONLINE, MSG_TYPE_ADMIN_OFFLINE,
    MSG_TYPE_DUPLICATE_NAME,
    MSG_TYPE_TEXT_CHAT, MSG_TYPE_TEXT_MESSAGE,
    MSG_TYPE_UDP_PORT, UDP_AUDIO_PORT,
    MAX_PACKET_SIZE,
)
from shared.crypto import _global_nonce_pool
from shared.rudp import (
    pack_rudp_message, unpack_rudp_message,
    pack_ack, pack_response, pack_request,
    RUDP_FLAG_NEEDS_ACK, RUDP_FLAG_IS_ACK, RUDP_FLAG_IS_RESPONSE,
    RUDP_HEADER_SIZE, RUDPServer,
)

logger = logging.getLogger(__name__)

# Server password for regular clients
_env_password = os.environ.get("OVC_PASSWORD")
if _env_password:
    CLIENT_PASSWORD = _env_password
    logger.info("Using client password from OVC_PASSWORD environment variable")
else:
    logger.error("CRITICAL: OVC_PASSWORD environment variable is not set!")
    logger.error("Please set it before starting the server:")
    logger.error("  Windows: set OVC_PASSWORD=YourSecurePassword")
    logger.error("  Linux/Mac: export OVC_PASSWORD=YourSecurePassword")
    sys.exit(1)

# Admin password
_env_admin_password = os.environ.get("OVC_ADMIN_PASSWORD")
if _env_admin_password:
    ADMIN_PASSWORD = _env_admin_password
    logger.info("Using admin password from OVC_ADMIN_PASSWORD environment variable")
else:
    logger.error("CRITICAL: OVC_ADMIN_PASSWORD environment variable is not set!")
    logger.error("Please set it before starting the server:")
    logger.error("  Windows: set OVC_ADMIN_PASSWORD=YourSecureAdminPassword")
    logger.error("  Linux/Mac: export OVC_ADMIN_PASSWORD=YourSecureAdminPassword")
    sys.exit(1)

HOST = '0.0.0.0'
CLIENT_PORT = 9090
ADMIN_PORT = 9091

REQUIRE_ADMIN = os.environ.get("OVC_REQUIRE_ADMIN", "false").lower() in ("true", "1", "yes")
logger.info(f"Admin required for clients: {REQUIRE_ADMIN}")

AUDIO_PACKET_TIMEOUT_MS = 200

# RUDP server instance for managing reliable communication
rudp_server = RUDPServer()

class ClientInfo:
    """Stores information about a connected client."""
    _next_id = 1
    _id_lock = threading.Lock()
    
    def __init__(self, name, session_key, is_admin=False, device_fingerprints=None, ip_address=None):
        with ClientInfo._id_lock:
            self.user_id = ClientInfo._next_id
            ClientInfo._next_id += 1
        
        self.name = name
        self.session_key = session_key
        self.is_admin = is_admin
        self.device_fingerprints = device_fingerprints or {}
        self.ip_address = ip_address
        self.last_heartbeat = time.time()
        self.udp_addr = None  # (ip, port) for UDP communication

clients = []  # List of ClientInfo (non-admin)
admins = []   # List of ClientInfo (admin)
global_lock = threading.RLock()  # RLock: reentrant, safe for nested acquire
HEARTBEAT_TIMEOUT = 30

# Rate limiting for authentication attempts
auth_rate_limit = {}
auth_rate_lock = threading.Lock()
MAX_AUTH_ATTEMPTS = 5
AUTH_BLOCK_DURATION = 300

def check_auth_rate_limit(ip: str) -> bool:
    now = time.time()
    with auth_rate_lock:
        if ip in auth_rate_limit:
            record = auth_rate_limit[ip]
            if record.get("blocked_until", 0) > now:
                remaining = record["blocked_until"] - now
                logger.warning(f"IP {ip} is rate limited, {remaining:.0f}s remaining")
                return False
            if record.get("blocked_until", 0) <= now and record["attempts"] >= MAX_AUTH_ATTEMPTS:
                auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
                return True
            if now - record.get("last_attempt", 0) > 60:
                auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
                return True
            return True
        else:
            auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
            return True

def record_auth_failure(ip: str):
    now = time.time()
    with auth_rate_lock:
        if ip not in auth_rate_limit:
            auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
        auth_rate_limit[ip]["attempts"] += 1
        auth_rate_limit[ip]["last_attempt"] = now
        if auth_rate_limit[ip]["attempts"] >= MAX_AUTH_ATTEMPTS:
            auth_rate_limit[ip]["blocked_until"] = now + AUTH_BLOCK_DURATION
            logger.warning(f"IP {ip} blocked for {AUTH_BLOCK_DURATION}s due to too many failed attempts")

def record_auth_success(ip: str):
    with auth_rate_lock:
        if ip in auth_rate_limit:
            del auth_rate_limit[ip]

# Device fingerprint database
device_fingerprint_db = {}
device_db_lock = threading.Lock()
DEVICE_DB_FILE = os.path.join(os.path.dirname(__file__), 'device_fingerprints.json')

# Ban list
ban_list = {}
ban_list_lock = threading.Lock()
BAN_LIST_FILE = os.path.join(os.path.dirname(__file__), 'ban_list.json')
IP_BAN_DURATION_DAYS = 7

# Audio recording configuration
RECORDING_ENABLED = os.environ.get("OVC_RECORDING_ENABLED", "false").lower() == "true"
RECORDING_DIR = os.environ.get("OVC_RECORDING_DIR", os.path.join(os.path.dirname(__file__), 'recordings'))
RECORDING_DURATION_MINUTES = int(os.environ.get("OVC_RECORDING_DURATION", "5"))
RECORDING_MAX_SIZE_MB = int(os.environ.get("OVC_RECORDING_MAX_SIZE", "10240"))
RECORDING_RETENTION_DAYS = int(os.environ.get("OVC_RECORDING_RETENTION", "30"))
RECORDING_SAMPLE_RATE = 16000
RECORDING_CHANNELS = 1
RECORDING_SAMPLE_WIDTH = 4

if RECORDING_ENABLED:
    logger.warning("AUDIO RECORDING IS ENABLED - Ensure you have user consent and comply with privacy laws")

import wave

class AudioRecorder:
    def __init__(self):
        self.recordings = {}
        self.lock = threading.RLock()
        self.max_file_bytes = RECORDING_DURATION_MINUTES * 60 * RECORDING_SAMPLE_RATE * RECORDING_CHANNELS * RECORDING_SAMPLE_WIDTH
        self.max_total_bytes = RECORDING_MAX_SIZE_MB * 1024 * 1024
        if RECORDING_ENABLED:
            os.makedirs(RECORDING_DIR, exist_ok=True)
    
    def start_recording(self, user_name):
        if not RECORDING_ENABLED:
            return
        with self.lock:
            if user_name in self.recordings:
                return
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{user_name}_{timestamp}.wav"
            filepath = os.path.join(RECORDING_DIR, filename)
            try:
                wf = wave.open(filepath, 'wb')
                wf.setnchannels(RECORDING_CHANNELS)
                wf.setsampwidth(RECORDING_SAMPLE_WIDTH)
                wf.setframerate(RECORDING_SAMPLE_RATE)
                self.recordings[user_name] = {
                    "file": wf,
                    "path": filepath,
                    "size": 0,
                    "start_time": time.time()
                }
                logger.info(f"Started recording for {user_name}: {filepath}")
            except Exception as e:
                logger.error(f"Failed to start recording for {user_name}: {e}")
    
    def write_audio(self, user_name, pcm_data):
        if not RECORDING_ENABLED:
            return
        with self.lock:
            if user_name not in self.recordings:
                return
            rec = self.recordings[user_name]
            try:
                rec["file"].writeframes(pcm_data)
                rec["size"] += len(pcm_data)
                if rec["size"] >= self.max_file_bytes:
                    self._rotate_file(user_name)
            except Exception as e:
                logger.error(f"Error writing audio for {user_name}: {e}")
    
    def _rotate_file(self, user_name):
        rec = self.recordings[user_name]
        try:
            rec["file"].close()
        except:
            pass
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{user_name}_{timestamp}.wav"
        filepath = os.path.join(RECORDING_DIR, filename)
        try:
            wf = wave.open(filepath, 'wb')
            wf.setnchannels(RECORDING_CHANNELS)
            wf.setsampwidth(RECORDING_SAMPLE_WIDTH)
            wf.setframerate(RECORDING_SAMPLE_RATE)
            self.recordings[user_name] = {
                "file": wf,
                "path": filepath,
                "size": 0,
                "start_time": time.time()
            }
            logger.info(f"Rotated recording for {user_name}: {filepath}")
        except Exception as e:
            logger.error(f"Failed to rotate recording for {user_name}: {e}")
    
    def stop_recording(self, user_name):
        with self.lock:
            if user_name in self.recordings:
                rec = self.recordings.pop(user_name)
                try:
                    rec["file"].close()
                    logger.info(f"Stopped recording for {user_name}: {rec['path']}")
                except Exception as e:
                    logger.error(f"Error closing recording for {user_name}: {e}")
    
    def stop_all(self):
        with self.lock:
            for user_name in list(self.recordings.keys()):
                self.stop_recording(user_name)

audio_recorder = AudioRecorder()

# Recording and admin forward queues
_recording_queue = queue.Queue(maxsize=2000)
_admin_forward_queue = queue.Queue(maxsize=2000)
_client_forward_queue = queue.Queue(maxsize=2000)
_recording_running = threading.Event()
_admin_forward_running = threading.Event()
_client_forward_running = threading.Event()

def admin_forward_thread():
    """Thread that re-encrypts client audio and forwards to all admins."""
    logger.info("Admin forward thread started")
    
    while _admin_forward_running.is_set():
        try:
            sender_id, sender_name, decrypted_audio = _admin_forward_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        
        try:
            with global_lock:
                current_admins = list(admins)
            
            if not current_admins:
                continue
            
            sender_name_bytes = sender_name.encode('utf-8')
            common_prefix = (
                struct.pack('!B', MSG_TYPE_AUDIO) +
                struct.pack('!I', sender_id) +
                struct.pack('!B', len(sender_name_bytes)) +
                sender_name_bytes +
                struct.pack('!d', time.time())
            )
            
            for admin in current_admins:
                if not admin.udp_addr:
                    continue
                re_encrypted = server_encrypt_with_key(decrypted_audio, admin.session_key)
                re_packet = common_prefix + struct.pack('!I', len(re_encrypted)) + re_encrypted
                try:
                    _udp_admin_sock.sendto(re_packet, admin.udp_addr)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Admin forward error: {e}")
    
    logger.info("Admin forward thread stopped")

def client_forward_thread():
    """Thread that re-encrypts client audio and forwards to other clients.
    
    Separated from the main UDP receive loop to prevent re-encryption
    overhead from blocking packet reception. This is critical for 3+ users
    where each packet triggers multiple re-encryptions.
    """
    logger.info("Client forward thread started")
    
    while _client_forward_running.is_set():
        try:
            sender_id, sender_name, decrypted_audio = _client_forward_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        
        try:
            with global_lock:
                all_clients = list(clients)
            
            sender_name_bytes = sender_name.encode('utf-8')
            common_prefix = (
                struct.pack('!B', MSG_TYPE_AUDIO) +
                struct.pack('!I', sender_id) +
                struct.pack('!B', len(sender_name_bytes)) +
                sender_name_bytes +
                struct.pack('!d', time.time())
            )
            
            for recipient in all_clients:
                if recipient.user_id == sender_id or not recipient.udp_addr:
                    continue
                re_encrypted = server_encrypt_with_key(decrypted_audio, recipient.session_key)
                if re_encrypted is None:
                    continue
                re_packet = common_prefix + struct.pack('!I', len(re_encrypted)) + re_encrypted
                try:
                    _udp_client_sock.sendto(re_packet, recipient.udp_addr)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Client forward error: {e}")
    
    logger.info("Client forward thread stopped")

def recording_thread_loop():
    """Thread that writes audio to disk."""
    logger.info("Recording thread started")
    
    while _recording_running.is_set():
        try:
            user_name, pcm_data = _recording_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        
        try:
            audio_recorder.write_audio(user_name, pcm_data)
        except Exception as e:
            logger.error(f"Recording thread error: {e}")
    
    logger.info("Recording thread stopped")

def start_recording_thread():
    _recording_running.set()
    t = threading.Thread(target=recording_thread_loop, daemon=True)
    t.start()

def stop_recording_thread():
    _recording_running.clear()

def start_admin_forward_thread():
    _admin_forward_running.set()
    t = threading.Thread(target=admin_forward_thread, daemon=True)
    t.start()

def stop_admin_forward_thread():
    _admin_forward_running.clear()

def start_client_forward_thread():
    _client_forward_running.set()
    t = threading.Thread(target=client_forward_thread, daemon=True)
    t.start()

def stop_client_forward_thread():
    _client_forward_running.clear()

# ============ Periodic User List Broadcast ============

def periodic_user_list_broadcast():
    """Periodically broadcast user list to all clients to ensure consistency."""
    while _server_running.is_set():
        time.sleep(5)
        if not _server_running.is_set():
            break
        try:
            broadcast_user_list()
            broadcast_user_list_to_admins()
        except Exception as e:
            logger.error(f"Periodic user list broadcast error: {e}")

def start_user_list_broadcast():
    t = threading.Thread(target=periodic_user_list_broadcast, daemon=True)
    t.start()

# ============ Load/Save utilities ============

def load_ban_list():
    global ban_list
    if os.path.exists(BAN_LIST_FILE):
        try:
            with open(BAN_LIST_FILE, 'r', encoding='utf-8') as f:
                ban_list = json.load(f)
            logger.info(f"Loaded ban list with {len(ban_list)} entries")
        except Exception as e:
            logger.error(f"Failed to load ban list: {e}")

def clean_expired_ip_bans():
    now = datetime.now()
    expired = []
    for fingerprint, info in list(ban_list.items()):
        if info.get("type") == "ip" and "expires_at" in info:
            try:
                expires_at = datetime.fromisoformat(info["expires_at"])
                if now > expires_at:
                    expired.append(fingerprint)
            except:
                pass
    for fingerprint in expired:
        del ban_list[fingerprint]
        logger.info(f"Expired IP ban removed: {fingerprint}")

def save_ban_list():
    try:
        with open(BAN_LIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(ban_list, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Failed to save ban list: {e}")

def is_device_banned(fingerprints: dict) -> tuple:
    for fp_type, fp_value in fingerprints.items():
        if fp_value and fp_value in ban_list:
            return (True, fp_type)
    return (False, None)

def ban_device(fingerprints: dict, admin_name: str, reason: str = ""):
    now = datetime.now().isoformat()
    for fp_type, fp_value in fingerprints.items():
        if fp_value and fp_value not in ban_list:
            ban_entry = {
                "type": fp_type,
                "banned_at": now,
                "banned_by": admin_name,
                "reason": reason
            }
            if fp_type == "ip":
                expires = datetime.now() + timedelta(days=IP_BAN_DURATION_DAYS)
                ban_entry["expires_at"] = expires.isoformat()
            ban_list[fp_value] = ban_entry
            logger.info(f"Banned device ({fp_type}): {fp_value} by {admin_name}")
    save_ban_list()

def unban_device(fingerprint: str):
    if fingerprint in ban_list:
        del ban_list[fingerprint]
        save_ban_list()
        return True
    return False

def get_ban_list_grouped() -> list:
    groups = {}
    for fingerprint, info in ban_list.items():
        key = info.get("banned_at", "unknown") + "_" + info.get("banned_by", "unknown")
        if key not in groups:
            groups[key] = {
                "device_id": key,
                "fingerprints": [],
                "names": [],
                "ips": [],
                "banned_at": info.get("banned_at"),
                "first_banned": info.get("banned_at"),  # alias for admin compatibility
                "banned_by": info.get("banned_by"),
                "reason": info.get("reason", ""),
                "expires_at": info.get("expires_at", "")
            }
        fp_type = info.get("type", "unknown")
        groups[key]["fingerprints"].append({
            "type": fp_type,
            "value": fingerprint,
            "value_short": fingerprint[:8] + "..." if len(fingerprint) > 10 else fingerprint,
            "reason": info.get("reason", ""),
            "expires_at": info.get("expires_at", "")
        })
        # Look up names and IPs from device fingerprint database
        if fp_type != "ip" and fingerprint in device_fingerprint_db:
            db_entry = device_fingerprint_db[fingerprint]
            for name in db_entry.get("names", []):
                if name not in groups[key]["names"]:
                    groups[key]["names"].append(name)
            for ip in db_entry.get("ips", []):
                if ip not in groups[key]["ips"]:
                    groups[key]["ips"].append(ip)
    return list(groups.values())

def unban_device_group(device_key: str) -> bool:
    removed = False
    for fingerprint, info in list(ban_list.items()):
        key = info.get("banned_at", "unknown") + "_" + info.get("banned_by", "unknown")
        if key == device_key:
            del ban_list[fingerprint]
            removed = True
    if removed:
        save_ban_list()
    return removed

def load_device_db():
    global device_fingerprint_db
    if os.path.exists(DEVICE_DB_FILE):
        try:
            with open(DEVICE_DB_FILE, 'r', encoding='utf-8') as f:
                device_fingerprint_db = json.load(f)
            logger.info(f"Loaded device fingerprint database")
        except Exception as e:
            logger.error(f"Failed to load device fingerprint DB: {e}")

def save_device_db():
    try:
        with open(DEVICE_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(device_fingerprint_db, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Failed to save device fingerprint DB: {e}")

def update_device_fingerprint(fingerprints: dict, name: str, ip: str):
    with device_db_lock:
        for fp_type, fp_value in fingerprints.items():
            if fp_value and fp_type != "ip":
                if fp_value not in device_fingerprint_db:
                    device_fingerprint_db[fp_value] = {"names": [], "ips": [], "last_seen": ""}
                entry = device_fingerprint_db[fp_value]
                if name not in entry["names"]:
                    entry["names"].append(name)
                if ip not in entry["ips"]:
                    entry["ips"].append(ip)
                entry["last_seen"] = datetime.now().isoformat()
        save_device_db()

# ============ Encryption/Decryption ============

def server_decrypt_with_key(data: bytes, key: bytes) -> bytes:
    try:
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return None

def server_encrypt_with_key(data: bytes, key: bytes) -> bytes:
    try:
        nonce = _global_nonce_pool.get()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext
    except Exception:
        return None

# ============ Broadcasting ============

def _send_raw_udp(sock, addr, msg_type, payload):
    """Send a fire-and-forget UDP message (no ACK, no retransmission).
    
    Uses RUDP format for client compatibility but with flags=0 so
    clients don't send ACKs. This avoids RUDP retransmission storms
    when the socket is congested with audio packets.
    Periodic broadcasts provide reliability instead.
    """
    import random
    seq_num = random.randint(0, 0xFFFF)
    packet = pack_rudp_message(msg_type, seq_num, 0, payload)
    try:
        sock.sendto(packet, addr)
    except Exception:
        pass

def broadcast_user_list():
    with global_lock:
        user_list = [{"id": c.user_id, "name": c.name} for c in clients]
        users_json = json.dumps(user_list)
        clients_snapshot = list(clients)  # Copy to safely iterate outside lock
    
    for c in clients_snapshot:
        if c.udp_addr:
            encrypted = server_encrypt_with_key(users_json.encode('utf-8'), c.session_key)
            if encrypted:
                _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_USER_LIST, encrypted)

def broadcast_user_list_to_admins():
    with global_lock:
        detailed = []
        for c in clients:
            detailed.append({
                "id": c.user_id,
                "name": c.name,
                "ip": c.ip_address,
                "fingerprints": {k: v[:16] + "..." if len(v) > 16 else v for k, v in c.device_fingerprints.items()}
            })
        users_json = json.dumps(detailed)
        admins_snapshot = list(admins)  # Copy to safely iterate outside lock
    
    for a in admins_snapshot:
        if a.udp_addr:
            encrypted = server_encrypt_with_key(users_json.encode('utf-8'), a.session_key)
            if encrypted:
                _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_USER_LIST, encrypted)

def broadcast_user_event(event_type, name):
    event_data = f"{name} has {event_type}"
    with global_lock:
        clients_snapshot = list(clients)
        admins_snapshot = list(admins)
    for c in clients_snapshot:
        if c.udp_addr:
            encrypted = server_encrypt_with_key(event_data.encode('utf-8'), c.session_key)
            if encrypted:
                _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_USER_JOINED, encrypted)
    for a in admins_snapshot:
        if a.udp_addr:
            encrypted = server_encrypt_with_key(event_data.encode('utf-8'), a.session_key)
            if encrypted:
                _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_USER_JOINED, encrypted)

def broadcast_admin_status(status_msg_type):
    """Broadcast admin online/offline status to all clients."""
    with global_lock:
        clients_snapshot = list(clients)
    for c in clients_snapshot:
        if c.udp_addr:
            _send_raw_udp(_udp_client_sock, c.udp_addr, status_msg_type, b'')

def broadcast_ban_list_to_admins():
    ban_list_data = get_ban_list_grouped()
    ban_list_json = json.dumps(ban_list_data)
    with global_lock:
        admins_snapshot = list(admins)
    for a in admins_snapshot:
        if a.udp_addr:
            encrypted = server_encrypt_with_key(ban_list_json.encode('utf-8'), a.session_key)
            if encrypted:
                _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_BAN_LIST, encrypted)

# ============ UDP Sockets ============
_udp_client_sock = None  # Port 9090 for clients
_udp_admin_sock = None   # Port 9091 for admins
_server_running = threading.Event()

def send_recording_notice(addr, user_name: str, session_key: bytes):
    """Send recording notice to a client via RUDP."""
    purpose = "Quality monitoring and service improvement"
    purpose_bytes = purpose.encode('utf-8')
    payload = (
        struct.pack('!B', 1 if RECORDING_ENABLED else 0) +
        struct.pack('!I', len(purpose_bytes)) +
        purpose_bytes +
        struct.pack('!I', RECORDING_DURATION_MINUTES) +
        struct.pack('!I', RECORDING_MAX_SIZE_MB)
    )
    encrypted = server_encrypt_with_key(payload, session_key)
    if encrypted:
        _send_raw_udp(_udp_client_sock, addr, MSG_TYPE_RECORDING_NOTICE, encrypted)

# ============ Auth Handlers ============

def handle_client_auth_step1(data, addr, seq_num):
    """Handle RSA key request from client."""
    logger.info(f"Client {addr} requesting RSA key")
    pub_key_len = len(public_key_bytes)
    rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_JOIN, seq_num,
                              struct.pack('!I', pub_key_len) + public_key_bytes)

def handle_client_auth_step2(data, addr, seq_num):
    """Handle JOIN message from client.
    
    Note: This runs in a background thread to avoid blocking the UDP
    receive loop with CPU-heavy RSA decryption and PBKDF2 operations.
    """
    client_ip = addr[0]
    
    # Guard: if this address is already connected, this is a duplicate
    # request (e.g., RUDP retransmission before auth completed). Ignore it.
    with global_lock:
        for c in clients:
            if c.udp_addr == addr:
                logger.debug(f"Client {addr} already connected, ignoring duplicate auth")
                return
    
    if not check_auth_rate_limit(client_ip):
        logger.warning(f"Client {addr} rate limited")
        rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
        return
    
    try:
        # Parse JOIN packet: [name_len(4)][name][encrypted_password_len(4)][encrypted_password][fingerprints_len(4)][fingerprints_json]
        if len(data) < 8:
            return
        offset = 0
        name_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if name_len == 0 or name_len > 128:
            return
        if len(data) < offset + name_len:
            return
        name = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
        
        encrypted_password_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if encrypted_password_len == 0 or encrypted_password_len > 512:
            return
        if len(data) < offset + encrypted_password_len:
            return
        encrypted_password = data[offset:offset+encrypted_password_len]
        offset += encrypted_password_len
        
        fingerprints_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if fingerprints_len == 0 or fingerprints_len > 1024:
            return
        if len(data) < offset + fingerprints_len:
            return
        fingerprints_json = data[offset:offset+fingerprints_len].decode('utf-8')
        
        # Decrypt password
        try:
            cipher = PKCS1_OAEP.new(server_rsa_key)
            password = cipher.decrypt(encrypted_password).decode('utf-8')
        except Exception as e:
            logger.warning(f"Client [{name}] failed to decrypt password: {e}")
            rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
            return
        
        if password != CLIENT_PASSWORD:
            logger.warning(f"Client [{name}] authentication failed from {addr} (wrong password)")
            record_auth_failure(client_ip)
            rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
            return
        
        # Parse device fingerprints
        try:
            device_fingerprints = json.loads(fingerprints_json)
            fp_summary = f"MAC:{device_fingerprints.get('mac', 'N/A')[:16]} CPU:{device_fingerprints.get('cpu', 'N/A')[:16]}"
            logger.info(f"Client [{name}] device fingerprints: {fp_summary}")
        except Exception as e:
            logger.warning(f"Client [{name}] failed to parse device fingerprints: {e}")
            device_fingerprints = {}
        
        # Update device fingerprint database
        update_device_fingerprint(device_fingerprints, name, client_ip)
        
        # Add IP for banning
        device_fingerprints_with_ip = dict(device_fingerprints)
        device_fingerprints_with_ip['ip'] = client_ip
        
        # Check non-compliant hardware
        missing_fps = [fp_type for fp_type, fp_value in device_fingerprints.items() if fp_type != 'ip' and not fp_value]
        if missing_fps:
            logger.warning(f"Client [{name}] non-compliant hardware: missing {', '.join(missing_fps)}")
            ban_device(device_fingerprints_with_ip, "system", "Non-compliant hardware")
            rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_BANNED, seq_num)
            return
        
        # Check admin online status (don't reject, just note for later notification)
        with global_lock:
            admin_offline = (len(admins) == 0 and REQUIRE_ADMIN)
        if admin_offline:
            logger.info(f"Client [{name}] connecting while admin offline, will notify")
        
        # Check duplicate name
        with global_lock:
            for c in clients:
                if c.name == name:
                    logger.warning(f"Client [{name}] rejected: duplicate name")
                    rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_DUPLICATE_NAME, seq_num)
                    return
        
        # Check ban
        is_banned, banned_type = is_device_banned(device_fingerprints_with_ip)
        if is_banned:
            logger.warning(f"Client [{name}] connection rejected: device banned ({banned_type})")
            rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_BANNED, seq_num)
            return
        
        record_auth_success(client_ip)
        
        # Generate session key
        session_key = get_random_bytes(32)
        salt = get_random_bytes(32)
        derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
        nonce = get_random_bytes(12)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
        
        # Create client info
        client_info = ClientInfo(name, session_key, is_admin=False, device_fingerprints=device_fingerprints, ip_address=client_ip)
        client_info.udp_addr = addr
        
        with global_lock:
            clients.append(client_info)
            logger.info(f"User [{name}] joined and authenticated (total: {len(clients)})")
        
        # Send auth success with session key and user_id
        response = salt + nonce + tag + encrypted_session_key + struct.pack('!I', client_info.user_id)
        rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_AUTH_SUCCESS, seq_num, response)
        
        # Send recording notice
        send_recording_notice(addr, name, session_key)
        
        # Notify client if admin is offline
        if admin_offline:
            _send_raw_udp(_udp_client_sock, addr, MSG_TYPE_ADMIN_OFFLINE, b'')
            logger.info(f"Notified client [{name}] that admin is offline")
        
        # Start recording
        audio_recorder.start_recording(name)
        
        # Broadcast
        broadcast_user_event("joined", name)
        broadcast_user_list()
        broadcast_user_list_to_admins()
        
        logger.info(f"Client [{name}] authenticated successfully, user_id={client_info.user_id}")
        
    except Exception as e:
        logger.error(f"Error in client auth: {e}")
        logger.error(traceback.format_exc())

def handle_admin_auth(data, addr, seq_num):
    """Handle admin JOIN message.
    
    Note: This runs in a background thread to avoid blocking the UDP
    receive loop with CPU-heavy RSA decryption and PBKDF2 operations.
    """
    client_ip = addr[0]
    
    # Guard: if this address is already connected, ignore duplicate
    with global_lock:
        for a in admins:
            if a.udp_addr == addr:
                logger.debug(f"Admin {addr} already connected, ignoring duplicate auth")
                return
    
    if not check_auth_rate_limit(client_ip):
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
        return
    
    try:
        # Same format as client JOIN
        if len(data) < 8:
            return
        offset = 0
        name_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if name_len == 0 or name_len > 128:
            return
        if len(data) < offset + name_len:
            return
        name = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
        
        encrypted_password_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if encrypted_password_len == 0 or encrypted_password_len > 512:
            return
        if len(data) < offset + encrypted_password_len:
            return
        encrypted_password = data[offset:offset+encrypted_password_len]
        offset += encrypted_password_len
        
        fingerprints_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        if fingerprints_len == 0 or fingerprints_len > 1024:
            return
        if len(data) < offset + fingerprints_len:
            return
        fingerprints_json = data[offset:offset+fingerprints_len].decode('utf-8')
        
        try:
            cipher = PKCS1_OAEP.new(server_rsa_key)
            password = cipher.decrypt(encrypted_password).decode('utf-8')
        except Exception as e:
            logger.warning(f"Admin [{name}] failed to decrypt password: {e}")
            rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
            return
        
        if password != ADMIN_PASSWORD:
            logger.warning(f"Admin [{name}] authentication failed from {addr}")
            record_auth_failure(client_ip)
            rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_AUTH_FAIL, seq_num)
            return
        
        try:
            device_fingerprints = json.loads(fingerprints_json)
            fp_summary = f"MAC:{device_fingerprints.get('mac', 'N/A')[:16]} CPU:{device_fingerprints.get('cpu', 'N/A')[:16]}"
            logger.info(f"Admin [{name}] device fingerprints: {fp_summary}")
        except:
            device_fingerprints = {}
        
        update_device_fingerprint(device_fingerprints, name, client_ip)
        
        session_key = get_random_bytes(32)
        salt = get_random_bytes(32)
        derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
        nonce = get_random_bytes(12)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
        
        client_info = ClientInfo(name, session_key, is_admin=True, device_fingerprints=device_fingerprints)
        client_info.udp_addr = addr
        
        with global_lock:
            admins.append(client_info)
            logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)})")
        
        response = salt + nonce + tag + encrypted_session_key + struct.pack('!I', client_info.user_id)
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_AUTH_SUCCESS, seq_num, response)
        
        broadcast_user_list_to_admins()
        
        # Notify all clients that admin is now online
        if REQUIRE_ADMIN:
            with global_lock:
                has_clients = len(clients) > 0
            if has_clients:
                broadcast_admin_status(MSG_TYPE_ADMIN_ONLINE)
                logger.info(f"Notified {len(clients)} clients that admin is online")
        
        logger.info(f"Admin [{name}] authenticated successfully, user_id={client_info.user_id}")
        
    except Exception as e:
        logger.error(f"Error in admin auth: {e}")
        logger.error(traceback.format_exc())

# ============ Message Handlers ============

def handle_client_message(msg_type, seq_num, flags, payload, addr):
    """Handle a control message from a client."""
    client_ip = addr[0]
    
    # Find the client
    client_info = None
    with global_lock:
        for c in clients:
            if c.udp_addr == addr:
                client_info = c
                break
    
    if client_info is None:
        # Not authenticated yet
        if msg_type == MSG_TYPE_JOIN:
            if len(payload) == 0:
                # Empty payload = RSA key request
                handle_client_auth_step1(payload, addr, seq_num)
            else:
                # Offload auth to background thread to avoid blocking
                # the UDP receive loop (RSA decrypt + PBKDF2 are CPU-heavy
                # and would cause audio packet bursts/delays for all users)
                threading.Thread(
                    target=handle_client_auth_step2,
                    args=(payload, addr, seq_num),
                    daemon=True
                ).start()
        else:
            logger.warning(f"Unknown message type {msg_type} from unauthenticated client {addr}")
        return
    
    if msg_type == MSG_TYPE_HEARTBEAT:
        client_info.last_heartbeat = time.time()
        # Send ACK (no need)
        #rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_HEARTBEAT, seq_num)
    
    elif msg_type == MSG_TYPE_LEAVE:
        logger.info(f"Client [{client_info.name}] requested leave")
        remove_client(client_info)
    
    elif msg_type == MSG_TYPE_RECORDING_CONSENT:
        # Decrypt consent
        decrypted = server_decrypt_with_key(payload, client_info.session_key)
        if decrypted:
            logger.info(f"Client [{client_info.name}] recording consent: {decrypted}")
        # Send ACK (no need)
        #rudp_server.send_response(_udp_client_sock, addr, MSG_TYPE_RECORDING_CONSENT, seq_num)
    
    elif msg_type == MSG_TYPE_TEXT_CHAT:
        # Server-side admin gate: if REQUIRE_ADMIN and no admin online, discard
        if REQUIRE_ADMIN:
            with global_lock:
                admin_online = len(admins) > 0
            if not admin_online:
                logger.info(f"Text message from [{client_info.name}] discarded: no admin online")
                return
        
        decrypted = server_decrypt_with_key(payload, client_info.session_key)
        if decrypted:
            try:
                text = decrypted.decode('utf-8')
                logging.getLogger("chat").info(f"Chat from [{client_info.name}]: {text[:100]}{'...' if len(text) > 100 else ''}")
                handle_text_message(client_info.name, text, addr)
            except Exception as e:
                logger.error(f"Failed to decode text message from [{client_info.name}]: {e}")

def handle_admin_message(msg_type, seq_num, flags, payload, addr):
    """Handle a control message from an admin."""
    # Find the admin
    admin_info = None
    with global_lock:
        for a in admins:
            if a.udp_addr == addr:
                admin_info = a
                break
    
    if admin_info is None:
        if msg_type == MSG_TYPE_ADMIN_JOIN:
            if len(payload) == 0:
                # Empty payload = RSA key request
                pub_key_len = len(public_key_bytes)
                rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_ADMIN_JOIN, seq_num,
                                          struct.pack('!I', pub_key_len) + public_key_bytes)
            else:
                # Offload auth to background thread to avoid blocking
                # the UDP receive loop (RSA decrypt + PBKDF2 are CPU-heavy)
                threading.Thread(
                    target=handle_admin_auth,
                    args=(payload, addr, seq_num),
                    daemon=True
                ).start()
        else:
            logger.warning(f"Unknown message type {msg_type} from unauthenticated admin {addr}")
        return
    
    if msg_type == MSG_TYPE_HEARTBEAT:
        admin_info.last_heartbeat = time.time()
        # Send ACK (no need)
        #rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_HEARTBEAT, seq_num)
    
    elif msg_type == MSG_TYPE_LEAVE:
        logger.info(f"Admin [{admin_info.name}] requested leave")
        remove_admin(admin_info)
    
    elif msg_type == MSG_TYPE_ADMIN_BAN:
        # Strip the 4-byte length prefix added by admin
        decrypted = server_decrypt_with_key(payload[4:], admin_info.session_key)
        if decrypted:
            try:
                ban_data = json.loads(decrypted.decode('utf-8'))
                target_user_id = ban_data.get("user_id")
                reason = ban_data.get("reason", "")
                with global_lock:
                    for c in clients:
                        if c.user_id == target_user_id:
                            device_fingerprints_with_ip = dict(c.device_fingerprints)
                            device_fingerprints_with_ip['ip'] = c.ip_address
                            ban_device(device_fingerprints_with_ip, admin_info.name, reason)
                            # Kick the user
                            _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_BANNED, b'')
                            remove_client(c)
                            break
                broadcast_ban_list_to_admins()
            except Exception as e:
                logger.error(f"Error processing ban: {e}")
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_ADMIN_BAN, seq_num)
    
    elif msg_type == MSG_TYPE_ADMIN_GET_BAN_LIST:
        broadcast_ban_list_to_admins()
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_ADMIN_GET_BAN_LIST, seq_num)
    
    elif msg_type == MSG_TYPE_ADMIN_UNBAN:
        # Strip the 4-byte length prefix added by admin
        decrypted = server_decrypt_with_key(payload[4:], admin_info.session_key)
        if decrypted:
            try:
                unban_data = json.loads(decrypted.decode('utf-8'))
                device_key = unban_data.get("device_key")
                if device_key:
                    unban_device_group(device_key)
                    broadcast_ban_list_to_admins()
            except Exception as e:
                logger.error(f"Error processing unban: {e}")
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_ADMIN_UNBAN, seq_num)
    
    elif msg_type == MSG_TYPE_ADMIN_KICK:
        # Strip the 4-byte length prefix added by admin
        decrypted = server_decrypt_with_key(payload[4:], admin_info.session_key)
        if decrypted:
            try:
                kick_data = json.loads(decrypted.decode('utf-8'))
                target_user_id = kick_data.get("user_id")
                with global_lock:
                    for c in clients:
                        if c.user_id == target_user_id:
                            _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_LEAVE, b'')
                            remove_client(c)
                            break
            except Exception as e:
                logger.error(f"Error processing kick: {e}")
        rudp_server.send_response(_udp_admin_sock, addr, MSG_TYPE_ADMIN_KICK, seq_num)
    
    elif msg_type == MSG_TYPE_TEXT_CHAT:
        decrypted = server_decrypt_with_key(payload, admin_info.session_key)
        if decrypted:
            try:
                text = decrypted.decode('utf-8')
                logging.getLogger("chat").info(f"Chat from admin [{admin_info.name}]: {text[:100]}{'...' if len(text) > 100 else ''}")
                handle_text_message(admin_info.name, text, addr)
            except Exception as e:
                logger.error(f"Failed to decode text message from admin [{admin_info.name}]: {e}")

def remove_client(client_info):
    """Remove a client and clean up."""
    with global_lock:
        if client_info in clients:
            clients.remove(client_info)
            logger.info(f"User [{client_info.name}] removed (total: {len(clients)})")
    
    audio_recorder.stop_recording(client_info.name)
    broadcast_user_event("left", client_info.name)
    broadcast_user_list()
    broadcast_user_list_to_admins()

def remove_admin(admin_info):
    """Remove an admin and clean up."""
    with global_lock:
        if admin_info in admins:
            admins.remove(admin_info)
            logger.info(f"Admin [{admin_info.name}] removed (total: {len(admins)})")
    
    if REQUIRE_ADMIN:
        broadcast_admin_status(MSG_TYPE_ADMIN_OFFLINE)
    
    broadcast_user_list_to_admins()

# ============ Text Chat ============

def find_client_by_name(name: str):
    """Find a client by name (case-sensitive exact match)."""
    with global_lock:
        for c in clients:
            if c.name == name:
                return c
    return None

def find_client_by_addr(addr):
    """Find a client or admin by UDP address."""
    with global_lock:
        for c in clients:
            if c.udp_addr == addr:
                return c
        for a in admins:
            if a.udp_addr == addr:
                return a
    return None

def broadcast_text_message(formatted_text: str, sender_addr):
    """Broadcast a formatted text message to all clients and admins.
    
    Args:
        formatted_text: Already-formatted text (e.g., "[username] message").
        sender_addr: Address of the sender (skipped for echo).
    """
    with global_lock:
        # Send to all clients (including sender for echo)
        for c in list(clients):
            if c.udp_addr:
                encrypted = server_encrypt_with_key(formatted_text.encode('utf-8'), c.session_key)
                if encrypted:
                    _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
        # Send to all admins
        for a in list(admins):
            if a.udp_addr:
                encrypted = server_encrypt_with_key(formatted_text.encode('utf-8'), a.session_key)
                if encrypted:
                    _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)

def handle_text_message(sender_name: str, text: str, sender_addr):
    """Handle a text chat message from a client or admin.
    
    Detects whisper commands (/msg) and routes accordingly.
    """
    text = text.strip()
    if not text:
        return
    
    # Check for whisper
    if text.startswith('/msg '):
        parts = text[5:].split(' ', 1)
        if len(parts) < 2:
            # Invalid whisper format — notify sender
            error = "[System] Usage: /msg <username> <message>"
            sender_info = find_client_by_addr(sender_addr)
            if sender_info:
                encrypted = server_encrypt_with_key(error.encode('utf-8'), sender_info.session_key)
                if encrypted:
                    _send_raw_udp(_udp_client_sock, sender_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
            logging.getLogger("chat").info(f"Whisper: [{sender_name}] invalid format")
            return
        
        target_name = parts[0].strip()
        message = parts[1].strip()
        
        if not message:
            error = "[System] Message cannot be empty"
            sender_info = find_client_by_addr(sender_addr)
            if sender_info:
                encrypted = server_encrypt_with_key(error.encode('utf-8'), sender_info.session_key)
                if encrypted:
                    _send_raw_udp(_udp_client_sock, sender_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
            return
        
        target = find_client_by_name(target_name)
        if target is None:
            # Target not found
            error = f"[System] User '{target_name}' not found"
            sender_info = find_client_by_addr(sender_addr)
            if sender_info:
                encrypted = server_encrypt_with_key(error.encode('utf-8'), sender_info.session_key)
                if encrypted:
                    _send_raw_udp(_udp_client_sock, sender_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
            logging.getLogger("chat").info(f"Whisper: [{sender_name}] -> [{target_name}] not found")
            return
        
        # Send to target — use "you" instead of target name
        whisper_for_target = f"[{sender_name} → you] {message}"
        encrypted = server_encrypt_with_key(whisper_for_target.encode('utf-8'), target.session_key)
        if encrypted:
            _send_raw_udp(_udp_client_sock, target.udp_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
        
        # Send to all admins — show full target name
        admin_text = f"[{sender_name} → {target_name}] {message}"
        with global_lock:
            for a in list(admins):
                if a.udp_addr:
                    encrypted = server_encrypt_with_key(admin_text.encode('utf-8'), a.session_key)
                    if encrypted:
                        _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
        
        # Send confirmation to sender
        confirm = f"[You → {target_name}] {message}"
        sender_info = find_client_by_addr(sender_addr)
        if sender_info:
            encrypted = server_encrypt_with_key(confirm.encode('utf-8'), sender_info.session_key)
            if encrypted:
                _send_raw_udp(_udp_client_sock, sender_addr, MSG_TYPE_TEXT_MESSAGE, encrypted)
        
        logging.getLogger("chat").info(f"Whisper: [{sender_name}] -> [{target_name}]: {message[:100]}{'...' if len(message) > 100 else ''}")
        return
    
    # Normal broadcast
    formatted = f"[{sender_name}] {text}"
    broadcast_text_message(formatted, sender_addr)
    logging.getLogger("chat").info(f"Chat broadcast: [{sender_name}]: {text[:100]}{'...' if len(text) > 100 else ''}")

# ============ Audio Handling ============

def handle_audio_packet(data, addr, is_admin_side=False):
    """Handle an incoming audio packet."""
    if len(data) < 17:
        return
    
    try:
        # Parse: [msg_type(1)][user_id(4)][timestamp(8)][encrypted_len(4)][encrypted_audio]
        msg_type = struct.unpack('!B', data[:1])[0]
        if msg_type != MSG_TYPE_AUDIO:
            return
        
        user_id = struct.unpack('!I', data[1:5])[0]
        timestamp = struct.unpack('!d', data[5:13])[0]
        encrypted_len = struct.unpack('!I', data[13:17])[0]
        encrypted_audio = data[17:17+encrypted_len]
        
        current_time = time.time()
        packet_age_ms = (current_time - timestamp) * 1000
        if packet_age_ms > AUDIO_PACKET_TIMEOUT_MS:
            return
        
        # Find sender
        sender_name = None
        sender_id = None
        sender_session_key = None
        
        if is_admin_side:
            with global_lock:
                all_admins = list(admins)
            for a in all_admins:
                if a.user_id == user_id:
                    sender_name = a.name
                    sender_id = a.user_id
                    sender_session_key = a.session_key
                    a.udp_addr = addr
                    break
        else:
            with global_lock:
                all_clients = list(clients)
            for c in all_clients:
                if c.user_id == user_id:
                    sender_name = c.name
                    sender_id = c.user_id
                    sender_session_key = c.session_key
                    c.udp_addr = addr
                    break
        
        if sender_name is None or sender_session_key is None:
            return
        
        # Decrypt audio
        decrypted_audio = server_decrypt_with_key(encrypted_audio, sender_session_key)
        if decrypted_audio is None:
            return
        
        # Enqueue for recording (only for client audio, not admin)
        if not is_admin_side:
            try:
                _recording_queue.put_nowait((sender_name, decrypted_audio))
            except queue.Full:
                pass
            
            # Enqueue for admin forwarding (separate thread, includes sender_id)
            try:
                _admin_forward_queue.put_nowait((sender_id, sender_name, decrypted_audio))
            except queue.Full:
                pass
            
            # Enqueue for client-to-client forwarding (separate thread)
            try:
                _client_forward_queue.put_nowait((sender_id, sender_name, decrypted_audio))
            except queue.Full:
                pass
        
    except Exception as e:
        logger.error(f"Error processing UDP audio: {e}")

# ============ Main Receive Loop ============

def udp_receive_loop():
    """Main UDP receive loop - handles both client and admin sockets.
    
    Uses select() to poll both sockets simultaneously, avoiding the
    0.01s per-socket timeout penalty that would otherwise limit the
    loop to ~50 packets/sec when 6+ users are connected.
    """
    global _udp_client_sock, _udp_admin_sock
    
    logger.info("UDP receive loop started")
    
    _udp_client_sock.setblocking(False)
    _udp_admin_sock.setblocking(False)
    
    while _server_running.is_set():
        try:
            readable, _, _ = select.select(
                [_udp_client_sock, _udp_admin_sock], [], [], 0.05
            )
        except (select.error, ValueError):
            time.sleep(0.01)
            continue
        
        for sock in readable:
            try:
                data, addr = sock.recvfrom(MAX_PACKET_SIZE)
            except (BlockingIOError, socket.error):
                continue
            
            if len(data) < 1:
                continue
            
            msg_type = struct.unpack('!B', data[:1])[0]
            
            if sock == _udp_client_sock:
                if msg_type == MSG_TYPE_AUDIO:
                    handle_audio_packet(data, addr)
                else:
                    result = rudp_server.handle_message(_udp_client_sock, data, addr)
                    if result is not None:
                        msg_type, seq_num, flags, payload = result
                        handle_client_message(msg_type, seq_num, flags, payload, addr)
            else:
                if msg_type == MSG_TYPE_AUDIO:
                    handle_audio_packet(data, addr, is_admin_side=True)
                else:
                    result = rudp_server.handle_message(_udp_admin_sock, data, addr)
                    if result is not None:
                        msg_type, seq_num, flags, payload = result
                        handle_admin_message(msg_type, seq_num, flags, payload, addr)
    
    logger.info("UDP receive loop stopped")

# ============ Heartbeat Check ============

def check_heartbeats():
    while _server_running.is_set():
        time.sleep(3)
        
        timed_out_clients = []
        timed_out_admins = []
        
        with global_lock:
            for c in clients:
                if time.time() - c.last_heartbeat > HEARTBEAT_TIMEOUT:
                    timed_out_clients.append(c)
            for a in admins:
                if time.time() - a.last_heartbeat > HEARTBEAT_TIMEOUT:
                    timed_out_admins.append(a)
            
            for c in timed_out_clients:
                if c in clients:
                    clients.remove(c)
                    logger.info(f"User [{c.name}] heartbeat timeout, removed (total: {len(clients)})")
            for a in timed_out_admins:
                if a in admins:
                    admins.remove(a)
                    logger.info(f"Admin [{a.name}] heartbeat timeout, removed (total: {len(admins)})")
        
        for c in timed_out_clients:
            audio_recorder.stop_recording(c.name)
            broadcast_user_event("left", c.name)
            broadcast_user_list()
            broadcast_user_list_to_admins()
        
        for a in timed_out_admins:
            if REQUIRE_ADMIN:
                broadcast_admin_status(MSG_TYPE_ADMIN_OFFLINE)
            broadcast_user_list_to_admins()

# ============ Main ============

def main():
    global server_rsa_key, server_public_key, public_key_bytes, public_key_fingerprint
    global _udp_client_sock, _udp_admin_sock
    
    parser = argparse.ArgumentParser(description="OpenVoiceChat Server (UDP)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--log-dir", default=os.path.join(os.path.dirname(__file__), "logs"),
                        help="Directory for log files")
    args = parser.parse_args()
    
    # Create logs directory
    os.makedirs(args.log_dir, exist_ok=True)
    
    log_level = getattr(logging, args.log_level)
    log_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Root logger: console + file
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler (stdout, for docker logs)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)
    
    # System log file (rotating: 10MB max, keep 5 backups)
    system_log_path = os.path.join(args.log_dir, "server.log")
    system_file_handler = RotatingFileHandler(
        system_log_path, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    system_file_handler.setLevel(log_level)
    system_file_handler.setFormatter(log_format)
    root_logger.addHandler(system_file_handler)
    
    logger.info(f"System log file: {system_log_path}")
    
    # Chat logger: writes to a separate chat log file
    chat_log_path = os.path.join(args.log_dir, "chat.log")
    chat_logger = logging.getLogger("chat")
    chat_logger.setLevel(logging.INFO)
    chat_logger.propagate = False  # Don't duplicate to root logger
    chat_file_handler = RotatingFileHandler(
        chat_log_path, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    chat_file_handler.setLevel(logging.INFO)
    chat_file_handler.setFormatter(
        logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    )
    chat_logger.addHandler(chat_file_handler)
    
    logger.info(f"Chat log file: {chat_log_path}")
    
    # Load or generate RSA key pair
    key_file = os.path.join(os.path.dirname(__file__), 'server_rsa_key.pem')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            server_rsa_key = RSA.import_key(f.read())
        logger.info(f"RSA key loaded from {key_file}")
    else:
        server_rsa_key = RSA.generate(2048)
        with open(key_file, 'wb') as f:
            f.write(server_rsa_key.export_key())
        os.chmod(key_file, 0o600)
        logger.info(f"RSA key generated and saved to {key_file}")
    
    server_public_key = server_rsa_key.publickey()
    public_key_bytes = server_public_key.export_key()
    public_key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
    logger.info(f"Server public key fingerprint: {public_key_fingerprint}")
    
    # Load data
    load_device_db()
    load_ban_list()
    
    # Create UDP sockets
    _udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _udp_client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _udp_client_sock.bind((HOST, CLIENT_PORT))
    logger.info(f"Client UDP server on {HOST}:{CLIENT_PORT}")
    
    _udp_admin_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _udp_admin_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _udp_admin_sock.bind((HOST, ADMIN_PORT))
    logger.info(f"Admin UDP server on {HOST}:{ADMIN_PORT}")
    
    _server_running.set()
    
    # Start threads
    heartbeat_thread = threading.Thread(target=check_heartbeats, daemon=True)
    heartbeat_thread.start()
    
    start_recording_thread()
    start_admin_forward_thread()
    start_client_forward_thread()
    start_user_list_broadcast()
    
    receive_thread = threading.Thread(target=udp_receive_loop, daemon=True)
    receive_thread.start()
    
    logger.info("Server is running")
    logger.info(f"Clients connect to UDP port {CLIENT_PORT}")
    logger.info(f"Admins connect to UDP port {ADMIN_PORT}")
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        _server_running.clear()
        # Notify all clients before shutdown
        with global_lock:
            for c in clients:
                try:
                    _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_LEAVE, b'')
                except:
                    pass
            for a in admins:
                try:
                    _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_LEAVE, b'')
                except:
                    pass
        stop_recording_thread()
        stop_admin_forward_thread()
        stop_client_forward_thread()
        audio_recorder.stop_all()
        if _udp_client_sock:
            _udp_client_sock.close()
        if _udp_admin_sock:
            _udp_admin_sock.close()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down")
        _server_running.clear()
        # Notify all clients before shutdown
        with global_lock:
            for c in clients:
                try:
                    _send_raw_udp(_udp_client_sock, c.udp_addr, MSG_TYPE_LEAVE, b'')
                except:
                    pass
            for a in admins:
                try:
                    _send_raw_udp(_udp_admin_sock, a.udp_addr, MSG_TYPE_LEAVE, b'')
                except:
                    pass
        stop_recording_thread()
        stop_admin_forward_thread()
        stop_client_forward_thread()
        audio_recorder.stop_all()
        if _udp_client_sock:
            _udp_client_sock.close()
        if _udp_admin_sock:
            _udp_admin_sock.close()

if __name__ == "__main__":
    main()