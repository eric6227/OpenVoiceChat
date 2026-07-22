import socket
import threading
import struct
import logging
import argparse
import time
import hashlib
import os
import json
import signal
import sys
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
    MAX_PACKET_SIZE,
)

logger = logging.getLogger(__name__)

# Server password for regular clients - MUST be set via OVC_PASSWORD environment variable
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

# Admin password - MUST be set via OVC_ADMIN_PASSWORD environment variable
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

# Whether to require at least one admin online for clients to stay connected
# Set OVC_REQUIRE_ADMIN=false to allow clients to remain connected without admin
REQUIRE_ADMIN = os.environ.get("OVC_REQUIRE_ADMIN", "true").lower() in ("true", "1", "yes")
logger.info(f"Admin required for clients: {REQUIRE_ADMIN}")

# Audio packet timeout (milliseconds) - drop packets older than this
AUDIO_PACKET_TIMEOUT_MS = 200

class ClientInfo:
    """Stores information about a connected client."""
    _next_id = 1
    _id_lock = threading.Lock()
    
    def __init__(self, conn, name, session_key, is_admin=False, device_fingerprints=None, ip_address=None):
        with ClientInfo._id_lock:
            self.user_id = ClientInfo._next_id
            ClientInfo._next_id += 1
        
        self.conn = conn
        self.name = name
        self.session_key = session_key
        self.is_admin = is_admin
        self.device_fingerprints = device_fingerprints or {}
        self.ip_address = ip_address
        self.last_heartbeat = time.time()
        self.lock = threading.Lock()

clients = []  # List of ClientInfo (non-admin)
admins = []   # List of ClientInfo (admin)
global_lock = threading.Lock()
HEARTBEAT_TIMEOUT = 30  # Seconds before a client is considered disconnected

# Rate limiting for authentication attempts: {ip: {"attempts": count, "last_attempt": timestamp, "blocked_until": timestamp}}
auth_rate_limit = {}
auth_rate_lock = threading.Lock()
MAX_AUTH_ATTEMPTS = 5  # Maximum failed attempts before blocking
AUTH_BLOCK_DURATION = 300  # Block duration in seconds (5 minutes)

def check_auth_rate_limit(ip: str) -> bool:
    """Check if an IP is rate limited for authentication attempts.
    
    Returns True if the IP is allowed to attempt authentication, False if blocked.
    """
    now = time.time()
    
    with auth_rate_lock:
        if ip in auth_rate_limit:
            record = auth_rate_limit[ip]
            
            # Check if currently blocked
            if record.get("blocked_until", 0) > now:
                remaining = record["blocked_until"] - now
                logger.warning(f"IP {ip} is rate limited, {remaining:.0f}s remaining")
                return False
            
            # Reset if block has expired
            if record.get("blocked_until", 0) <= now and record["attempts"] >= MAX_AUTH_ATTEMPTS:
                auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
                return True
            
            # Check if within time window (reset after 60 seconds)
            if now - record.get("last_attempt", 0) > 60:
                auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
                return True
            
            return True
        else:
            auth_rate_limit[ip] = {"attempts": 0, "last_attempt": now, "blocked_until": 0}
            return True

def record_auth_failure(ip: str):
    """Record a failed authentication attempt and block if necessary."""
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
    """Reset rate limit counter on successful authentication."""
    with auth_rate_lock:
        if ip in auth_rate_limit:
            del auth_rate_limit[ip]

# Device fingerprint database: {fingerprint: {"names": [...], "ips": [...], "last_seen": "..."}}
device_fingerprint_db = {}
device_db_lock = threading.Lock()
DEVICE_DB_FILE = os.path.join(os.path.dirname(__file__), 'device_fingerprints.json')

# Ban list: {fingerprint: {"type": "...", "banned_at": "...", "banned_by": "...", "reason": "...", "expires_at": "..."}}
ban_list = {}
ban_list_lock = threading.Lock()
BAN_LIST_FILE = os.path.join(os.path.dirname(__file__), 'ban_list.json')

# IP ban duration in days (Chinese IPv4 addresses change frequently)
IP_BAN_DURATION_DAYS = 7

# Audio recording configuration (DISABLED by default for privacy compliance)
# To enable recording, set OVC_RECORDING_ENABLED=true and ensure users provide consent
RECORDING_ENABLED = os.environ.get("OVC_RECORDING_ENABLED", "false").lower() == "true"
RECORDING_DIR = os.environ.get("OVC_RECORDING_DIR", os.path.join(os.path.dirname(__file__), 'recordings'))
RECORDING_DURATION_MINUTES = int(os.environ.get("OVC_RECORDING_DURATION", "5"))  # Minutes per file
RECORDING_MAX_SIZE_MB = int(os.environ.get("OVC_RECORDING_MAX_SIZE", "10240"))  # Max total size in MB (default 10GB)
RECORDING_RETENTION_DAYS = int(os.environ.get("OVC_RECORDING_RETENTION", "30"))  # Days to keep recordings
RECORDING_SAMPLE_RATE = 16000  # Sample rate for PCM audio
RECORDING_CHANNELS = 1  # Mono audio
RECORDING_SAMPLE_WIDTH = 4  # 32-bit audio (4 bytes per sample) to prevent distortion

if RECORDING_ENABLED:
    logger.warning("AUDIO RECORDING IS ENABLED - Ensure you have user consent and comply with privacy laws")

import wave

class AudioRecorder:
    """Manages audio recording for all users."""
    
    def __init__(self):
        self.recordings = {}  # {user_name: {"file": wave_obj, "size": bytes_written, "start_time": timestamp}}
        self.lock = threading.RLock()
        self.max_file_bytes = RECORDING_DURATION_MINUTES * 60 * RECORDING_SAMPLE_RATE * RECORDING_CHANNELS * RECORDING_SAMPLE_WIDTH
        self.max_total_bytes = RECORDING_MAX_SIZE_MB * 1024 * 1024
        
        if RECORDING_ENABLED:
            os.makedirs(RECORDING_DIR, exist_ok=True)
            logger.info(f"Audio recording enabled: {RECORDING_DIR}")
            logger.info(f"Recording duration: {RECORDING_DURATION_MINUTES} minutes per file")
            logger.info(f"Max total size: {RECORDING_MAX_SIZE_MB} MB")
    
    def _get_recording_path(self, user_name: str) -> str:
        """Get the next recording file path for a user."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(RECORDING_DIR, f"{user_name}_{timestamp}.wav")
    
    def _cleanup_old_recordings(self, user_name: str):
        """Remove recordings older than retention period to comply with privacy laws."""
        if not RECORDING_ENABLED:
            return
            
        cutoff_time = time.time() - (RECORDING_RETENTION_DAYS * 24 * 60 * 60)
        
        # Get all recordings for this user
        for filename in os.listdir(RECORDING_DIR):
            if filename.startswith(f"{user_name}_") and filename.endswith('.wav'):
                filepath = os.path.join(RECORDING_DIR, filename)
                file_mtime = os.path.getmtime(filepath)
                
                # Remove files older than retention period
                if file_mtime < cutoff_time:
                    try:
                        os.remove(filepath)
                        logger.info(f"Removed expired recording (> {RECORDING_RETENTION_DAYS} days): {filepath}")
                    except Exception as e:
                        logger.warning(f"Failed to remove expired recording {filepath}: {e}")
    
    def start_recording(self, user_name: str):
        """Start recording audio for a user."""
        if not RECORDING_ENABLED:
            return
        
        with self.lock:
            # Close existing recording if any
            if user_name in self.recordings:
                self._close_recording(user_name)
            
            # Cleanup old recordings
            self._cleanup_old_recordings(user_name)
            
            # Start new recording
            filepath = self._get_recording_path(user_name)
            try:
                wave_file = wave.open(filepath, 'wb')
                wave_file.setnchannels(RECORDING_CHANNELS)
                wave_file.setsampwidth(RECORDING_SAMPLE_WIDTH)
                wave_file.setframerate(RECORDING_SAMPLE_RATE)
                
                self.recordings[user_name] = {
                    "file": wave_file,
                    "size": 0,
                    "start_time": time.time(),
                    "filepath": filepath
                }
                logger.info(f"Started recording for user '{user_name}': {filepath}")
            except Exception as e:
                logger.error(f"Failed to start recording for user '{user_name}': {e}")
    
    def write_audio(self, user_name: str, audio_data: bytes):
        """Write decrypted audio data to recording file."""
        if not RECORDING_ENABLED:
            return
        
        with self.lock:
            if user_name not in self.recordings:
                # Auto-start recording if not already started
                self.start_recording(user_name)
            
            if user_name not in self.recordings:
                return
            
            recording = self.recordings[user_name]
            
            # Check if we need to rotate file (duration limit)
            elapsed = time.time() - recording["start_time"]
            if elapsed >= RECORDING_DURATION_MINUTES * 60:
                self._close_recording(user_name)
                self.start_recording(user_name)
                if user_name not in self.recordings:
                    return
                recording = self.recordings[user_name]
            
            # Write audio data
            try:
                # Convert 16-bit PCM to 32-bit PCM to prevent distortion
                import array
                samples_16 = array.array('h', audio_data)
                samples_32 = array.array('i', [s << 16 for s in samples_16])
                audio_data_32 = samples_32.tobytes()
                
                recording["file"].writeframes(audio_data_32)
                recording["size"] += len(audio_data_32)
            except Exception as e:
                logger.error(f"Failed to write audio for user '{user_name}': {e}")
    
    def _close_recording(self, user_name: str):
        """Close recording file for a user."""
        if user_name in self.recordings:
            recording = self.recordings[user_name]
            try:
                recording["file"].close()
                logger.info(f"Closed recording for user '{user_name}': {recording['filepath']} ({recording['size']} bytes)")
            except Exception as e:
                logger.error(f"Failed to close recording for user '{user_name}': {e}")
            finally:
                del self.recordings[user_name]
    
    def stop_recording(self, user_name: str):
        """Stop recording for a user."""
        if not RECORDING_ENABLED:
            return
        
        with self.lock:
            self._close_recording(user_name)
    
    def stop_all(self):
        """Stop all recordings."""
        if not RECORDING_ENABLED:
            return
        
        with self.lock:
            for user_name in list(self.recordings.keys()):
                self._close_recording(user_name)
            logger.info("All recordings stopped")

# Global audio recorder instance
audio_recorder = AudioRecorder()

def send_recording_notice(conn, user_name: str):
    """Send recording status notice to client.
    
    Format: [msg_type(1)][recording_enabled(1)][purpose_len(4)][purpose][storage_days(4)]
    """
    purpose = "用于审查用户言论是否违规"
    purpose_bytes = purpose.encode('utf-8')
    
    # Build notice packet
    notice_packet = (
        struct.pack('!B', MSG_TYPE_RECORDING_NOTICE) +
        struct.pack('!B', 1 if RECORDING_ENABLED else 0) +
        struct.pack('!I', len(purpose_bytes)) +
        purpose_bytes +
        struct.pack('!I', RECORDING_RETENTION_DAYS)  # Storage duration in days
    )
    
    conn.sendall(notice_packet)
    logger.info(f"Sent recording notice to {user_name}: recording_enabled={RECORDING_ENABLED}")

def load_ban_list():
    """Load ban list from file."""
    global ban_list
    if os.path.exists(BAN_LIST_FILE):
        try:
            with open(BAN_LIST_FILE, 'r', encoding='utf-8') as f:
                ban_list = json.load(f)
            logger.info(f"Loaded {len(ban_list)} banned devices from ban list")
            # Clean up expired IP bans
            clean_expired_ip_bans()
        except Exception as e:
            logger.error(f"Failed to load ban list: {e}")
            ban_list = {}
    else:
        ban_list = {}

def clean_expired_ip_bans():
    """Remove expired IP bans from the ban list."""
    now = datetime.now()
    expired = []
    
    for fp_value, ban_info in ban_list.items():
        if ban_info.get("type") == "ip":
            expires_at_str = ban_info.get("expires_at")
            if expires_at_str:
                try:
                    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
                    if now >= expires_at:
                        expired.append(fp_value)
                except Exception as e:
                    logger.warning(f"Failed to parse expiration date for {fp_value}: {e}")
    
    for fp_value in expired:
        removed = ban_list.pop(fp_value)
        logger.info(f"Removed expired IP ban: {fp_value[:16]}... (expired at {removed.get('expires_at', 'unknown')})")
    
    if expired:
        save_ban_list()
        logger.info(f"Cleaned {len(expired)} expired IP bans")

def save_ban_list():
    """Save ban list to file."""
    try:
        with open(BAN_LIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(ban_list, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save ban list: {e}")

def is_device_banned(fingerprints: dict) -> tuple:
    """Check if any of the device fingerprints are banned.
    
    Returns: (is_banned, banned_fingerprint_type)
    """
    now = datetime.now()
    
    for fp_type, fp_value in fingerprints.items():
        if fp_value and fp_value in ban_list:
            ban_info = ban_list[fp_value]
            
            # Check if this is an IP ban and if it has expired
            if fp_type == "ip":
                expires_at_str = ban_info.get("expires_at")
                if expires_at_str:
                    try:
                        expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
                        if now >= expires_at:
                            # IP ban has expired, remove it and continue checking
                            ban_list.pop(fp_value)
                            logger.info(f"IP ban expired for {fp_value[:16]}..., removing from ban list")
                            save_ban_list()
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to parse expiration date for {fp_value}: {e}")
            
            return True, fp_type
    
    return False, None

def ban_device(fingerprints: dict, admin_name: str, reason: str = ""):
    """Ban a device by adding all its fingerprints to the ban list.
    
    - IP addresses are banned for 7 days (Chinese IPv4 addresses change frequently)
    - Hardware fingerprints (mac, cpu, motherboard, bios) are banned permanently
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with ban_list_lock:
        for fp_type, fp_value in fingerprints.items():
            if fp_value:
                ban_entry = {
                    "type": fp_type,
                    "banned_at": now,
                    "banned_by": admin_name,
                    "reason": reason
                }
                
                # IP addresses expire after 7 days, hardware fingerprints are permanent
                if fp_type == "ip":
                    expires_at = datetime.now() + timedelta(days=IP_BAN_DURATION_DAYS)
                    ban_entry["expires_at"] = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                    logger.info(f"Banned {fp_type} {fp_value[:16]}... by admin {admin_name} (expires in {IP_BAN_DURATION_DAYS} days)")
                else:
                    ban_entry["expires_at"] = None
                    logger.info(f"Banned {fp_type} fingerprint {fp_value[:16]}... by admin {admin_name} (permanent)")
                
                ban_list[fp_value] = ban_entry
        
        save_ban_list()

def unban_device(fingerprint: str):
    """Unban a device by removing its fingerprint from the ban list."""
    with ban_list_lock:
        if fingerprint in ban_list:
            removed = ban_list.pop(fingerprint)
            logger.info(f"Unbanned {removed['type']} fingerprint {fingerprint[:16]}...")
            save_ban_list()
            return True
    return False

def get_ban_list_grouped() -> list:
    """Get ban list grouped by device (all fingerprints of same device together).
    
    IP addresses are NOT treated as separate devices, they are just attributes of a device.
    Devices are identified by hardware fingerprints (mac, cpu, motherboard, bios).
    
    Returns list of dicts with:
    - device_id: unique identifier (first MAC or first hardware fingerprint)
    - fingerprints: list of {type, value_short, banned_at, banned_by, reason, expires_at}
    - names: list of associated names from device_fingerprint_db
    - ips: list of associated IPs from device_fingerprint_db
    """
    with ban_list_lock:
        # First pass: collect all hardware fingerprints (not IP)
        hardware_fps = {}  # fp_value -> ban_info
        ip_fps = []  # list of (fp_value, ban_info)
        
        for fp_value, ban_info in ban_list.items():
            fp_type = ban_info.get("type", "unknown")
            if fp_type == "ip":
                ip_fps.append((fp_value, ban_info))
            else:
                hardware_fps[fp_value] = ban_info
        
        # Second pass: group hardware fingerprints by device
        # Strategy: use device_fingerprint_db to find which fingerprints belong to same device
        devices = {}
        device_by_mac = {}  # mac_value -> device_key
        
        for fp_value, ban_info in hardware_fps.items():
            fp_type = ban_info.get("type", "unknown")
            
            # Find associated names and IPs from device fingerprint db
            names = []
            ips = []
            if fp_value in device_fingerprint_db:
                entry = device_fingerprint_db[fp_value]
                names = entry.get("names", [])
                ips = entry.get("ips", [])
            
            # Use MAC address as primary device identifier
            if fp_type == "mac":
                device_key = f"MAC:{fp_value[:16]}"
                device_by_mac[fp_value] = device_key
            else:
                # Try to find associated MAC to group with
                device_key = None
                if fp_value in device_fingerprint_db:
                    entry = device_fingerprint_db[fp_value]
                    # Check if any MAC in device_fingerprint_db shares names with this fingerprint
                    for mac_value, mac_entry in device_fingerprint_db.items():
                        if device_fingerprint_db.get(mac_value, {}).get("type") == "mac":
                            mac_names = set(mac_entry.get("names", []))
                            current_names = set(entry.get("names", []))
                            if mac_names & current_names:  # Has common names
                                device_key = f"MAC:{mac_value[:16]}"
                                device_by_mac[mac_value] = device_key
                                break
                
                if not device_key:
                    # Use this fingerprint as device identifier
                    device_key = f"{fp_type}:{fp_value[:16]}"
            
            if device_key not in devices:
                devices[device_key] = {
                    "device_id": device_key,
                    "fingerprints": [],
                    "names": names,
                    "ips": ips,
                    "first_banned": ban_info.get("banned_at", ""),
                    "banned_by": ban_info.get("banned_by", "")
                }
            else:
                # Update names and IPs if this entry has more info
                if names and not devices[device_key]["names"]:
                    devices[device_key]["names"] = names
                if ips and not devices[device_key]["ips"]:
                    devices[device_key]["ips"] = ips
            
            devices[device_key]["fingerprints"].append({
                "type": fp_type,
                "value": fp_value,
                "value_short": fp_value[:16],
                "banned_at": ban_info.get("banned_at", ""),
                "banned_by": ban_info.get("banned_by", ""),
                "reason": ban_info.get("reason", ""),
                "expires_at": ban_info.get("expires_at", "")
            })
        
        # Third pass: add IP bans to corresponding devices
        for ip_value, ip_ban_info in ip_fps:
            # Try to find which device this IP belongs to
            ip_str = ip_value.split(" ")[0] if " " in ip_value else ip_value  # Remove timestamp if present
            
            matched_device = None
            for device_key, device_info in devices.items():
                # Check if any IP in device's IP list matches
                for device_ip in device_info["ips"]:
                    if device_ip.startswith(ip_str):
                        matched_device = device_key
                        break
                if matched_device:
                    break
            
            if matched_device:
                # Add IP to device's fingerprints (marked as IP)
                devices[matched_device]["fingerprints"].append({
                    "type": "ip",
                    "value": ip_value,
                    "value_short": ip_value[:16],
                    "banned_at": ip_ban_info.get("banned_at", ""),
                    "banned_by": ip_ban_info.get("banned_by", ""),
                    "reason": ip_ban_info.get("reason", ""),
                    "expires_at": ip_ban_info.get("expires_at", "")
                })
            else:
                # IP doesn't match any known device, create standalone entry
                device_key = f"IP:{ip_value[:16]}"
                devices[device_key] = {
                    "device_id": device_key,
                    "fingerprints": [{
                        "type": "ip",
                        "value": ip_value,
                        "value_short": ip_value[:16],
                        "banned_at": ip_ban_info.get("banned_at", ""),
                        "banned_by": ip_ban_info.get("banned_by", ""),
                        "reason": ip_ban_info.get("reason", ""),
                        "expires_at": ip_ban_info.get("expires_at", "")
                    }],
                    "names": [],
                    "ips": [ip_value],
                    "first_banned": ip_ban_info.get("banned_at", ""),
                    "banned_by": ip_ban_info.get("banned_by", "")
                }
        
        return list(devices.values())

def unban_device_group(device_key: str) -> bool:
    """Unban all fingerprints associated with a device group.
    
    device_key format: "TYPE:VALUE_SHORT" (e.g., "MAC:3a5845755234e016")
    or just the first 32 chars of the fingerprint value.
    
    When a device is unbanned, all associated IP bans are also removed.
    """
    with ban_list_lock:
        fps_to_remove = []
        associated_ips = set()  # IPs associated with this device
        
        # Parse device_key to extract type and value
        device_type = None
        device_value_short = None
        
        if ":" in device_key:
            parts = device_key.split(":", 1)
            device_type = parts[0].upper()
            device_value_short = parts[1]
        
        # First pass: find all hardware fingerprints for this device and collect associated IPs
        for fp_value, ban_info in ban_list.items():
            fp_type = ban_info.get("type", "unknown")
            
            # Skip IP bans in first pass, we'll handle them separately
            if fp_type == "ip":
                continue
            
            should_remove = False
            
            # Method 1: Match by device_key format (TYPE:VALUE_SHORT)
            if device_type and device_value_short:
                # Check if fingerprint type matches
                if fp_type.upper() == device_type:
                    # Check if fingerprint value starts with the short value
                    if fp_value.startswith(device_value_short):
                        should_remove = True
                
                # For MAC type, also check device_fingerprint_db for related fingerprints
                if not should_remove and device_type == "MAC" and fp_value in device_fingerprint_db:
                    entry = device_fingerprint_db[fp_value]
                    # Check if this fingerprint shares names with the MAC
                    mac_names = set(entry.get("names", []))
                    # Find the MAC entry
                    for mac_value, mac_entry in device_fingerprint_db.items():
                        if mac_entry.get("type") == "mac" and mac_value.startswith(device_value_short):
                            mac_entry_names = set(mac_entry.get("names", []))
                            if mac_names & mac_entry_names:  # Has common names
                                should_remove = True
                                break
            
            # Method 2: Legacy matching by first 32 chars
            if not should_remove and fp_value[:32] == device_key[:32]:
                should_remove = True
            
            # Method 3: Match by names in device_fingerprint_db
            if not should_remove and fp_value in device_fingerprint_db:
                entry = device_fingerprint_db[fp_value]
                names = entry.get("names", [])
                if names:
                    entry_device_id = "|".join(sorted(names))
                    if entry_device_id == device_key:
                        should_remove = True
            
            if should_remove:
                fps_to_remove.append(fp_value)
                # Collect associated IPs from device_fingerprint_db
                if fp_value in device_fingerprint_db:
                    entry = device_fingerprint_db[fp_value]
                    for ip_entry in entry.get("ips", []):
                        # Extract IP address (format: "IP (timestamp)")
                        ip_addr = ip_entry.split(" ")[0] if " " in ip_entry else ip_entry
                        associated_ips.add(ip_addr)
        
        # Second pass: find IP bans that match the associated IPs
        for fp_value, ban_info in ban_list.items():
            fp_type = ban_info.get("type", "unknown")
            
            if fp_type == "ip":
                # Extract IP address from ban list key (format: "IP" or "IP (timestamp)")
                ban_ip = fp_value.split(" ")[0] if " " in fp_value else fp_value
                
                # Check if this IP is associated with the device
                if ban_ip in associated_ips:
                    fps_to_remove.append(fp_value)
                    continue
                
                # Also try matching by device_key if it's an IP type
                if device_type == "IP" and device_value_short:
                    if fp_value.startswith(device_value_short):
                        fps_to_remove.append(fp_value)
        
        # Remove all fingerprints
        for fp in fps_to_remove:
            removed = ban_list.pop(fp)
            logger.info(f"Unbanned {removed.get('type', 'unknown')} fingerprint {fp[:16]}...")
        
        if fps_to_remove:
            save_ban_list()
            return True
        
        return False

def load_device_db():
    """Load device fingerprint database from file."""
    global device_fingerprint_db
    if os.path.exists(DEVICE_DB_FILE):
        try:
            with open(DEVICE_DB_FILE, 'r', encoding='utf-8') as f:
                device_fingerprint_db = json.load(f)
            logger.info(f"Loaded {len(device_fingerprint_db)} device fingerprints from database")
        except Exception as e:
            logger.error(f"Failed to load device database: {e}")
            device_fingerprint_db = {}
    else:
        device_fingerprint_db = {}

def save_device_db():
    """Save device fingerprint database to file."""
    try:
        with open(DEVICE_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(device_fingerprint_db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save device database: {e}")

def update_device_fingerprint(fingerprints: dict, name: str, ip: str):
    """Update device fingerprint database with new name/IP information.
    
    For each fingerprint type (mac, cpu, motherboard, bios):
    - If fingerprint exists: update names, IPs, and timestamp
    - If fingerprint is new: create new entry
    - Old information is preserved
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    for fp_type, fp_value in fingerprints.items():
        if not fp_value:  # Skip empty fingerprints
            continue
        
        with device_db_lock:
            if fp_value in device_fingerprint_db:
                # Existing fingerprint - update
                entry = device_fingerprint_db[fp_value]
                
                # Add new name if not present
                if name not in entry["names"]:
                    entry["names"].append(name)
                    logger.info(f"Added new name '{name}' to {fp_type} fingerprint {fp_value[:16]}...")
                
                # Add new IP if not present
                ip_entry = f"{ip} ({now})"
                if not any(ip in old_entry for old_entry in entry["ips"]):
                    entry["ips"].append(ip_entry)
                    logger.info(f"Added new IP '{ip}' to {fp_type} fingerprint {fp_value[:16]}...")
                
                # Update timestamp
                entry["last_seen"] = now
            else:
                # New fingerprint - create entry
                device_fingerprint_db[fp_value] = {
                    "type": fp_type,
                    "names": [name],
                    "ips": [f"{ip} ({now})"],
                    "first_seen": now,
                    "last_seen": now
                }
                logger.info(f"New {fp_type} fingerprint registered: {fp_value[:16]}... for user '{name}'")
        
        # Save after each update
        save_device_db()

# RSA key pair for password encryption (will be generated in main() after logging is configured)
server_rsa_key = None
server_public_key = None
public_key_bytes = None
public_key_fingerprint = None


def server_decrypt_with_key(data: bytes, key: bytes) -> bytes:
    """Decrypt audio data using a specific session key."""
    if len(data) < 28:
        return None
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return None


def server_encrypt_with_key(data: bytes, key: bytes) -> bytes:
    """Encrypt audio data using a specific session key."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext


def broadcast_user_list():
    """Send the current user list to all connected clients and admins."""
    with global_lock:
        user_list = [(c.user_id, c.name) for c in clients]
        admin_names = [a.name for a in admins]
    
    # Format for clients: "Users: [ID:1]user1, [ID:2]user2"
    user_list_data = "Users: " + ", ".join([f"[ID:{uid}]{name}" for uid, name in user_list])
    # Format for admins: same but with admin info
    admin_list_data = "Users: " + ", ".join([f"[ID:{uid}]{name}" for uid, name in user_list]) + " | Admins: " + ", ".join(admin_names)
    
    with global_lock:
        all_clients = list(clients)
        all_admins = list(admins)
    
    for client in all_clients:
        try:
            user_list_bytes = user_list_data.encode('utf-8')
            encrypted_data = server_encrypt_with_key(user_list_bytes, client.session_key)
            packet = struct.pack('!B', MSG_TYPE_USER_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            client.conn.settimeout(2.0)
            client.conn.sendall(packet)
            client.conn.settimeout(None)
        except socket.timeout:
            logger.warning(f"Client [{client.name}] broadcast timeout, removing")
            client.conn.settimeout(None)
            with global_lock:
                if client in clients:
                    clients.remove(client)
        except Exception:
            pass
    
    for admin in all_admins:
        try:
            admin_list_bytes = admin_list_data.encode('utf-8')
            encrypted_data = server_encrypt_with_key(admin_list_bytes, admin.session_key)
            packet = struct.pack('!B', MSG_TYPE_USER_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            admin.conn.settimeout(2.0)
            admin.conn.sendall(packet)
            admin.conn.settimeout(None)
        except socket.timeout:
            logger.warning(f"Admin [{admin.name}] broadcast timeout, removing")
            admin.conn.settimeout(None)
            with global_lock:
                if admin in admins:
                    admins.remove(admin)
        except Exception:
            pass


def broadcast_user_list_to_admins():
    """Send detailed user list with device fingerprints to admins only."""
    with global_lock:
        all_clients = list(clients)
    
    # Build detailed user list for admins with all four fingerprints and user_id
    # Exclude admins from the list
    user_details = []
    for c in all_clients:
        if c.is_admin:
            continue
        fps = c.device_fingerprints
        mac_fp = fps.get('mac', '????????????????')[:16] if fps else '????????????????'
        cpu_fp = fps.get('cpu', '????????????????')[:16] if fps else '????????????????'
        mb_fp = fps.get('motherboard', '????????????????')[:16] if fps else '????????????????'
        bios_fp = fps.get('bios', '????????????????')[:16] if fps else '????????????????'
        
        # Combine all fingerprints into one device identifier
        device_id = f"{mac_fp}{cpu_fp}"[:32]
        ip_addr = c.ip_address or "未知"
        fingerprint = f"MAC:{mac_fp} CPU:{cpu_fp} MB:{mb_fp} BIOS:{bios_fp}"
        
        user_details.append({
            'user_id': c.user_id,
            'name': c.name,
            'device_id': device_id,
            'ip': ip_addr,
            'fingerprint': fingerprint
        })
    
    # Format: "Users: [ID:1] username [Device:xxx] [IP:xxx] [FP:xxx], [ID:2] username ..."
    user_list_parts = []
    for u in user_details:
        user_str = f"[ID:{u['user_id']}] {u['name']} [Device:{u['device_id']}] [IP:{u['ip']}] [FP:{u['fingerprint']}]"
        user_list_parts.append(user_str)
    
    user_list_data = "Users: " + ", ".join(user_list_parts)
    
    with global_lock:
        all_admins = list(admins)
    
    for admin in all_admins:
        try:
            user_list_bytes = user_list_data.encode('utf-8')
            encrypted_data = server_encrypt_with_key(user_list_bytes, admin.session_key)
            packet = struct.pack('!B', MSG_TYPE_USER_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            admin.conn.sendall(packet)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.warning(f"Admin [{admin.name}] connection error during broadcast: {e}")
            with global_lock:
                if admin in admins:
                    admins.remove(admin)
        except Exception:
            pass


def broadcast_user_event(event_type, name):
    """Send user join/leave event to all clients and admins."""
    event_data = f"{name} has {event_type}"
    event_bytes = event_data.encode('utf-8')
    
    with global_lock:
        all_clients = list(clients)
        all_admins = list(admins)
    
    for c in all_clients:
        try:
            encrypted_data = server_encrypt_with_key(event_bytes, c.session_key)
            packet = struct.pack('!B', MSG_TYPE_USER_JOINED) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            c.conn.sendall(packet)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.warning(f"Client [{c.name}] connection error during event broadcast: {e}")
            with global_lock:
                if c in clients:
                    clients.remove(c)
        except Exception:
            pass
    
    for admin in all_admins:
        try:
            encrypted_data = server_encrypt_with_key(event_bytes, admin.session_key)
            packet = struct.pack('!B', MSG_TYPE_USER_JOINED) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            admin.conn.sendall(packet)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.warning(f"Admin [{admin.name}] connection error during event broadcast: {e}")
            with global_lock:
                if admin in admins:
                    admins.remove(admin)
        except Exception:
            pass

def broadcast_ban_list_to_admins():
    """Send updated ban list to all admins."""
    ban_list_data = get_ban_list_grouped()
    ban_list_json = json.dumps(ban_list_data, ensure_ascii=False).encode('utf-8')
    
    with global_lock:
        all_admins = list(admins)
    
    for admin in all_admins:
        try:
            encrypted_data = server_encrypt_with_key(ban_list_json, admin.session_key)
            packet = struct.pack('!B', MSG_TYPE_BAN_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            admin.conn.sendall(packet)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.warning(f"Admin [{admin.name}] connection error during ban list broadcast: {e}")
            with global_lock:
                if admin in admins:
                    admins.remove(admin)
        except Exception:
            pass


def handle_client(conn, addr, is_admin=False):
    """Handle a single client connection."""
    role = "admin" if is_admin else "client"
    logger.info(f"{role.capitalize()} connected from {addr}")
    
    # Check rate limit before processing authentication
    client_ip = addr[0]
    if not check_auth_rate_limit(client_ip):
        logger.warning(f"{role.capitalize()} connection rejected from {addr}: rate limited")
        fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
        conn.sendall(fail_packet)
        conn.close()
        return
    
    try:
        # Set socket timeout for initial handshake
        conn.settimeout(10)
        
        # Step 1: Send RSA public key to client for password encryption
        logger.info(f"[{role}] Sending RSA public key...")
        pub_key_len = len(public_key_bytes)
        conn.sendall(struct.pack('!I', pub_key_len) + public_key_bytes)
        logger.info(f"[{role}] RSA public key sent ({pub_key_len} bytes)")
        
        # Step 2: Receive JOIN message with RSA-encrypted password
        data = b''
        while len(data) < 2:
            chunk = conn.recv(MAX_PACKET_SIZE)
            if not chunk:
                logger.warning(f"{role.capitalize()} disconnected before sending JOIN")
                return
            data += chunk
        
        logger.info(f"[{role}] Received {len(data)} bytes for initial packet, data: {data[:20].hex()}")
        msg_type = struct.unpack('!B', data[:1])[0]
        logger.info(f"[{role}] Message type: {msg_type}")
        
        if msg_type == MSG_TYPE_JOIN:
            # Parse JOIN packet: [msg_type(1)][name_len(4)][name][encrypted_password_len(4)][encrypted_password]
            offset = 1
            name_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logger.info(f"[{role}] Name length: {name_len}")
            
            if name_len == 0 or name_len > 128:
                logger.warning(f"Invalid username length: {name_len}")
                return
            
            # Wait for more data if needed
            while len(data) < offset + name_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    logger.warning(f"[{role}] Disconnected while reading name")
                    return
                data += chunk
                logger.info(f"[{role}] Received more data for name, total: {len(data)}")
            
            name = data[offset:offset+name_len].decode('utf-8')
            offset += name_len
            logger.info(f"[{role}] Name: {name}")
            
            encrypted_password_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logger.info(f"[{role}] Encrypted password length: {encrypted_password_len}")
            
            if encrypted_password_len == 0 or encrypted_password_len > 512:
                logger.warning(f"Invalid encrypted password length: {encrypted_password_len}")
                return
            
            while len(data) < offset + encrypted_password_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    logger.warning(f"[{role}] Disconnected while reading encrypted password")
                    return
                data += chunk
                logger.info(f"[{role}] Received more data for encrypted password, total: {len(data)}")
            
            encrypted_password = data[offset:offset+encrypted_password_len]
            offset += encrypted_password_len
            logger.info(f"[{role}] Encrypted password received, decrypting...")
            
            # Decrypt password using RSA private key
            try:
                cipher = PKCS1_OAEP.new(server_rsa_key)
                password = cipher.decrypt(encrypted_password).decode('utf-8')
                logger.info(f"[{role}] Password decrypted successfully")
            except Exception as e:
                logger.warning(f"[{role}] Failed to decrypt password: {e}")
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            # Verify password based on role
            expected_password = ADMIN_PASSWORD if is_admin else CLIENT_PASSWORD
            if password != expected_password:
                logger.warning(f"{role.capitalize()} [{name}] authentication failed from {addr} (wrong password)")
                record_auth_failure(client_ip)
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            # Read device fingerprints (JSON format)
            fingerprints_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logger.info(f"[{role}] Device fingerprints length: {fingerprints_len}")
            
            if fingerprints_len == 0 or fingerprints_len > 1024:
                logger.warning(f"Invalid device fingerprint length: {fingerprints_len}")
                return
            
            while len(data) < offset + fingerprints_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    logger.warning(f"[{role}] Disconnected while reading device fingerprints")
                    return
                data += chunk
            
            fingerprints_json = data[offset:offset+fingerprints_len].decode('utf-8')
            try:
                device_fingerprints = json.loads(fingerprints_json)
                fp_summary = f"MAC:{device_fingerprints.get('mac', 'N/A')[:16]} CPU:{device_fingerprints.get('cpu', 'N/A')[:16]}"
                logger.info(f"[{role}] Device fingerprints received: {fp_summary}")
            except Exception as e:
                logger.warning(f"[{role}] Failed to parse device fingerprints: {e}")
                device_fingerprints = {}
            
            # Update device fingerprint database
            client_ip = addr[0]
            logger.info(f"[{role}] Calling update_device_fingerprint...")
            try:
                update_device_fingerprint(device_fingerprints, name, client_ip)
                logger.info(f"[{role}] update_device_fingerprint completed")
            except Exception as e:
                logger.error(f"[{role}] Error updating device fingerprint: {e}", exc_info=True)
            
            # Add IP address to device fingerprints for banning (IP ban expires in 7 days)
            device_fingerprints_with_ip = dict(device_fingerprints)
            device_fingerprints_with_ip['ip'] = client_ip
            logger.info(f"[{role}] Device fingerprints with IP prepared")
            
            # Check if any fingerprint is missing (non-compliant hardware)
            if not is_admin:
                logger.info(f"[{role}] Checking for missing fingerprints...")
                missing_fps = [fp_type for fp_type, fp_value in device_fingerprints.items() if fp_type != 'ip' and not fp_value]
                if missing_fps:
                    logger.warning(f"{role.capitalize()} [{name}] non-compliant hardware: missing {', '.join(missing_fps)}")
                    # Ban all available fingerprints with reason "Non-compliant hardware"
                    ban_device(device_fingerprints_with_ip, "system", "Non-compliant hardware")
                    banned_packet = struct.pack('!B', MSG_TYPE_BANNED)
                    conn.sendall(banned_packet)
                    import time
                    time.sleep(0.5)
                    return
            
            # Check if any admin is online (only for regular clients)
            if not is_admin:
                logger.info(f"[{role}] Checking if admin is online...")
                with global_lock:
                    admin_count = len(admins)
                logger.info(f"[{role}] Admin count: {admin_count}")
                if admin_count == 0:
                    logger.warning(f"Client [{name}] rejected: no admin online")
                    reject_packet = struct.pack('!B', MSG_TYPE_ADMIN_NOT_ONLINE)
                    conn.sendall(reject_packet)
                    import time
                    time.sleep(0.5)  # Give client time to receive the response
                    return
            
            # Check if device is banned (only for regular clients, not admins)
            if not is_admin:
                logger.info(f"[{role}] Checking if device is banned...")
                try:
                    is_banned, banned_type = is_device_banned(device_fingerprints_with_ip)
                    logger.info(f"[{role}] Device ban check result: is_banned={is_banned}, banned_type={banned_type}")
                    if is_banned:
                        ban_info = ban_list.get(device_fingerprints_with_ip.get(banned_type, ""), {})
                        logger.warning(f"{role.capitalize()} [{name}] connection rejected: device banned ({banned_type}) by {ban_info.get('banned_by', 'unknown')} at {ban_info.get('banned_at', 'unknown')}")
                        banned_packet = struct.pack('!B', MSG_TYPE_BANNED)
                        conn.sendall(banned_packet)
                        return
                except Exception as e:
                    logger.error(f"[{role}] Error checking device ban: {e}", exc_info=True)
                    return
            
            logger.info(f"[{role}] Password verified, generating session key...")
            record_auth_success(client_ip)
            
            # Generate session key
            session_key = get_random_bytes(32)
            logger.info(f"[{role}] Session key generated")
            
            # Generate random salt for key derivation (more secure than deriving salt from password)
            salt = get_random_bytes(32)
            derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            nonce = get_random_bytes(12)
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
            logger.info(f"[{role}] Session key encrypted with random salt")
            
            # Create client info
            client_info = ClientInfo(conn, name, session_key, is_admin, device_fingerprints, client_ip)
            logger.info(f"[{role}] Created client info object with device fingerprints")
            
            # Send auth success with encrypted session key AND user_id
            # Format: [msg_type(1)][salt(32)][nonce(12)][tag(16)][encrypted_session_key(32)][user_id(4)]
            response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + salt + nonce + tag + encrypted_session_key + struct.pack('!I', client_info.user_id)
            logger.info(f"[{role}] Sending auth success response with user_id={client_info.user_id} ({len(response)} bytes)...")
            conn.sendall(response)
            logger.info(f"[{role}] Auth success response sent")
            
            # For non-admin clients, send recording notice and wait for consent
            if not is_admin:
                try:
                    send_recording_notice(conn, name)
                    logger.info(f"[{role}] Waiting for recording consent from {name}...")
                    
                    # Wait for consent response (with timeout)
                    conn.settimeout(30)  # 30 second timeout for user to decide
                    consent_type_data = conn.recv(1)
                    
                    if not consent_type_data:
                        logger.warning(f"[{role}] {name} disconnected before providing consent")
                        conn.close()
                        return
                    
                    consent_type = struct.unpack('!B', consent_type_data)[0]
                    
                    if consent_type == MSG_TYPE_RECORDING_CONSENT:
                        consent_data = conn.recv(1)
                        if not consent_data:
                            logger.warning(f"[{role}] {name} sent incomplete consent")
                            conn.close()
                            return
                        
                        user_consent = struct.unpack('!B', consent_data)[0] == 1
                        
                        if not user_consent:
                            logger.info(f"[{role}] {name} refused recording consent, connection rejected")
                            conn.close()
                            return
                        
                        logger.info(f"[{role}] {name} consented to recording")
                    else:
                        logger.warning(f"[{role}] {name} sent unexpected message type: {consent_type}")
                        conn.close()
                        return
                    
                    # Reset timeout for handshake
                    conn.settimeout(10)
                except socket.timeout:
                    logger.warning(f"[{role}] {name} consent timeout")
                    conn.close()
                    return
                except Exception as e:
                    logger.error(f"[{role}] Error handling recording consent: {e}")
                    conn.close()
                    return
            
            # Add to clients/admins list AFTER consent
            with global_lock:
                if is_admin:
                    admins.append(client_info)
                    logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)})")
                else:
                    clients.append(client_info)
                    logger.info(f"User [{name}] joined and authenticated (total: {len(clients)})")
                    # Start recording for this user (only after consent)
                    audio_recorder.start_recording(name)
            
            # Broadcast outside of lock to avoid deadlock
            if not is_admin:
                logger.info(f"[{role}] About to broadcast user event...")
                try:
                    broadcast_user_event("joined", name)
                    logger.info(f"[{role}] Broadcast user event completed")
                except Exception as e:
                    logger.error(f"[{role}] Error broadcasting user event: {e}")
                try:
                    broadcast_user_list()
                    logger.info(f"[{role}] Broadcast user list completed")
                except Exception as e:
                    logger.error(f"[{role}] Error broadcasting user list: {e}")
                try:
                    broadcast_user_list_to_admins()
                    logger.info(f"[{role}] Broadcast detailed user list to admins completed")
                except Exception as e:
                    logger.error(f"[{role}] Error broadcasting detailed user list to admins: {e}")
            
            logger.info(f"[{role}] Setting socket to non-blocking...")
            # Set socket to non-blocking for audio forwarding
            conn.settimeout(None)
            
            logger.info(f"[{role}] Starting audio loop...")
            # Handle audio and heartbeat messages
            handle_audio_loop(client_info)
            
        elif msg_type == MSG_TYPE_ADMIN_JOIN:
            # Same as JOIN but for admin
            offset = 1
            name_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if name_len == 0 or name_len > 128:
                logger.warning(f"Invalid admin name length: {name_len}")
                return
            
            while len(data) < offset + name_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    return
                data += chunk
            
            name = data[offset:offset+name_len].decode('utf-8')
            offset += name_len
            
            encrypted_password_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if encrypted_password_len == 0 or encrypted_password_len > 512:
                logger.warning(f"Invalid encrypted password length: {encrypted_password_len}")
                return
            
            while len(data) < offset + encrypted_password_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    return
                data += chunk
            
            encrypted_password = data[offset:offset+encrypted_password_len]
            offset += encrypted_password_len
            
            # Decrypt password using RSA private key
            try:
                cipher = PKCS1_OAEP.new(server_rsa_key)
                password = cipher.decrypt(encrypted_password).decode('utf-8')
            except Exception as e:
                logger.warning(f"Admin [{name}] failed to decrypt password: {e}")
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            if password != ADMIN_PASSWORD:
                logger.warning(f"Admin [{name}] authentication failed from {addr} (wrong admin password)")
                record_auth_failure(addr[0])
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            # Read device fingerprints (JSON format)
            fingerprints_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if fingerprints_len == 0 or fingerprints_len > 1024:
                logger.warning(f"Invalid device fingerprint length: {fingerprints_len}")
                return
            
            while len(data) < offset + fingerprints_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    return
                data += chunk
            
            fingerprints_json = data[offset:offset+fingerprints_len].decode('utf-8')
            try:
                device_fingerprints = json.loads(fingerprints_json)
                fp_summary = f"MAC:{device_fingerprints.get('mac', 'N/A')[:16]} CPU:{device_fingerprints.get('cpu', 'N/A')[:16]}"
                logger.info(f"Admin [{name}] device fingerprints: {fp_summary}")
            except Exception as e:
                logger.warning(f"Admin [{name}] failed to parse device fingerprints: {e}")
                device_fingerprints = {}
            
            # Update device fingerprint database
            client_ip = addr[0]
            update_device_fingerprint(device_fingerprints, name, client_ip)
            
            session_key = get_random_bytes(32)
            
            # Create client info first to get user_id
            client_info = ClientInfo(conn, name, session_key, is_admin=True, device_fingerprints=device_fingerprints)
            
            # Generate random salt for key derivation (more secure than deriving salt from password)
            salt = get_random_bytes(32)
            derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            nonce = get_random_bytes(12)
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
            
            # Format: [msg_type(1)][salt(32)][nonce(12)][tag(16)][encrypted_session_key(32)][user_id(4)]
            response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + salt + nonce + tag + encrypted_session_key + struct.pack('!I', client_info.user_id)
            conn.sendall(response)
            
            with global_lock:
                admins.append(client_info)
                logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)})")
            
            # Broadcast outside of lock to avoid deadlock
            broadcast_user_list_to_admins()
            
            conn.settimeout(None)
            handle_audio_loop(client_info)
        
    except socket.timeout:
        logger.warning(f"{role.capitalize()} connection timed out during handshake")
    except Exception as e:
        import traceback
        logger.error(f"Error handling {role} connection: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
        # Remove client from list
        removed_name = None
        with global_lock:
            target_list = admins if is_admin else clients
            for i, c in enumerate(target_list):
                if c.conn == conn:
                    removed_name = c.name
                    target_list.pop(i)
                    logger.info(f"{role.capitalize()} [{c.name}] disconnected (total: {len(target_list)})")
                    break
        
        # If an admin disconnected, force all clients to disconnect
        if is_admin and removed_name:
            logger.info(f"Admin [{removed_name}] disconnected, forcing all clients to disconnect")
            with global_lock:
                clients_to_disconnect = list(clients)
                clients.clear()
            
            for client in clients_to_disconnect:
                try:
                    # Send disconnect signal to client
                    disconnect_packet = struct.pack('!B', MSG_TYPE_LEAVE)
                    client.conn.sendall(disconnect_packet)
                    logger.info(f"Force disconnected client [{client.name}]")
                except Exception as e:
                    logger.warning(f"Failed to force disconnect client [{client.name}]: {e}")
                finally:
                    try:
                        client.conn.close()
                    except:
                        pass
            
            # Notify remaining admins about the disconnected clients
            try:
                broadcast_user_list_to_admins()
            except Exception as e:
                logger.error(f"Error broadcasting admin disconnect event: {e}")
        
        # Broadcast outside of lock to avoid deadlock
        if not is_admin and removed_name:
            try:
                broadcast_user_event("left", removed_name)
                broadcast_user_list()
                broadcast_user_list_to_admins()
            except Exception as e:
                logger.error(f"Error broadcasting disconnect event: {e}")
        elif is_admin and removed_name:
            try:
                broadcast_user_list_to_admins()
            except Exception as e:
                logger.error(f"Error broadcasting admin disconnect event: {e}")
        conn.close()


def handle_audio_loop(client_info):
    """Main loop for receiving and forwarding audio packets."""
    is_admin = client_info.is_admin
    role = "admin" if is_admin else "client"
    logger.info(f"[{role}] Entering audio loop for {client_info.name}")
    
    # Set socket timeout for recv operations to detect dead connections
    # Only set timeout for clients (who send audio), not admins (who only receive)
    # Note: We use a longer timeout (60s) to avoid premature disconnection during network issues
    # The heartbeat check mechanism will handle actual connection monitoring
    if not is_admin:
        client_info.conn.settimeout(60.0)  # 60 second timeout for recv
    else:
        client_info.conn.settimeout(None)  # Admin doesn't send audio, no timeout needed
    
    while True:
        try:
            # Read message header (at least 2 bytes: msg_type + data)
            header = client_info.conn.recv(1)
            if not header:
                logger.info(f"{role.capitalize()} [{client_info.name}] connection closed")
                break
            
            # Update last activity time (TCP connection is alive)
            client_info.last_heartbeat = time.time()
            
            msg_type = struct.unpack('!B', header)[0]
            
            if msg_type == MSG_TYPE_HEARTBEAT:
                # Read encrypted heartbeat data: [encrypted_len(4)][encrypted_data]
                enc_len_data = b''
                while len(enc_len_data) < 4:
                    chunk = client_info.conn.recv(4 - len(enc_len_data))
                    if not chunk:
                        break
                    enc_len_data += chunk
                
                if len(enc_len_data) < 4:
                    break
                
                encrypted_len = struct.unpack('!I', enc_len_data)[0]
                if encrypted_len > 1000:
                    logger.warning(f"Invalid encrypted heartbeat data length: {encrypted_len}")
                    break
                
                encrypted_data = b''
                while len(encrypted_data) < encrypted_len:
                    chunk = client_info.conn.recv(min(encrypted_len - len(encrypted_data), MAX_PACKET_SIZE))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if len(encrypted_data) < encrypted_len:
                    break
                
                # Decrypt heartbeat to get name (for logging)
                try:
                    decrypted_name = server_decrypt_with_key(encrypted_data, client_info.session_key)
                    if decrypted_name:
                        logger.debug(f"Heartbeat from [{decrypted_name.decode('utf-8')}]")
                except Exception:
                    pass
                continue
            
            if msg_type == MSG_TYPE_LEAVE:
                # Read encrypted leave data: [encrypted_len(4)][encrypted_data]
                enc_len_data = b''
                while len(enc_len_data) < 4:
                    chunk = client_info.conn.recv(4 - len(enc_len_data))
                    if not chunk:
                        break
                    enc_len_data += chunk
                
                if len(enc_len_data) < 4:
                    break
                
                encrypted_len = struct.unpack('!I', enc_len_data)[0]
                if encrypted_len > 1000:
                    logger.warning(f"Invalid encrypted leave data length: {encrypted_len}")
                    break
                
                encrypted_data = b''
                while len(encrypted_data) < encrypted_len:
                    chunk = client_info.conn.recv(min(encrypted_len - len(encrypted_data), MAX_PACKET_SIZE))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if len(encrypted_data) < encrypted_len:
                    break
                
                # Decrypt leave message
                try:
                    decrypted_name = server_decrypt_with_key(encrypted_data, client_info.session_key)
                    if decrypted_name:
                        logger.info(f"{role.capitalize()} [{decrypted_name.decode('utf-8')}] sent LEAVE")
                except Exception:
                    logger.info(f"{role.capitalize()} [{client_info.name}] sent LEAVE")
                break
            
            # Handle admin commands BEFORE checking for audio
            if msg_type == MSG_TYPE_ADMIN_BAN and role == 'admin':
                # Admin ban command: [msg_type(1)][encrypted_len(4)][encrypted_data]
                enc_len_data = b''
                while len(enc_len_data) < 4:
                    chunk = client_info.conn.recv(4 - len(enc_len_data))
                    if not chunk:
                        break
                    enc_len_data += chunk
                
                if len(enc_len_data) < 4:
                    break
                
                encrypted_len = struct.unpack('!I', enc_len_data)[0]
                if encrypted_len == 0 or encrypted_len > 1000:
                    logger.warning(f"Invalid encrypted data length for BAN: {encrypted_len}")
                    break
                
                encrypted_data = b''
                while len(encrypted_data) < encrypted_len:
                    chunk = client_info.conn.recv(min(encrypted_len - len(encrypted_data), MAX_PACKET_SIZE))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if len(encrypted_data) < encrypted_len:
                    break
                
                # Decrypt the command data
                ban_data = server_decrypt_with_key(encrypted_data, client_info.session_key)
                if ban_data is None:
                    logger.warning(f"Failed to decrypt BAN command from admin [{client_info.name}]")
                    break
                
                # Parse decrypted data: [target_name_len(4)][target_name][reason_len(4)][reason]
                offset = 0
                target_name_len = struct.unpack('!I', ban_data[offset:offset+4])[0]
                offset += 4
                
                if target_name_len == 0 or target_name_len > 100:
                    logger.warning(f"Invalid target name length: {target_name_len}")
                    break
                
                target_name = ban_data[offset:offset+target_name_len].decode('utf-8')
                offset += target_name_len
                
                reason_len = struct.unpack('!I', ban_data[offset:offset+4])[0]
                offset += 4
                
                if reason_len > 500:
                    logger.warning(f"Invalid reason length: {reason_len}")
                    break
                
                reason = ban_data[offset:offset+reason_len].decode('utf-8') if reason_len > 0 else ""
                
                logger.info(f"Admin [{client_info.name}] banning user '{target_name}' (reason: {reason})")
                
                # Find target client and ban their device
                with global_lock:
                    target_client = None
                    for c in clients:
                        if c.name == target_name:
                            target_client = c
                            break
                
                if target_client:
                    # Build fingerprints dict with IP address for banning
                    target_fingerprints = dict(target_client.device_fingerprints)
                    if target_client.ip_address:
                        target_fingerprints['ip'] = target_client.ip_address
                    
                    # Ban the device (IP will be banned for 7 days, hardware fingerprints permanently)
                    ban_device(target_fingerprints, client_info.name, reason)
                    
                    # Kick the client
                    try:
                        target_client.conn.sendall(struct.pack('!B', MSG_TYPE_BANNED))
                    except Exception:
                        pass
                    
                    # Remove from clients list
                    with global_lock:
                        if target_client in clients:
                            clients.remove(target_client)
                    
                    logger.info(f"User '{target_name}' has been banned and kicked by admin [{client_info.name}]")
                    
                    # Broadcast updated user list to all admins
                    broadcast_user_list_to_admins()
                else:
                    logger.warning(f"Target user '{target_name}' not found for ban command")
                continue
            
            elif msg_type == MSG_TYPE_ADMIN_GET_BAN_LIST and role == 'admin':
                # Admin request for ban list: [msg_type(1)][encrypted_len(4)][encrypted_data]
                enc_len_data = b''
                while len(enc_len_data) < 4:
                    chunk = client_info.conn.recv(4 - len(enc_len_data))
                    if not chunk:
                        break
                    enc_len_data += chunk
                
                if len(enc_len_data) < 4:
                    break
                
                encrypted_len = struct.unpack('!I', enc_len_data)[0]
                
                # Read and discard encrypted data (even if empty, it's encrypted)
                if encrypted_len > 0:
                    encrypted_data = b''
                    while len(encrypted_data) < encrypted_len:
                        chunk = client_info.conn.recv(min(encrypted_len - len(encrypted_data), MAX_PACKET_SIZE))
                        if not chunk:
                            break
                        encrypted_data += chunk
                
                logger.info(f"Admin [{client_info.name}] requesting ban list")
                
                ban_list_data = get_ban_list_grouped()
                ban_list_json = json.dumps(ban_list_data, ensure_ascii=False).encode('utf-8')
                
                # Send encrypted ban list: [msg_type(1)][encrypted_len(4)][encrypted_data]
                encrypted_data = server_encrypt_with_key(ban_list_json, client_info.session_key)
                ban_packet = struct.pack('!B', MSG_TYPE_BAN_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                client_info.conn.sendall(ban_packet)
                logger.info(f"Sent encrypted ban list with {len(ban_list_data)} devices to admin [{client_info.name}]")
                continue
            
            elif msg_type == MSG_TYPE_ADMIN_UNBAN and role == 'admin':
                # Admin unban command: [msg_type(1)][encrypted_len(4)][encrypted_data]
                enc_len_data = b''
                while len(enc_len_data) < 4:
                    chunk = client_info.conn.recv(4 - len(enc_len_data))
                    if not chunk:
                        break
                    enc_len_data += chunk
                
                if len(enc_len_data) < 4:
                    break
                
                encrypted_len = struct.unpack('!I', enc_len_data)[0]
                if encrypted_len == 0 or encrypted_len > 1000:
                    logger.warning(f"Invalid encrypted data length for UNBAN: {encrypted_len}")
                    break
                
                encrypted_data = b''
                while len(encrypted_data) < encrypted_len:
                    chunk = client_info.conn.recv(min(encrypted_len - len(encrypted_data), MAX_PACKET_SIZE))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if len(encrypted_data) < encrypted_len:
                    break
                
                # Decrypt the command data
                unban_data = server_decrypt_with_key(encrypted_data, client_info.session_key)
                if unban_data is None:
                    logger.warning(f"Failed to decrypt UNBAN command from admin [{client_info.name}]")
                    break
                
                # Parse decrypted data: [device_key_len(4)][device_key]
                device_key_len = struct.unpack('!I', unban_data[0:4])[0]
                if device_key_len == 0 or device_key_len > 500:
                    logger.warning(f"Invalid device key length: {device_key_len}")
                    break
                
                device_key = unban_data[4:4+device_key_len].decode('utf-8')
                
                logger.info(f"Admin [{client_info.name}] unbanning device '{device_key[:32]}...'")
                
                success = unban_device_group(device_key)
                
                if success:
                    logger.info(f"Device '{device_key[:32]}...' has been unbanned by admin [{client_info.name}]")
                else:
                    logger.warning(f"Device '{device_key[:32]}...' not found in ban list")
                
                # Send updated ban list to all admins
                broadcast_ban_list_to_admins()
                continue
            
            if msg_type == MSG_TYPE_AUDIO:
                try:
                    logger.debug(f"[{role}] Received audio packet from {client_info.name}")
                    # Read audio data with timestamp
                    # Format: [timestamp(8)][encrypted_len(4)][encrypted_audio]
                    timestamp_data = b''
                    while len(timestamp_data) < 8:
                        chunk = client_info.conn.recv(8 - len(timestamp_data))
                        if not chunk:
                            break
                        timestamp_data += chunk
                    
                    if len(timestamp_data) < 8:
                        logger.warning(f"[{role}] Incomplete timestamp from {client_info.name}")
                        break
                    
                    timestamp = struct.unpack('!d', timestamp_data)[0]
                    current_time = time.time()
                    
                    # Check if packet is too old (timeout)
                    packet_age_ms = (current_time - timestamp) * 1000
                    if packet_age_ms > AUDIO_PACKET_TIMEOUT_MS:
                        logger.debug(f"Dropping old audio packet from {client_info.name} (age: {packet_age_ms:.0f}ms)")
                        continue
                    
                    # Read encrypted audio data
                    audio_data = b''
                    while len(audio_data) < 4:
                        chunk = client_info.conn.recv(4 - len(audio_data))
                        if not chunk:
                            break
                        audio_data += chunk
                    
                    if len(audio_data) < 4:
                        logger.warning(f"[{role}] Incomplete audio length from {client_info.name}")
                        break
                    
                    audio_len = struct.unpack('!I', audio_data)[0]
                    logger.debug(f"[{role}] Audio length: {audio_len} from {client_info.name}")
                    
                    encrypted_audio = b''
                    while len(encrypted_audio) < audio_len:
                        chunk = client_info.conn.recv(min(audio_len - len(encrypted_audio), MAX_PACKET_SIZE))
                        if not chunk:
                            break
                        encrypted_audio += chunk
                    
                    if len(encrypted_audio) < audio_len:
                        logger.warning(f"[{role}] Incomplete audio data from {client_info.name}")
                        break
                    
                    logger.debug(f"[{role}] Received full audio packet ({len(encrypted_audio)} bytes) from {client_info.name}")
                    
                    # Decrypt and re-encrypt for each recipient
                    decrypted_audio = server_decrypt_with_key(encrypted_audio, client_info.session_key)
                    if decrypted_audio is None:
                        logger.warning(f"Decryption failed for audio from {client_info.name}")
                        continue
                    
                    logger.debug(f"[{role}] Decrypted audio ({len(decrypted_audio)} bytes) from {client_info.name}")
                    
                    # Decompress audio data for recording
                    try:
                        import zlib
                        pcm_audio = zlib.decompress(decrypted_audio)
                        # Record audio if recording is enabled
                        audio_recorder.write_audio(client_info.name, pcm_audio)
                    except Exception as e:
                        logger.warning(f"Failed to decompress/record audio from {client_info.name}: {e}")
                    
                    # Forward to all clients except sender
                    with global_lock:
                        all_clients = list(clients)
                        all_admins = list(admins)
                    
                    logger.debug(f"[{role}] Forwarding to {len(all_clients)} clients, {len(all_admins)} admins")
                    
                    # Prepare sender info
                    sender_id_bytes = struct.pack('!I', client_info.user_id)
                    sender_name_bytes = client_info.name.encode('utf-8')
                    sender_name_len = struct.pack('!B', len(sender_name_bytes))
                    
                    for recipient in all_clients:
                        if recipient is client_info:
                            continue
                        try:
                            re_encrypted = server_encrypt_with_key(decrypted_audio, recipient.session_key)
                            # Format for client: [msg_type(1)][sender_id(4)][sender_name_len(1)][sender_name(N)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                            re_packet = (
                                struct.pack('!B', MSG_TYPE_AUDIO) +
                                sender_id_bytes +
                                sender_name_len +
                                sender_name_bytes +
                                struct.pack('!d', current_time) +
                                struct.pack('!I', len(re_encrypted)) +
                                re_encrypted
                            )
                            recipient.conn.sendall(re_packet)
                            logger.debug(f"[{role}] Forwarded audio to client [{recipient.name}]")
                        except (BrokenPipeError, ConnectionResetError, OSError) as e:
                            logger.warning(f"Client [{recipient.name}] connection error during audio forward: {e}")
                            with global_lock:
                                if recipient in clients:
                                    clients.remove(recipient)
                        except Exception as e:
                            import traceback
                            logger.warning(f"Failed to forward audio to client [{recipient.name}]: {e}")
                            logger.warning(f"Traceback: {traceback.format_exc()}")
                            with global_lock:
                                if recipient in clients:
                                    clients.remove(recipient)
                    
                    # Forward to all admins (with sender_id and sender_name for identification)
                    for admin in all_admins:
                        try:
                            re_encrypted = server_encrypt_with_key(decrypted_audio, admin.session_key)
                            # Format for admin: [msg_type(1)][sender_id(4)][sender_name_len(1)][sender_name(N)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                            re_packet = (
                                struct.pack('!B', MSG_TYPE_AUDIO) +
                                sender_id_bytes +
                                sender_name_len +
                                sender_name_bytes +
                                struct.pack('!d', current_time) +
                                struct.pack('!I', len(re_encrypted)) +
                                re_encrypted
                            )
                            admin.conn.sendall(re_packet)
                            # Update admin's last activity time since they only receive audio
                            admin.last_heartbeat = current_time
                            logger.debug(f"[{role}] Forwarded audio to admin [{admin.name}] from [{client_info.name}(ID:{client_info.user_id})]")
                        except (BrokenPipeError, ConnectionResetError, OSError) as e:
                            logger.warning(f"Admin [{admin.name}] connection error during audio forward: {e}")
                            with global_lock:
                                if admin in admins:
                                    admins.remove(admin)
                except Exception as e:
                    import traceback
                    logger.error(f"[{role}] Error processing audio from {client_info.name}: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    break
            else:
                # For admins, unknown message types are expected (they don't send audio)
                # Just log and continue waiting for valid admin commands
                if role == 'admin':
                    logger.debug(f"[{role}] Ignoring unknown message type: {msg_type} from {client_info.name}")
                    continue
                else:
                    logger.warning(f"[{role}] Unknown message type: {msg_type} from {client_info.name}")
                    break
        except ConnectionResetError:
            logger.info(f"{role.capitalize()} [{client_info.name}] connection reset")
            break
        except BrokenPipeError:
            logger.info(f"{role.capitalize()} [{client_info.name}] connection broken")
            break
        except ConnectionAbortedError:
            logger.info(f"{role.capitalize()} [{client_info.name}] connection aborted (locally closed)")
            break
        except OSError as e:
            logger.info(f"{role.capitalize()} [{client_info.name}] socket error: {e}")
            break
        except socket.timeout:
            logger.info(f"{role.capitalize()} [{client_info.name}] socket timeout (30s), treating as disconnected")
            break
        except Exception as e:
            import traceback
            logger.error(f"Error handling {role} [{client_info.name}]: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            break
    
    # Stop recording when client disconnects
    if not is_admin:
        audio_recorder.stop_recording(client_info.name)
    
    client_info.conn.close()


def check_heartbeats():
    """Periodically check for timed-out clients and admins."""
    while True:
        time.sleep(3)
        
        with global_lock:
            timed_out = []
            for c in clients:
                if time.time() - c.last_heartbeat > HEARTBEAT_TIMEOUT:
                    timed_out.append(('client', c))
            for a in admins:
                if time.time() - a.last_heartbeat > HEARTBEAT_TIMEOUT:
                    timed_out.append(('admin', a))
            
            # Remove timed out clients/admins from lists first
            for role, c in timed_out:
                if role == 'client':
                    if c in clients:
                        clients.remove(c)
                        logger.info(f"User [{c.name}] heartbeat timeout, removed (total: {len(clients)})")
                else:
                    if c in admins:
                        admins.remove(c)
                        logger.info(f"Admin [{c.name}] heartbeat timeout, removed (total: {len(admins)})")
                
                # Close the connection
                try:
                    c.conn.close()
                except:
                    pass
        
        # Broadcast outside of lock to avoid blocking new connections
        for role, c in timed_out:
            if role == 'client':
                broadcast_user_event("left", c.name)
                broadcast_user_list()
                broadcast_user_list_to_admins()
            else:
                # Force all clients to disconnect when admin times out (only if REQUIRE_ADMIN is true)
                if REQUIRE_ADMIN:
                    with global_lock:
                        clients_to_disconnect = list(clients)
                        clients.clear()
                    
                    for client in clients_to_disconnect:
                        try:
                            disconnect_packet = struct.pack('!B', MSG_TYPE_LEAVE)
                            client.conn.sendall(disconnect_packet)
                            logger.info(f"Force disconnected client [{client.name}] due to admin timeout")
                        except Exception as e:
                            logger.warning(f"Failed to force disconnect client [{client.name}]: {e}")
                        finally:
                            try:
                                client.conn.close()
                            except:
                                pass
                else:
                    logger.info("Admin timed out but REQUIRE_ADMIN=false, clients remain connected")
                
                broadcast_user_list_to_admins()


def start_server(port, is_admin=False):
    """Start TCP server."""
    role = "admin" if is_admin else "client"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(128)
    logger.info(f"{role.capitalize()} server started on {HOST}:{port}")
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, is_admin))
        thread.daemon = True
        thread.start()


def main():
    global server_rsa_key, server_public_key, public_key_bytes, public_key_fingerprint
    
    parser = argparse.ArgumentParser(description="OpenVoiceChat Server (TCP)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Load or generate RSA key pair (persistent like SSH host key)
    key_file = os.path.join(os.path.dirname(__file__), 'server_rsa_key.pem')
    
    if os.path.exists(key_file):
        # Load existing key
        with open(key_file, 'rb') as f:
            server_rsa_key = RSA.import_key(f.read())
        logger.info(f"RSA key loaded from {key_file}")
    else:
        # Generate new key and save to file
        server_rsa_key = RSA.generate(2048)
        with open(key_file, 'wb') as f:
            f.write(server_rsa_key.export_key())
        os.chmod(key_file, 0o600)  # Restrict permissions
        logger.info(f"RSA key generated and saved to {key_file}")
    
    server_public_key = server_rsa_key.publickey()
    public_key_bytes = server_public_key.export_key()
    public_key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
    logger.info(f"Server public key fingerprint: {public_key_fingerprint}")
    logger.info(f"Verify this fingerprint on client side to prevent MITM attacks")
    
    logger.info("Session-based authentication enabled")
    
    # Load device fingerprint database
    load_device_db()
    
    # Load ban list
    load_ban_list()
    
    # Start heartbeat checker
    heartbeat_thread = threading.Thread(target=check_heartbeats)
    heartbeat_thread.daemon = True
    heartbeat_thread.start()
    
    # Start client server
    client_thread = threading.Thread(target=start_server, args=(CLIENT_PORT, False))
    client_thread.daemon = True
    client_thread.start()
    
    # Start admin server
    admin_thread = threading.Thread(target=start_server, args=(ADMIN_PORT, True))
    admin_thread.daemon = True
    admin_thread.start()
    
    logger.info(f"Client server listening on {HOST}:{CLIENT_PORT}")
    logger.info(f"Admin server listening on {HOST}:{ADMIN_PORT}")
    
    # Register signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        audio_recorder.stop_all()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down")
        # Stop all recordings
        audio_recorder.stop_all()


if __name__ == "__main__":
    main()