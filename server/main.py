import socket
import threading
import struct
import logging
import argparse
import time
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# Server password - can be set via OVC_PASSWORD environment variable
_env_password = os.environ.get("OVC_PASSWORD")
if _env_password:
    SERVER_PASSWORD = _env_password
    logger.info(f"Using password from OVC_PASSWORD environment variable")
else:
    SERVER_PASSWORD = "OpenVoiceChat2026!"
    logger.info("Using default password (OVC_PASSWORD not set)")

HOST = '0.0.0.0'
CLIENT_PORT = 9090
ADMIN_PORT = 9091
MAX_PACKET_SIZE = 65536

# Message type constants
MSG_TYPE_JOIN = 1
MSG_TYPE_AUDIO = 2
MSG_TYPE_ADMIN_JOIN = 4
MSG_TYPE_USER_LIST = 5
MSG_TYPE_USER_JOINED = 6
MSG_TYPE_HEARTBEAT = 7
MSG_TYPE_LEAVE = 8
MSG_TYPE_AUTH_SUCCESS = 9
MSG_TYPE_AUTH_FAIL = 10

# Audio packet timeout (milliseconds) - drop packets older than this
AUDIO_PACKET_TIMEOUT_MS = 200

class ClientInfo:
    """Stores information about a connected client."""
    def __init__(self, conn, name, session_key, is_admin=False):
        self.conn = conn
        self.name = name
        self.session_key = session_key
        self.is_admin = is_admin
        self.last_heartbeat = time.time()
        self.lock = threading.Lock()

clients = []  # List of ClientInfo (non-admin)
admins = []   # List of ClientInfo (admin)
global_lock = threading.Lock()
HEARTBEAT_TIMEOUT = 10  # Seconds before a client is considered disconnected


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
        user_names = [c.name for c in clients]
        admin_names = [a.name for a in admins]
    
    user_list_data = "Users: " + ", ".join(user_names)
    admin_list_data = "Users: " + ", ".join(user_names) + " | Admins: " + ", ".join(admin_names)
    
    user_header = struct.pack('!B', MSG_TYPE_USER_LIST)
    
    with global_lock:
        all_clients = list(clients)
        all_admins = list(admins)
    
    for client in all_clients:
        try:
            packet = user_header + user_list_data.encode('utf-8')
            client.conn.sendall(packet)
        except Exception:
            pass
    
    for admin in all_admins:
        try:
            packet = user_header + admin_list_data.encode('utf-8')
            admin.conn.sendall(packet)
        except Exception:
            pass


def broadcast_user_event(event_type, name):
    """Broadcast a user join/leave event to all clients and admins."""
    event_data = f"{name} has joined" if event_type == MSG_TYPE_USER_JOINED else f"{name} has left"
    event_bytes = event_data.encode('utf-8')
    header = struct.pack('!B', event_type)
    packet = header + event_bytes
    
    with global_lock:
        all_clients = list(clients)
        all_admins = list(admins)
    
    for client in all_clients:
        try:
            client.conn.sendall(packet)
        except Exception:
            pass
    
    for admin in all_admins:
        try:
            admin.conn.sendall(packet)
        except Exception:
            pass


def handle_client(conn, addr, is_admin=False):
    """Handle a single client connection."""
    role = "admin" if is_admin else "client"
    logger.info(f"{role.capitalize()} connected from {addr}")
    
    try:
        # Set socket timeout for initial handshake
        conn.settimeout(10)
        
        # Receive JOIN message
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
            # Parse JOIN packet: [msg_type(1)][name_len(4)][name][password_len(4)][password]
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
            
            password_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logger.info(f"[{role}] Password length: {password_len}")
            
            if password_len == 0 or password_len > 256:
                logger.warning(f"Invalid password length: {password_len}")
                return
            
            while len(data) < offset + password_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    logger.warning(f"[{role}] Disconnected while reading password")
                    return
                data += chunk
                logger.info(f"[{role}] Received more data for password, total: {len(data)}")
            
            password = data[offset:offset+password_len].decode('utf-8')
            logger.info(f"[{role}] Password received, verifying...")
            
            # Verify password
            if password != SERVER_PASSWORD:
                logger.warning(f"User [{name}] authentication failed from {addr}")
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            logger.info(f"[{role}] Password verified, generating session key...")
            
            # Generate session key
            session_key = get_random_bytes(32)
            logger.info(f"[{role}] Session key generated")
            
            # Send auth success with encrypted session key
            salt = hashlib.sha256(password.encode('utf-8')).digest()
            derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            nonce = get_random_bytes(12)
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
            logger.info(f"[{role}] Encrypted session key prepared")
            
            response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + nonce + tag + encrypted_session_key
            logger.info(f"[{role}] Sending auth success response ({len(response)} bytes)...")
            conn.sendall(response)
            logger.info(f"[{role}] Auth success response sent")
            
            # Create client info
            client_info = ClientInfo(conn, name, session_key, is_admin)
            logger.info(f"[{role}] Created client info object")
            
            with global_lock:
                if is_admin:
                    admins.append(client_info)
                    logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)})")
                else:
                    clients.append(client_info)
                    logger.info(f"User [{name}] joined and authenticated (total: {len(clients)})")
            
            # Broadcast outside of lock to avoid deadlock
            if not is_admin:
                logger.info(f"[{role}] About to broadcast user event...")
                try:
                    broadcast_user_event(MSG_TYPE_USER_JOINED, name)
                    logger.info(f"[{role}] Broadcast user event completed")
                except Exception as e:
                    logger.error(f"[{role}] Error broadcasting user event: {e}")
                try:
                    broadcast_user_list()
                    logger.info(f"[{role}] Broadcast user list completed")
                except Exception as e:
                    logger.error(f"[{role}] Error broadcasting user list: {e}")
            
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
            
            password_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if password_len == 0 or password_len > 256:
                logger.warning(f"Invalid password length: {password_len}")
                return
            
            while len(data) < offset + password_len:
                chunk = conn.recv(MAX_PACKET_SIZE)
                if not chunk:
                    return
                data += chunk
            
            password = data[offset:offset+password_len].decode('utf-8')
            
            if password != SERVER_PASSWORD:
                logger.warning(f"Admin [{name}] authentication failed from {addr}")
                fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                conn.sendall(fail_packet)
                return
            
            session_key = get_random_bytes(32)
            
            salt = hashlib.sha256(password.encode('utf-8')).digest()
            derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            nonce = get_random_bytes(12)
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
            
            response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + nonce + tag + encrypted_session_key
            conn.sendall(response)
            
            client_info = ClientInfo(conn, name, session_key, is_admin=True)
            
            with global_lock:
                admins.append(client_info)
                logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)})")
            
            # Broadcast outside of lock to avoid deadlock
            broadcast_user_list()
            
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
        # Broadcast outside of lock to avoid deadlock
        if not is_admin and removed_name:
            try:
                broadcast_user_event(MSG_TYPE_USER_JOINED, removed_name)
                broadcast_user_list()
            except Exception as e:
                logger.error(f"Error broadcasting disconnect event: {e}")
        conn.close()


def handle_audio_loop(client_info):
    """Main loop for receiving and forwarding audio packets."""
    is_admin = client_info.is_admin
    role = "admin" if is_admin else "client"
    
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
                continue
            
            if msg_type == MSG_TYPE_LEAVE:
                logger.info(f"{role.capitalize()} [{client_info.name}] sent LEAVE")
                break
            
            if msg_type == MSG_TYPE_AUDIO:
                # Read audio data with timestamp
                # Format: [timestamp(8)][encrypted_len(4)][encrypted_audio]
                timestamp_data = b''
                while len(timestamp_data) < 8:
                    chunk = client_info.conn.recv(8 - len(timestamp_data))
                    if not chunk:
                        break
                    timestamp_data += chunk
                
                if len(timestamp_data) < 8:
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
                    break
                
                audio_len = struct.unpack('!I', audio_data)[0]
                
                encrypted_audio = b''
                while len(encrypted_audio) < audio_len:
                    chunk = client_info.conn.recv(min(audio_len - len(encrypted_audio), MAX_PACKET_SIZE))
                    if not chunk:
                        break
                    encrypted_audio += chunk
                
                if len(encrypted_audio) < audio_len:
                    break
                
                # Decrypt and re-encrypt for each recipient
                decrypted_audio = server_decrypt_with_key(encrypted_audio, client_info.session_key)
                if decrypted_audio is None:
                    logger.warning(f"Decryption failed for audio from {client_info.name}")
                    continue
                
                # Forward to all clients except sender
                with global_lock:
                    all_clients = list(clients)
                    all_admins = list(admins)
                
                for recipient in all_clients:
                    if recipient is client_info:
                        continue
                    try:
                        re_encrypted = server_encrypt_with_key(decrypted_audio, recipient.session_key)
                        re_packet = struct.pack('!B', MSG_TYPE_AUDIO) + struct.pack('!d', current_time) + struct.pack('!I', len(re_encrypted)) + re_encrypted
                        recipient.conn.sendall(re_packet)
                    except Exception:
                        pass
                
                # Forward to all admins
                for admin in all_admins:
                    try:
                        re_encrypted = server_encrypt_with_key(decrypted_audio, admin.session_key)
                        re_packet = struct.pack('!B', MSG_TYPE_AUDIO) + struct.pack('!d', current_time) + struct.pack('!I', len(re_encrypted)) + re_encrypted
                        admin.conn.sendall(re_packet)
                        # Update admin's last activity time since they only receive audio
                        admin.last_heartbeat = current_time
                    except Exception:
                        pass
        
        except socket.timeout:
            # Check activity timeout
            if time.time() - client_info.last_heartbeat > HEARTBEAT_TIMEOUT:
                logger.info(f"{role.capitalize()} [{client_info.name}] connection timeout")
                break
            continue
        except Exception as e:
            logger.error(f"Audio socket error for {client_info.name}: {e}")
            break


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
            
            for role, c in timed_out:
                if role == 'client':
                    clients.remove(c)
                    logger.info(f"User [{c.name}] heartbeat timeout, removed (total: {len(clients)})")
                    broadcast_user_event(MSG_TYPE_USER_JOINED, c.name)
                    broadcast_user_list()
                else:
                    admins.remove(c)
                    logger.info(f"Admin [{c.name}] heartbeat timeout, removed (total: {len(admins)})")
                    broadcast_user_list()


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
    parser = argparse.ArgumentParser(description="OpenVoiceChat Server (TCP)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger.info("Session-based authentication enabled")
    
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
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down")


if __name__ == "__main__":
    main()