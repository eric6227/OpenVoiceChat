import socket
import threading
import struct
import logging
import argparse
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# Server password - CHANGE THIS TO A STRONG PASSWORD!
SERVER_PASSWORD = "OpenVoiceChat2026!"

HOST = '0.0.0.0'
PORT = 9090           # Client audio data port
ADMIN_PORT = 9091     # Admin audio data port
SIGNAL_PORT = 9092    # Client signal port
ADMIN_SIGNAL_PORT = 9093  # Admin signal port
MAX_PACKET_SIZE = 65536

clients = {}          # {addr: {'name': str, 'last_heartbeat': float, 'session_key': bytes}}
admins = {}           # {addr: {'name': str, 'last_heartbeat': float, 'session_key': bytes}}
clients_lock = threading.Lock()
HEARTBEAT_TIMEOUT = 10  # Seconds before a client is considered disconnected

# Signaling sockets (global, used by broadcast functions)
sock_client_signal = None
sock_admin_signal = None

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


def broadcast_user_list():
    """Send the current user list to all connected clients and admins."""
    with clients_lock:
        user_names = [info['name'] for info in clients.values()]
        admin_names = [info['name'] for info in admins.values()]
    
    # Build different list messages for clients vs admins
    user_list_data = "Users: " + ", ".join(user_names)
    admin_list_data = "Users: " + ", ".join(user_names) + " | Admins: " + ", ".join(admin_names)
    
    user_header = struct.pack('!B', MSG_TYPE_USER_LIST)
    
    with clients_lock:
        client_addrs = list(clients.keys())
        admin_addrs = list(admins.keys())
    
    for addr in client_addrs:
        try:
            packet = user_header + user_list_data.encode('utf-8')
            sock_client_signal.sendto(packet, addr)
        except Exception:
            pass
    
    for addr in admin_addrs:
        try:
            packet = user_header + admin_list_data.encode('utf-8')
            sock_admin_signal.sendto(packet, addr)
        except Exception:
            pass


def broadcast_user_event(event_type, name):
    """Broadcast a user join/leave event to all clients and admins."""
    event_data = f"{name} has joined" if event_type == MSG_TYPE_USER_JOINED else f"{name} has left"
    event_bytes = event_data.encode('utf-8')
    header = struct.pack('!B', event_type)
    packet = header + event_bytes
    
    with clients_lock:
        client_addrs = list(clients.keys())
        admin_addrs = list(admins.keys())
    
    for addr in client_addrs:
        try:
            sock_client_signal.sendto(packet, addr)
        except Exception:
            pass
    
    for addr in admin_addrs:
        try:
            sock_admin_signal.sendto(packet, addr)
        except Exception:
            pass


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


def broadcast_audio(data, sender_addr):
    """
    Receive encrypted audio from a client, decrypt it with sender's session key,
    re-encrypt with each recipient's session key, and broadcast.
    """
    # Strip the message type byte, then decrypt with sender's session key
    encrypted_data = data[1:]
    
    # Find sender's session key
    sender_session_key = None
    with clients_lock:
        if sender_addr in clients:
            sender_session_key = clients[sender_addr].get('session_key')
        elif sender_addr in admins:
            sender_session_key = admins[sender_addr].get('session_key')
    
    if sender_session_key is None:
        return  # Unknown sender, discard
    
    decrypted_data = server_decrypt_with_key(encrypted_data, sender_session_key)
    if decrypted_data is None:
        return  # Decryption failed, discard
    
    with clients_lock:
        client_addrs = list(clients.keys())
        admin_addrs = list(admins.keys())

    # Forward to all clients except the sender
    for addr in client_addrs:
        if addr == sender_addr:
            continue
        try:
            recipient_key = clients[addr].get('session_key')
            if recipient_key:
                re_encrypted_data = server_encrypt_with_key(decrypted_data, recipient_key)
                re_packet = struct.pack('!B', MSG_TYPE_AUDIO) + re_encrypted_data
                sock_client.sendto(re_packet, addr)
        except Exception as e:
            logger.error(f"Send failed to {addr}: {e}")
            with clients_lock:
                if addr in clients:
                    clients.pop(addr)

    # Forward to all admins
    for addr in admin_addrs:
        try:
            recipient_key = admins[addr].get('session_key')
            if recipient_key:
                re_encrypted_data = server_encrypt_with_key(decrypted_data, recipient_key)
                re_packet = struct.pack('!B', MSG_TYPE_AUDIO) + re_encrypted_data
                sock_admin.sendto(re_packet, addr)
        except Exception as e:
            logger.error(f"Send failed to {addr}: {e}")
            with clients_lock:
                if addr in admins:
                    admins.pop(addr)


def handle_user_signal():
    """Handle client signaling: JOIN, HEARTBEAT, LEAVE messages."""
    global sock_client_signal
    sock_client_signal = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_client_signal.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_client_signal.bind((HOST, SIGNAL_PORT))
    logger.info(f"Client signal server started, listening on {HOST}:{SIGNAL_PORT}")
    
    while True:
        try:
            data, addr = sock_client_signal.recvfrom(MAX_PACKET_SIZE)
            
            if len(data) < 2:
                continue

            msg_type = struct.unpack('!B', data[:1])[0]
            
            if msg_type == MSG_TYPE_JOIN:
                try:
                    # Parse JOIN packet: [msg_type(1)][name_len(4)][name][password_len(4)][password][audio_port(2)]
                    offset = 1
                    name_len = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    if name_len == 0 or name_len > 128:
                        logger.warning(f"Invalid username length: {name_len}")
                        continue
                    
                    name = data[offset:offset+name_len].decode('utf-8')
                    offset += name_len
                    
                    # Extract password
                    password_len = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    if password_len == 0 or password_len > 256:
                        logger.warning(f"Invalid password length: {password_len}")
                        continue
                    
                    password = data[offset:offset+password_len].decode('utf-8')
                    offset += password_len
                    
                    # Verify password
                    if password != SERVER_PASSWORD:
                        logger.warning(f"User [{name}] authentication failed from {addr}")
                        # Send auth failure response
                        fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                        sock_client_signal.sendto(fail_packet, addr)
                        continue
                    
                    # Generate session key for this client
                    session_key = get_random_bytes(32)
                    
                    # Extract audio port
                    has_audio_port = len(data) >= offset + 2
                    client_audio_port = None
                    if has_audio_port:
                        client_audio_port = struct.unpack('!H', data[offset:offset+2])[0]
                    
                    client_addr = (addr[0], client_audio_port) if client_audio_port else addr
                    
                    with clients_lock:
                        clients[client_addr] = {
                            'name': name, 
                            'last_heartbeat': time.time(),
                            'session_key': session_key
                        }
                    
                    logger.info(f"User [{name}] joined and authenticated (total: {len(clients)}), audio addr: {client_addr}")
                    
                    # Send auth success with encrypted session key
                    # Encrypt session key using password-derived key
                    salt = hashlib.sha256(password.encode('utf-8')).digest()
                    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
                    nonce = get_random_bytes(12)
                    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                    encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
                    
                    response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + nonce + tag + encrypted_session_key
                    sock_client_signal.sendto(response, addr)
                    
                    broadcast_user_event(MSG_TYPE_USER_JOINED, name)
                    broadcast_user_list()
                except Exception as e:
                    logger.error(f"Error handling user join: {e}")
            
            elif msg_type == MSG_TYPE_HEARTBEAT:
                try:
                    name_len = struct.unpack('!I', data[1:5])[0]
                    if name_len == 0 or name_len > 128:
                        continue
                    
                    name = data[5:5+name_len].decode('utf-8')
                    has_audio_port = len(data) >= 5 + name_len + 2
                    client_audio_port = None
                    if has_audio_port:
                        client_audio_port = struct.unpack('!H', data[5+name_len:7+name_len])[0]
                    
                    client_addr = (addr[0], client_audio_port) if client_audio_port else addr
                    
                    with clients_lock:
                        if client_addr in clients:
                            clients[client_addr]['last_heartbeat'] = time.time()
                        else:
                            clients[client_addr] = {'name': name, 'last_heartbeat': time.time()}
                            logger.info(f"User [{name}] reconnected")
                except Exception:
                    pass
            
            elif msg_type == MSG_TYPE_LEAVE:
                try:
                    name_len = struct.unpack('!I', data[1:5])[0]
                    if name_len == 0 or name_len > 128:
                        continue
                    
                    name = data[5:5+name_len].decode('utf-8')
                    has_audio_port = len(data) >= 5 + name_len + 2
                    client_audio_port = None
                    if has_audio_port:
                        client_audio_port = struct.unpack('!H', data[5+name_len:7+name_len])[0]
                    
                    client_addr = (addr[0], client_audio_port) if client_audio_port else addr
                    
                    with clients_lock:
                        if client_addr in clients:
                            del clients[client_addr]
                            logger.info(f"User [{name}] left (total: {len(clients)})")
                            broadcast_user_event(MSG_TYPE_USER_JOINED, name)
                            broadcast_user_list()
                except Exception:
                    pass
        except Exception:
            pass


def handle_admin_signal():
    """Handle admin signaling: ADMIN_JOIN, HEARTBEAT, LEAVE messages."""
    global sock_admin_signal
    sock_admin_signal = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_admin_signal.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_admin_signal.bind((HOST, ADMIN_SIGNAL_PORT))
    logger.info(f"Admin signal server started, listening on {HOST}:{ADMIN_SIGNAL_PORT}")
    
    while True:
        try:
            data, addr = sock_admin_signal.recvfrom(MAX_PACKET_SIZE)
            
            if len(data) < 2:
                continue

            msg_type = struct.unpack('!B', data[:1])[0]
            
            if msg_type == MSG_TYPE_ADMIN_JOIN:
                try:
                    # Parse ADMIN_JOIN packet: [msg_type(1)][name_len(4)][name][password_len(4)][password][audio_port(2)]
                    offset = 1
                    name_len = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    if name_len == 0 or name_len > 128:
                        logger.warning(f"Invalid admin name length: {name_len}")
                        continue
                    
                    name = data[offset:offset+name_len].decode('utf-8')
                    offset += name_len
                    
                    # Extract password
                    password_len = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    if password_len == 0 or password_len > 256:
                        logger.warning(f"Invalid password length: {password_len}")
                        continue
                    
                    password = data[offset:offset+password_len].decode('utf-8')
                    offset += password_len
                    
                    # Verify password
                    if password != SERVER_PASSWORD:
                        logger.warning(f"Admin [{name}] authentication failed from {addr}")
                        # Send auth failure response
                        fail_packet = struct.pack('!B', MSG_TYPE_AUTH_FAIL)
                        sock_admin_signal.sendto(fail_packet, addr)
                        continue
                    
                    # Generate session key for this admin
                    session_key = get_random_bytes(32)
                    
                    # Extract audio port
                    has_audio_port = len(data) >= offset + 2
                    admin_audio_port = None
                    if has_audio_port:
                        admin_audio_port = struct.unpack('!H', data[offset:offset+2])[0]
                    
                    admin_addr = (addr[0], admin_audio_port) if admin_audio_port else addr
                    
                    with clients_lock:
                        admins[admin_addr] = {
                            'name': name, 
                            'last_heartbeat': time.time(),
                            'session_key': session_key
                        }
                    
                    logger.info(f"Admin [{name}] joined and authenticated (total: {len(admins)}), audio addr: {admin_addr}")
                    
                    # Send auth success with encrypted session key
                    salt = hashlib.sha256(password.encode('utf-8')).digest()
                    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
                    nonce = get_random_bytes(12)
                    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                    encrypted_session_key, tag = cipher.encrypt_and_digest(session_key)
                    
                    response = struct.pack('!B', MSG_TYPE_AUTH_SUCCESS) + nonce + tag + encrypted_session_key
                    sock_admin_signal.sendto(response, addr)
                    
                    broadcast_user_list()
                except Exception as e:
                    logger.error(f"Error handling admin join: {e}")
            
            elif msg_type == MSG_TYPE_HEARTBEAT:
                try:
                    name_len = struct.unpack('!I', data[1:5])[0]
                    if name_len == 0 or name_len > 128:
                        continue
                    
                    name = data[5:5+name_len].decode('utf-8')
                    has_audio_port = len(data) >= 5 + name_len + 2
                    admin_audio_port = None
                    if has_audio_port:
                        admin_audio_port = struct.unpack('!H', data[5+name_len:7+name_len])[0]
                    
                    admin_addr = (addr[0], admin_audio_port) if admin_audio_port else addr
                    
                    with clients_lock:
                        if admin_addr in admins:
                            admins[admin_addr]['last_heartbeat'] = time.time()
                        else:
                            admins[admin_addr] = {'name': name, 'last_heartbeat': time.time()}
                            logger.info(f"Admin [{name}] reconnected")
                except Exception:
                    pass
            
            elif msg_type == MSG_TYPE_LEAVE:
                try:
                    name_len = struct.unpack('!I', data[1:5])[0]
                    if name_len == 0 or name_len > 128:
                        continue
                    
                    name = data[5:5+name_len].decode('utf-8')
                    has_audio_port = len(data) >= 5 + name_len + 2
                    admin_audio_port = None
                    if has_audio_port:
                        admin_audio_port = struct.unpack('!H', data[5+name_len:7+name_len])[0]
                    
                    admin_addr = (addr[0], admin_audio_port) if admin_audio_port else addr
                    
                    with clients_lock:
                        if admin_addr in admins:
                            del admins[admin_addr]
                            logger.info(f"Admin [{name}] left (total: {len(admins)})")
                            broadcast_user_list()
                except Exception:
                    pass
        except Exception:
            pass


def handle_audio_socket(sock_obj, is_admin=False):
    """Handle incoming audio packets and broadcast them."""
    while True:
        try:
            data, addr = sock_obj.recvfrom(MAX_PACKET_SIZE)
            
            if len(data) < 2:
                continue

            msg_type = struct.unpack('!B', data[:1])[0]
            
            if msg_type == MSG_TYPE_AUDIO:
                broadcast_audio(data, addr)
        except Exception:
            pass


def check_heartbeats():
    """Periodically check for timed-out clients and admins, remove them."""
    while True:
        time.sleep(3)
        
        timed_out_clients = []
        with clients_lock:
            for addr, info in list(clients.items()):
                if time.time() - info['last_heartbeat'] > HEARTBEAT_TIMEOUT:
                    timed_out_clients.append((addr, info['name']))
                    del clients[addr]
        
        for addr, name in timed_out_clients:
            logger.info(f"User [{name}] heartbeat timeout, removed (total: {len(clients)})")
            broadcast_user_event(MSG_TYPE_USER_JOINED, name)
            broadcast_user_list()
        
        timed_out_admins = []
        with clients_lock:
            for addr, info in list(admins.items()):
                if time.time() - info['last_heartbeat'] > HEARTBEAT_TIMEOUT:
                    timed_out_admins.append((addr, info['name']))
                    del admins[addr]
        
        for addr, name in timed_out_admins:
            logger.info(f"Admin [{name}] heartbeat timeout, removed (total: {len(admins)})")
            broadcast_user_list()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    
    parser = argparse.ArgumentParser(description="OpenVoiceChat Server")
    parser.add_argument("--host", default=HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=PORT, help="User audio port")
    parser.add_argument("--admin-port", type=int, default=ADMIN_PORT, help="Admin audio port")
    parser.add_argument("--signal-port", type=int, default=SIGNAL_PORT, help="User signal port")
    parser.add_argument("--admin-signal-port", type=int, default=ADMIN_SIGNAL_PORT, help="Admin signal port")
    args = parser.parse_args()
    
    HOST = args.host
    PORT = args.port
    ADMIN_PORT = args.admin_port
    SIGNAL_PORT = args.signal_port
    ADMIN_SIGNAL_PORT = args.admin_signal_port
    
    # Create and bind client audio socket
    sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_client.bind((HOST, PORT))
    sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
    sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
    
    # Create and bind admin audio socket
    sock_admin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_admin.bind((HOST, ADMIN_PORT))
    sock_admin.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
    sock_admin.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
    
    logger.info(f"Signal server started, user on {HOST}:{SIGNAL_PORT}, admin on {HOST}:{ADMIN_SIGNAL_PORT}")
    logger.info(f"Audio server started, user on {HOST}:{PORT}, admin on {HOST}:{ADMIN_PORT}")
    logger.info("Session-based authentication enabled")
    
    # Start all server threads
    t_user_signal = threading.Thread(target=handle_user_signal, daemon=True)
    t_user_signal.start()
    
    t_admin_signal = threading.Thread(target=handle_admin_signal, daemon=True)
    t_admin_signal.start()
    
    t_audio_user = threading.Thread(target=handle_audio_socket, args=(sock_client, False), daemon=True)
    t_audio_user.start()
    
    t_audio_admin = threading.Thread(target=handle_audio_socket, args=(sock_admin, True), daemon=True)
    t_audio_admin.start()
    
    t_heartbeat = threading.Thread(target=check_heartbeats, daemon=True)
    t_heartbeat.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        sock_client.close()
        sock_admin.close()