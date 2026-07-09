import socket
import threading
import struct
import sys
import logging
import time
import os
import hashlib
import getpass
import zlib
import argparse
import yaml
import ctypes
import ctypes.wintypes

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

try:
    import pyaudio
except ImportError:
    print("错误: 请先安装 pyaudio: pip install pyaudio")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("错误: 请先安装 pycryptodome: pip install pycryptodome")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

logger = logging.getLogger(__name__)

FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
CHUNK = 512

MSG_TYPE_JOIN = 1
MSG_TYPE_AUDIO = 2
MSG_TYPE_ADMIN_JOIN = 4
MSG_TYPE_USER_LIST = 5
MSG_TYPE_USER_JOINED = 6
MSG_TYPE_HEARTBEAT = 7
MSG_TYPE_LEAVE = 8
MSG_TYPE_AUTH_SUCCESS = 9
MSG_TYPE_AUTH_FAIL = 10

JITTER_BUFFER_SIZE = 3
MAX_PACKET_SIZE = 65536


class AudioEncryptor:
    """AES-256-GCM encryptor/decryptor for audio data."""
    def __init__(self, password: str):
        salt = hashlib.sha256(password.encode('utf-8')).digest()
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
        self.key = key
        logger.info("AES-256-GCM encryption initialized")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data: returns nonce(12) + tag(16) + ciphertext."""
        nonce = get_random_bytes(12)
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


class SessionKeyEncryptor:
    """AES-256-GCM encryptor/decryptor using a session key."""
    def __init__(self, session_key: bytes):
        self.key = session_key
        logger.info("Session key encryption initialized")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data: returns nonce(12) + tag(16) + ciphertext."""
        nonce = get_random_bytes(12)
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
    def __init__(self, size=JITTER_BUFFER_SIZE):
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
                return b'\x00' * (CHUNK * 2)


class AudioPlayer:
    """Audio playback with jitter buffer and volume control."""
    def __init__(self, p, volume=1.0, output_device=None):
        kwargs = {
            'format': FORMAT,
            'channels': CHANNELS,
            'rate': RATE,
            'output': True,
            'frames_per_buffer': CHUNK
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
                    import array
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


def send_heartbeat(sock, server_addr, name, is_admin=False):
    """Continuously send heartbeat packets to keep the connection alive."""
    heartbeat_interval = 3
    msg_type = MSG_TYPE_ADMIN_JOIN if is_admin else MSG_TYPE_JOIN
    while True:
        try:
            name_bytes = name.encode('utf-8')
            heartbeat_packet = struct.pack('!BI', msg_type, len(name_bytes)) + name_bytes + b'\x01'
            sock.sendto(heartbeat_packet, server_addr)
            time.sleep(heartbeat_interval)
        except Exception:
            time.sleep(heartbeat_interval)


def receive_audio(sock, player: AudioPlayer, encryptor: SessionKeyEncryptor, compressor: AudioCompressor):
    """Receive encrypted audio from server via TCP, decrypt, decompress, and play."""
    logger.info("Starting to receive audio (monitoring mode)...")
    packet_count = 0
    buffer = b''
    
    while True:
        try:
            data = sock.recv(MAX_PACKET_SIZE)
            if not data:
                logger.warning("Server disconnected")
                break
            
            buffer += data
            
            while len(buffer) >= 1:
                msg_type = struct.unpack('!B', buffer[:1])[0]
                
                if msg_type == MSG_TYPE_AUDIO:
                    # Format: [msg_type(1)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                    if len(buffer) < 13:  # 1 + 8 + 4
                        break
                    
                    timestamp = struct.unpack('!d', buffer[1:9])[0]
                    encrypted_len = struct.unpack('!I', buffer[9:13])[0]
                    
                    if len(buffer) < 13 + encrypted_len:
                        break
                    
                    encrypted_data = buffer[13:13+encrypted_len]
                    buffer = buffer[13+encrypted_len:]
                    
                    packet_count += 1
                    if packet_count <= 3:
                        logger.info(f"收到第 {packet_count} 个音频包，大小: {len(encrypted_data)}")
                    
                    compressed_data = encryptor.decrypt(encrypted_data)
                    if compressed_data is None:
                        if packet_count <= 3:
                            logger.warning("警告: 解密失败")
                        continue
                    if packet_count <= 3:
                        logger.info(f"解密成功，压缩数据大小: {len(compressed_data)}")
                    if compressed_data and compressor:
                        pcm_data = compressor.decompress(compressed_data)
                        if packet_count <= 3:
                            logger.info(f"解压成功，PCM数据大小: {len(pcm_data)}")
                        if player:
                            player.push(pcm_data)
                elif msg_type == MSG_TYPE_USER_LIST:
                    if len(buffer) < 2:
                        break
                    user_list = buffer[1:].decode('utf-8')
                    buffer = b''
                    print(f"\n[Online Users] {user_list}\n")
                elif msg_type == MSG_TYPE_USER_JOINED:
                    if len(buffer) < 2:
                        break
                    event = buffer[1:].decode('utf-8')
                    buffer = b''
                    print(f"\n[User Joined] {event}\n")
                else:
                    buffer = buffer[1:]
        except ConnectionResetError:
            logger.warning("Connection reset by server")
            break
        except Exception as e:
            logger.error(f"Error receiving audio: {e}")
            time.sleep(0.1)


class AdminGUI:
    """Main GUI class for the voice chat admin."""
    def __init__(self, root):
        self.root = root
        self.root.title("Voice Chat Admin (Monitoring Mode)")
        self.root.resizable(True, True)
        
        # Automatically set window size to 1/5 width and 1/2 height of screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = screen_width // 5
        window_height = screen_height // 2
        self.root.geometry(f"{window_width}x{window_height}")
        
        self.connected = False
        self.running = False
        
        self.sock_audio = None
        self.sock_signal = None
        self.player = None
        self.p = None
        self.encryptor = None
        self.compressor = None
        self.audio_encryptor = None  # Session key based encryptor
        self.session_key = None
        self.server_addr = None
        self.signal_addr = None
        self.name = None
        
        # Config file path (same directory as executable)
        if getattr(sys, 'frozen', False):
            # Packaged executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Development environment
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(base_dir, 'config_admin.yaml')
        self._load_config()
        
        self._setup_ui()
        
    def _load_config(self):
        """Load configuration from YAML file."""
        self.config = {
            'host': '127.0.0.1',
            'port': 9091,
            'name': '',
            'volume': 1.0,
            'password_encrypted': None
        }
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = yaml.safe_load(f)
                    if saved_config:
                        self.config.update(saved_config)
        except Exception as e:
            logger.warning(f"Failed to load config file: {e}")
            
    def _save_config(self):
        """Save configuration to YAML file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False)
        except Exception as e:
            logger.warning(f"Failed to save config file: {e}")
            
    def _encrypt_password(self, password: str) -> str:
        """Encrypt password using Windows DPAPI."""
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
        
    def _decrypt_password(self, encrypted_hex: str) -> str:
        """Decrypt password using Windows DPAPI."""
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
        
    def _setup_ui(self):
        """Initialize and layout all GUI components."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="连接配置", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="服务器:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.host_var = tk.StringVar(value=self.config.get('host', '127.0.0.1'))
        ttk.Entry(config_frame, textvariable=self.host_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="端口:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.StringVar(value=str(self.config.get('port', 9091)))
        ttk.Entry(config_frame, textvariable=self.port_var, width=10).grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(config_frame, text="昵称:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.name_var = tk.StringVar(value=self.config.get('name', ''))
        ttk.Entry(config_frame, textvariable=self.name_var, width=20).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="密码:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.password_var, show="*", width=10).grid(row=1, column=3, padx=5, pady=5)
        
        self.remember_password_var = tk.BooleanVar(value=False)
        self.remember_password_check = ttk.Checkbutton(config_frame, text="记住密码", variable=self.remember_password_var)
        self.remember_password_check.grid(row=1, column=4, padx=5, pady=5)
        
        # Show masked password if saved
        if self.config.get('password_encrypted'):
            self.password_var.set("••••••••")
            self.remember_password_var.set(True)
        
        ttk.Label(config_frame, text="音量:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.volume_var = tk.DoubleVar(value=self.config.get('volume', 1.0))
        ttk.Scale(config_frame, from_=0.0, to=2.0, variable=self.volume_var, orient=tk.HORIZONTAL).grid(row=2, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
        self.volume_label = ttk.Label(config_frame, text=f"{self.config.get('volume', 1.0):.1f}")
        self.volume_label.grid(row=2, column=3, padx=5, pady=5)
        self.volume_var.trace('w', self._update_volume_label)
        self.volume_var.trace('w', self._apply_volume)
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.connect_btn = ttk.Button(control_frame, text="连接", command=self._toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(status_frame, text="状态:").pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar(value="未连接")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Online users frame
        users_frame = ttk.LabelFrame(main_frame, text="在线用户", padding="10")
        users_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.users_text = scrolledtext.ScrolledText(users_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.users_text.pack(fill=tk.BOTH, expand=True)
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def _update_volume_label(self, *args):
        """Update volume display label."""
        self.volume_label.config(text=f"{self.volume_var.get():.1f}")
        
    def _apply_volume(self, *args):
        """Apply volume setting to audio player."""
        if hasattr(self, 'player') and self.player:
            self.player.volume = self.volume_var.get()
        self.config['volume'] = self.volume_var.get()
        self._save_config()
        
    def _recv_exact(self, size):
        """Receive exactly size bytes from TCP socket."""
        data = b''
        while len(data) < size:
            try:
                chunk = self.sock_audio.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data
        
    def _log(self, message):
        """Append a message to the log display. Thread-safe."""
        if self.root and self.root.winfo_exists():
            self.root.after(0, self._log_impl, message)
    
    def _log_impl(self, message):
        """Internal log implementation, must be called from main thread."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def _update_users(self, message):
        """Update the online users list display."""
        self.users_text.config(state=tk.NORMAL)
        self.users_text.delete(1.0, tk.END)
        self.users_text.insert(tk.END, f"{message}\n")
        self.users_text.config(state=tk.DISABLED)
        
    def _toggle_connection(self):
        """Toggle between connect and disconnect."""
        if not self.connected:
            self._connect()
        else:
            self._disconnect()
            
    def _connect(self):
        """Validate inputs and initiate connection."""
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        name = self.name_var.get().strip()
        password = self.password_var.get().strip()
        volume = self.volume_var.get()
        
        if not host:
            messagebox.showerror("错误", "服务器地址不能为空")
            return
            
        if not port_str.isdigit():
            messagebox.showerror("错误", "端口必须是数字")
            return
            
        port = int(port_str)
        
        if not name:
            messagebox.showerror("错误", "昵称不能为空")
            return
            
        # Handle password
        if password == "••••••••" and self.config.get('password_encrypted'):
            # Use saved encrypted password
            password = self._decrypt_password(self.config['password_encrypted'])
            if not password:
                messagebox.showerror("错误", "无法解密保存的密码，请重新输入")
                return
        elif not password:
            messagebox.showerror("错误", "密码不能为空")
            return
            
        # Save configuration
        self.config['host'] = host
        self.config['port'] = port
        self.config['name'] = name
        self.config['volume'] = volume
        
        # Handle password saving
        if self.remember_password_var.get():
            self.config['password_encrypted'] = self._encrypt_password(password)
        else:
            self.config['password_encrypted'] = None
            
        self._save_config()
        
        self.name = name
        
        self.connect_btn.config(state=tk.DISABLED)
        self.status_var.set("正在连接...")
        
        thread = threading.Thread(target=self._connect_thread, args=(host, port, name, password, volume), daemon=True)
        thread.start()
        
    def _connect_thread(self, host, port, name, password, volume):
        """Background thread to establish connection to server."""
        try:
            self.compressor = AudioCompressor(level=6)
            
            self.sock_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_audio.settimeout(10)
            self.sock_audio.connect((host, port))
            self.sock_audio.settimeout(None)
            
            name_bytes = name.encode('utf-8')
            password_bytes = password.encode('utf-8')
            join_packet = (
                struct.pack('!BI', MSG_TYPE_ADMIN_JOIN, len(name_bytes)) + name_bytes +
                struct.pack('!I', len(password_bytes)) + password_bytes
            )
            self.sock_audio.sendall(join_packet)
            
            response_data = self._recv_exact(61)
            if not response_data or len(response_data) < 1:
                self.root.after(0, self._connect_failed, "服务器响应格式错误")
                return
            
            response_type = struct.unpack('!B', response_data[:1])[0]
            
            if response_type == MSG_TYPE_AUTH_FAIL:
                self.root.after(0, self._connect_failed, "密码错误，身份验证失败")
                return
            elif response_type == MSG_TYPE_AUTH_SUCCESS:
                if len(response_data) < 61:
                    self.root.after(0, self._connect_failed, "服务器响应格式错误")
                    return
                
                nonce = response_data[1:13]
                tag = response_data[13:29]
                encrypted_session_key = response_data[29:61]
                
                salt = hashlib.sha256(password.encode('utf-8')).digest()
                derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
                cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                self.session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
                
                self.audio_encryptor = SessionKeyEncryptor(self.session_key)
                
                connected = True
            else:
                self.root.after(0, self._connect_failed, "未知的服务器响应")
                return
                
            self.p = pyaudio.PyAudio()
            self.player = AudioPlayer(self.p, volume=volume)
            
            self.running = True
            self.connected = True
            
            receive_thread = threading.Thread(target=self._receive_audio, daemon=True)
            receive_thread.start()
            
            self.root.after(0, self._connect_success, name)
            
        except Exception as e:
            self.root.after(0, self._connect_failed, f"连接出错: {e}")
            
    def _connect_success(self, name):
        """Update UI after successful connection."""
        self.connected = True
        self.connect_btn.config(text="断开")
        self.connect_btn.config(state=tk.NORMAL)
        self.status_var.set(f"已连接 ({name})")
        self.status_label.config(foreground="green")
        self._log(f"已以管理员身份加入服务器，昵称: {name}")
        self._log("您可以监听所有用户的语音，但无法说话。")
        
    def _connect_failed(self, message):
        """Update UI after connection failure."""
        self.connected = False
        self.connect_btn.config(text="连接")
        self.connect_btn.config(state=tk.NORMAL)
        self.status_var.set("连接失败")
        self.status_label.config(foreground="red")
        self._log(message)
        self._cleanup()
        
    def _disconnect(self):
        """Disconnect from server and clean up resources."""
        self.running = False
        self.connected = False
        
        # Send LEAVE message
        try:
            if self.name and self.sock_audio:
                name_bytes = self.name.encode('utf-8')
                leave_packet = struct.pack('!BI', MSG_TYPE_LEAVE, len(name_bytes)) + name_bytes
                self.sock_audio.sendall(leave_packet)
                import time
                time.sleep(0.3)
        except Exception:
            pass
        
        self.connect_btn.config(text="连接")
        self.status_var.set("已断开")
        self.status_label.config(foreground="red")
        self._log("已断开连接")
        self._cleanup()
        
    def _cleanup(self):
        """Clean up all network and audio resources."""
        if self.player:
            self.player.stop()
            self.player = None
        if self.sock_audio:
            self.sock_audio.close()
            self.sock_audio = None
        if self.p:
            self.p.terminate()
            self.p = None
        
        # Clear audio encryptor for next connection
        self.audio_encryptor = None
            
    def _receive_audio(self):
        """Receive and process incoming audio from server via TCP."""
        self._log("开始接收音频（监听模式）...")
        packet_count = 0
        buffer = b''
        
        while self.running:
            try:
                data = self.sock_audio.recv(MAX_PACKET_SIZE)
                if not data:
                    self._log("服务器断开连接")
                    break
                
                buffer += data
                
                while len(buffer) >= 1:
                    msg_type = struct.unpack('!B', buffer[:1])[0]
                    
                    if msg_type == MSG_TYPE_AUDIO:
                        # Format: [msg_type(1)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                        if len(buffer) < 13:
                            break
                        
                        timestamp = struct.unpack('!d', buffer[1:9])[0]
                        encrypted_len = struct.unpack('!I', buffer[9:13])[0]
                        
                        if len(buffer) < 13 + encrypted_len:
                            break
                        
                        encrypted_data = buffer[13:13+encrypted_len]
                        buffer = buffer[13+encrypted_len:]
                        
                        packet_count += 1
                        if packet_count <= 3:
                            self._log(f"收到第 {packet_count} 个音频包，大小: {len(encrypted_data)}")
                        
                        if not self.audio_encryptor:
                            if packet_count <= 3:
                                self._log("警告: audio_encryptor 未初始化")
                            continue
                        compressed_data = self.audio_encryptor.decrypt(encrypted_data)
                        if compressed_data is None:
                            if packet_count <= 3:
                                self._log("警告: 解密失败")
                            continue
                        if packet_count <= 3:
                            self._log(f"解密成功，压缩数据大小: {len(compressed_data)}")
                        if compressed_data and self.compressor:
                            pcm_data = self.compressor.decompress(compressed_data)
                            if packet_count <= 3:
                                self._log(f"解压成功，PCM数据大小: {len(pcm_data)}")
                            if self.player:
                                self.player.push(pcm_data)
                    elif msg_type == MSG_TYPE_USER_LIST:
                        user_list = buffer[1:].decode('utf-8')
                        buffer = b''
                        self.root.after(0, self._update_users, user_list)
                    elif msg_type == MSG_TYPE_USER_JOINED:
                        event = buffer[1:].decode('utf-8')
                        buffer = b''
                        self.root.after(0, self._log, f"[用户事件] {event}")
                    else:
                        buffer = buffer[1:]
            except ConnectionResetError:
                self._log("连接被服务器重置")
                break
            except Exception as e:
                if self.running:
                    self._log(f"接收音频出错: {e}")
                time.sleep(0.1)
                
    def on_closing(self):
        """Handle window close event."""
        if self.connected:
            self._disconnect()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description='语音聊天管理员（监听模式）')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='服务器地址')
    parser.add_argument('--admin-port', type=int, default=9091, help='管理员端口')
    parser.add_argument('--name', type=str, default=None, help='管理员昵称')
    parser.add_argument('--password', type=str, default=None, help='加密密码')
    parser.add_argument('--volume', type=float, default=1.0, help='播放音量 0.0-2.0 (默认: 1.0)')
    parser.add_argument('--rate', type=int, default=16000, help='音频采样率 (默认: 16000)')
    parser.add_argument('--chunk', type=int, default=512, help='音频块大小 (默认: 512)')
    parser.add_argument('--channels', type=int, default=1, help='音频声道数 (默认: 1)')
    parser.add_argument('--compress-level', type=int, default=6, help='zlib压缩级别 1-9 (默认: 6)')
    parser.add_argument('--jitter-buffer', type=int, default=3, help='抖动缓冲区大小 (默认: 3)')
    parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='日志级别')
    parser.add_argument('--quiet', action='store_true', help='静默模式，不显示任何日志')
    parser.add_argument('--output-device', type=int, default=None, help='音频输出设备索引')
    parser.add_argument('--list-devices', action='store_true', help='列出所有音频设备')
    parser.add_argument('--nogui', action='store_true', help='启动命令行界面（默认启动图形界面）')
    args = parser.parse_args()

    if not args.nogui:
        if not HAS_GUI:
            print("错误: 未安装 tkinter，无法启动图形界面，请使用 --nogui 参数启动命令行版本")
            return
        
        # 设置 DPI 感知，解决高分辨率屏幕下的模糊问题
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass
        
        root = tk.Tk()
        app = AdminGUI(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
        return

    if args.list_devices:
        p = pyaudio.PyAudio()
        info = p.get_host_api_info_by_index(0)
        num_devices = info.get('deviceCount')
        print("可用音频设备:")
        for i in range(num_devices):
            device_info = p.get_device_info_by_host_api_device_index(0, i)
            print(f"  [{i}] {device_info.get('name')} (输出通道: {device_info.get('maxOutputChannels')})")
        p.terminate()
        return

    if args.quiet:
        logging.disable(logging.CRITICAL)
    else:
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format='%(asctime)s [%(levelname)s] %(message)s'
        )

    global RATE, CHUNK, CHANNELS, JITTER_BUFFER_SIZE
    RATE = args.rate
    CHUNK = args.chunk
    CHANNELS = args.channels
    JITTER_BUFFER_SIZE = args.jitter_buffer

    host = args.host
    port = args.admin_port

    if args.name:
        name = args.name
    else:
        name = input("管理员昵称: ").strip()
        if not name:
            name = "管理员"

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("加密密码: ").strip()
    
    if not password:
        logger.error("密码不能为空")
        return
    
    encryptor = AudioEncryptor(password)
    compressor = AudioCompressor(level=args.compress_level)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    logger.info(f"正在连接服务器 {host}:{port}...")
    
    try:
        sock.settimeout(10)
        sock.connect((host, port))
        sock.settimeout(None)
    except Exception as e:
        logger.error(f"无法连接到服务器 {host}:{port}: {e}")
        sock.close()
        return
    
    name_bytes = name.encode('utf-8')
    password_bytes = password.encode('utf-8')
    join_packet = (
        struct.pack('!BI', MSG_TYPE_ADMIN_JOIN, len(name_bytes)) + name_bytes +
        struct.pack('!I', len(password_bytes)) + password_bytes
    )
    sock.sendall(join_packet)
    
    response_data = b''
    while len(response_data) < 61:
        chunk = sock.recv(61 - len(response_data))
        if not chunk:
            logger.error("服务器响应不完整")
            sock.close()
            return
        response_data += chunk
    
    if len(response_data) < 1:
        logger.error("服务器响应格式错误")
        sock.close()
        return
    
    response_type = struct.unpack('!B', response_data[:1])[0]
    
    if response_type == MSG_TYPE_AUTH_FAIL:
        logger.error("密码错误，身份验证失败")
        sock.close()
        return
    elif response_type != MSG_TYPE_AUTH_SUCCESS:
        logger.error("未知的服务器响应")
        sock.close()
        return
    
    nonce = response_data[1:13]
    tag = response_data[13:29]
    encrypted_session_key = response_data[29:61]
    
    salt = hashlib.sha256(password.encode('utf-8')).digest()
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
    
    audio_encryptor = SessionKeyEncryptor(session_key)
    
    logger.info(f"已以管理员身份加入服务器，昵称: {name}")
        
    print("=" * 50)
    print("管理员监听模式已连接！")
    print("您可以监听所有用户的语音，但无法说话。")
    print("按 Ctrl+C 退出。")
    print("=" * 50)

    p = pyaudio.PyAudio()

    player = AudioPlayer(p, volume=args.volume, output_device=args.output_device)

    receive_thread = threading.Thread(target=receive_audio, args=(sock, player, audio_encryptor, compressor), daemon=True)
    receive_thread.start()

    try:
        while receive_thread.is_alive():
            receive_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n正在断开连接...")
        try:
            name_bytes = name.encode('utf-8')
            leave_packet = struct.pack('!BI', MSG_TYPE_LEAVE, len(name_bytes)) + name_bytes
            sock.sendall(leave_packet)
        except Exception:
            pass
    finally:
        player.stop()
        sock.close()
        p.terminate()
        logger.info("已断开连接")


if __name__ == '__main__':
    main()