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

# Windows DPAPI structure for password encryption
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

# Audio configuration
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
CHUNK = 512

# Message type constants
MSG_TYPE_JOIN = 1
MSG_TYPE_AUDIO = 2
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
    def __init__(self, p, output_device=None):
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
        self.jitter_buffer = JitterBuffer()
        self.running = True
        self.volume = 1.0
        self.play_thread = threading.Thread(target=self._play_loop, daemon=True)
        self.play_thread.start()

    def _apply_volume(self, data: bytes) -> bytes:
        """Apply volume gain to audio samples."""
        if self.volume == 1.0:
            return data
        import array
        samples = array.array('h', data)
        samples = [int(s * self.volume) for s in samples]
        # Clamp to 16-bit range
        samples = [max(-32768, min(32767, s)) for s in samples]
        return array.array('h', samples).tobytes()

    def _play_loop(self):
        while self.running:
            data = self.jitter_buffer.pop()
            if data:
                data = self._apply_volume(data)
                self.stream.write(data)
            else:
                time.sleep(0.001)

    def push(self, data):
        self.jitter_buffer.push(data)

    def stop(self):
        self.running = False
        if self.play_thread.is_alive():
            self.play_thread.join(timeout=1.0)
        self.stream.stop_stream()
        self.stream.close()


def send_audio(sock, p, listen_own: bool, player: AudioPlayer, encryptor: SessionKeyEncryptor, compressor: AudioCompressor, mute: bool = False, input_device=None, gain: float = 1.0):
    """Capture microphone audio, apply gain/mute, compress, encrypt, and send to server via TCP."""
    kwargs = {
        'format': FORMAT,
        'channels': CHANNELS,
        'rate': RATE,
        'input': True,
        'frames_per_buffer': CHUNK
    }
    if input_device is not None:
        kwargs['input_device_index'] = input_device
    stream = p.open(**kwargs)
    logger.info(f"Microphone opened, sending audio... (muted: {'yes' if mute else 'no'}, gain: {gain:.1f})")
    
    packet_count = 0
    try:
        while True:
            data = stream.read(CHUNK, exception_on_overflow=False)
            try:
                original_data = data
                if mute:
                    import array
                    samples = array.array('h', data)
                    samples = [0] * len(samples)
                    data = samples.tobytes()
                elif gain != 1.0:
                    import array
                    samples = array.array('h', data)
                    samples = array.array('h', [int(s * gain) for s in samples])
                    samples = array.array('h', [max(-32768, min(32767, s)) for s in samples])
                    data = samples.tobytes()
                compressed_data = compressor.compress(data)
                encrypted_data = encryptor.encrypt(compressed_data)
                timestamp = time.time()
                header = struct.pack('!B', MSG_TYPE_AUDIO) + struct.pack('!d', timestamp) + struct.pack('!I', len(encrypted_data))
                packet = header + encrypted_data
                sock.sendall(packet)
                
                packet_count += 1
                if packet_count % 10 == 0:
                    logger.debug(f"[Send] Sent #{packet_count}, size: {len(packet)} bytes")
                
                if listen_own and player:
                    player.push(original_data)
            except Exception as e:
                logger.error(f"Failed to send audio: {e}")
                time.sleep(0.01)
    except Exception as e:
        logger.error(f"Error reading audio data: {e}")
    finally:
        stream.stop_stream()
        stream.close()


def send_heartbeat(sock, server_addr, name):
    """Continuously send heartbeat packets to keep the connection alive."""
    heartbeat_interval = 3
    while True:
        try:
            name_bytes = name.encode('utf-8')
            heartbeat_packet = struct.pack('!BI', MSG_TYPE_JOIN, len(name_bytes)) + name_bytes + b'\x01'
            sock.sendto(heartbeat_packet, server_addr)
            time.sleep(heartbeat_interval)
        except Exception:
            time.sleep(heartbeat_interval)


def receive_audio(sock, player: AudioPlayer, encryptor: SessionKeyEncryptor, compressor: AudioCompressor):
    """Receive encrypted audio from server via TCP, decrypt, decompress, and play."""
    logger.info("Starting to receive audio...")
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
                    if packet_count % 10 == 0:
                        logger.debug(f"Received packet #{packet_count}, size: {len(encrypted_data)} bytes")
                    
                    compressed_data = encryptor.decrypt(encrypted_data)
                    if compressed_data:
                        pcm_data = compressor.decompress(compressed_data)
                        if packet_count % 10 == 0:
                            logger.debug(f"Decryption OK, compressed: {len(compressed_data)} bytes, PCM: {len(pcm_data)} bytes")
                        player.push(pcm_data)
                    else:
                        if packet_count % 10 == 0:
                            logger.debug("Decryption failed, skipping")
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


class VoiceChatGUI:
    """Main GUI class for the voice chat client."""
    def __init__(self, root):
        self.root = root
        self.root.title("Voice Chat Client")
        self.root.resizable(True, True)
        
        # Automatically set window size to 1/5 width and 1/2 height of screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = screen_width // 5
        window_height = screen_height // 2
        self.root.geometry(f"{window_width}x{window_height}")
        
        self.connected = False
        self.running = False
        self.mute = False
        self.listen_own = False
        
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
        
        # Threading protection
        self._connect_lock = False  # Prevent multiple simultaneous connections
        self._listen_btn_lock = False  # Prevent rapid listen button clicks
        self._active_threads = []  # Track active threads for cleanup
        
        # Local listening related
        self.local_listen_stream = None
        self.local_listen_player = None
        self.local_listen_running = False
        self.local_p = None
        self.local_listen_lock = threading.Lock()  # Protect local listen operations from race conditions
        
        # Config file path (same directory as executable)
        if getattr(sys, 'frozen', False):
            # Packaged executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Development environment
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(base_dir, 'config.yaml')
        self._load_config()
        
        self._setup_ui()
        
    def _load_config(self):
        """Load configuration from YAML file."""
        self.config = {
            'host': '127.0.0.1',
            'port': 9090,
            'name': '',
            'mute_on_connect': False,
            'mute': False,
            'listen_own': False,
            'password_encrypted': None,
            'volume': 1.0,
            'gain': 1.0
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
        self.port_var = tk.StringVar(value=str(self.config.get('port', 9090)))
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
        
        self.listen_own = self.config.get('listen_own', False)
        
        # Load independent mute state (not affected by mute_on_connect)
        self.mute = self.config.get('mute', False)
        self.mute_var = tk.BooleanVar(value=self.config.get('mute_on_connect', False))
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.connect_btn = ttk.Button(control_frame, text="连接", command=self._toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        if self.listen_own:
            self.listen_own_btn = ttk.Button(control_frame, text="关闭监听", command=self._toggle_listen_own)
        else:
            self.listen_own_btn = ttk.Button(control_frame, text="监听自己", command=self._toggle_listen_own)
        self.listen_own_btn.pack(side=tk.LEFT, padx=5)
        
        if self.mute:
            self.mute_btn = ttk.Button(control_frame, text="取消静音", command=self._toggle_mute)
        else:
            self.mute_btn = ttk.Button(control_frame, text="静音", command=self._toggle_mute)
        self.mute_btn.pack(side=tk.LEFT, padx=5)
        
        # Start local listen if configured
        if self.listen_own:
            self._start_local_listen()
        
        self.mute_check = ttk.Checkbutton(config_frame, text="连接时静音", variable=self.mute_var, command=self._on_mute_var_change)
        self.mute_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(config_frame, text="收听音量:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.volume_var = tk.DoubleVar(value=self.config.get('volume', 1.0))
        ttk.Scale(config_frame, from_=0.0, to=2.0, variable=self.volume_var, orient=tk.HORIZONTAL).grid(row=3, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        self.volume_label = ttk.Label(config_frame, text=f"{self.config.get('volume', 1.0):.1f}")
        self.volume_label.grid(row=3, column=2, padx=5, pady=5)
        self.volume_var.trace('w', self._update_volume_label)
        self.volume_var.trace('w', self._apply_volume)
        
        ttk.Label(config_frame, text="麦克风增益:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.gain_var = tk.DoubleVar(value=self.config.get('gain', 1.0))
        ttk.Scale(config_frame, from_=0.0, to=2.0, variable=self.gain_var, orient=tk.HORIZONTAL).grid(row=4, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        self.gain_label = ttk.Label(config_frame, text=f"{self.config.get('gain', 1.0):.1f}")
        self.gain_label.grid(row=4, column=2, padx=5, pady=5)
        self.gain_var.trace('w', self._update_gain_label)
        self.gain_var.trace('w', self._apply_gain)
        
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
        
        if message.startswith("Users: "):
            users_str = message[7:]
            users = [u.strip() for u in users_str.split(",") if u.strip()]
            if users:
                for user in users:
                    self.users_text.insert(tk.END, f"  {user}\n")
            else:
                self.users_text.insert(tk.END, "  (暂无用户在线)\n")
        else:
            self.users_text.insert(tk.END, f"{message}\n")
        
        self.users_text.config(state=tk.DISABLED)
        
    def _toggle_connection(self):
        """Toggle between connect and disconnect with thread protection."""
        # Use button state to prevent rapid clicking
        if self.connect_btn.cget('state') == tk.DISABLED:
            return
            
        if not self.connected:
            self._connect()
        else:
            self._disconnect()
            
    def _connect(self):
        """Validate inputs and initiate connection."""
        # Disable button immediately to prevent rapid clicking
        self.connect_btn.config(state=tk.DISABLED)
        
        try:
            host = self.host_var.get().strip()
            port_str = self.port_var.get().strip()
            name = self.name_var.get().strip()
            password = self.password_var.get().strip()
            
            if not host:
                messagebox.showerror("错误", "服务器地址不能为空")
                self.connect_btn.config(state=tk.NORMAL)
                return
                
            if not port_str.isdigit():
                messagebox.showerror("错误", "端口必须是数字")
                self.connect_btn.config(state=tk.NORMAL)
                return
                
            port = int(port_str)
            
            if not name:
                messagebox.showerror("错误", "昵称不能为空")
                self.connect_btn.config(state=tk.NORMAL)
                return
                
            # Handle password
            if password == "••••••••" and self.config.get('password_encrypted'):
                # Use saved encrypted password
                password = self._decrypt_password(self.config['password_encrypted'])
                if not password:
                    messagebox.showerror("错误", "无法解密保存的密码，请重新输入")
                    self.connect_btn.config(state=tk.NORMAL)
                    return
            elif not password:
                messagebox.showerror("错误", "密码不能为空")
                self.connect_btn.config(state=tk.NORMAL)
                return
                
            # Save configuration
            self.config['host'] = host
            self.config['port'] = port
            self.config['name'] = name
            self.config['mute_on_connect'] = self.mute_var.get()
            
            # Handle password saving
            if self.remember_password_var.get():
                self.config['password_encrypted'] = self._encrypt_password(password)
            else:
                self.config['password_encrypted'] = None
                
            self._save_config()
            
            # Apply mute on connect preference: only override if enabled
            if self.mute_var.get():
                self.mute = True
            # If mute_on_connect is False, keep the current mute state
            
            self.name = name
            
            self.status_var.set("正在连接...")
            
            thread = threading.Thread(target=self._connect_thread, args=(host, port, name, password), daemon=True)
            thread.start()
        except Exception:
            self.connect_btn.config(state=tk.NORMAL)
            raise
        
    def _connect_thread(self, host, port, name, password):
        """Background thread to establish connection to server."""
        try:
            # Ensure old connection is fully cleaned up
            self.running = False
            self.connected = False
            
            # Wait for old threads to stop (with timeout)
            import time
            for t in self._active_threads:
                if t.is_alive():
                    t.join(timeout=1.0)
            self._active_threads.clear()
            
            # Clean up old resources
            self._cleanup()
            
            # Wait for socket to fully close
            time.sleep(0.2)
            
            self.compressor = AudioCompressor(level=6)
            
            self.sock_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_audio.settimeout(10)
            self.root.after(0, self._log, f"正在连接 {host}:{port}...")
            self.sock_audio.connect((host, port))
            self.sock_audio.settimeout(None)
            
            name_bytes = name.encode('utf-8')
            password_bytes = password.encode('utf-8')
            join_packet = (
                struct.pack('!BI', MSG_TYPE_JOIN, len(name_bytes)) + name_bytes +
                struct.pack('!I', len(password_bytes)) + password_bytes
            )
            self.root.after(0, self._log, f"发送加入请求，包大小: {len(join_packet)} 字节")
            self.sock_audio.sendall(join_packet)
            
            self.root.after(0, self._log, "等待服务器响应...")
            response_data = self._recv_exact(61)
            if not response_data or len(response_data) < 1:
                raise Exception("服务器响应格式错误")
            
            response_type = struct.unpack('!B', response_data[:1])[0]
            self.root.after(0, self._log, f"收到响应类型: {response_type}")
            
            if response_type == MSG_TYPE_AUTH_FAIL:
                raise Exception("密码错误，身份验证失败")
            elif response_type == MSG_TYPE_AUTH_SUCCESS:
                if len(response_data) < 61:
                    raise Exception("服务器响应格式错误")
                
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
                raise Exception("未知的服务器响应")
                
            self.p = pyaudio.PyAudio()
            self.player = AudioPlayer(self.p)
            
            self.running = True
            self.connected = True
            
            send_thread = threading.Thread(target=self._send_audio, daemon=True)
            send_thread.start()
            self._active_threads.append(send_thread)
            
            receive_thread = threading.Thread(target=self._receive_audio, daemon=True)
            receive_thread.start()
            self._active_threads.append(receive_thread)
            
            self.root.after(0, self._connect_success, name)
            
        except Exception as e:
            self.root.after(0, self._connect_failed, str(e))
            
    def _connect_success(self, name):
        """Update UI after successful connection."""
        self.connected = True
        self.connect_btn.config(text="断开")
        self.connect_btn.config(state=tk.NORMAL)
        self.mute_btn.config(state=tk.NORMAL)
        self.listen_own_btn.config(state=tk.NORMAL)
        self.mute_check.config(state=tk.DISABLED)
        self.player.volume = self.volume_var.get()
        self.status_var.set(f"已连接 ({name})")
        self.status_label.config(foreground="green")
        self._log(f"已加入服务器，昵称: {name}")
        
        # Update mute button text to reflect actual mute state
        if self.mute:
            self.mute_btn.config(text="取消静音")
        else:
            self.mute_btn.config(text="静音")
        
        # Restart local listen if it was enabled (it was stopped during cleanup)
        if self.listen_own:
            self._start_local_listen()
        
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
        # Disable button during disconnect
        self.connect_btn.config(state=tk.DISABLED)
        
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
        self.mute_btn.config(state=tk.DISABLED)
        self.listen_own_btn.config(state=tk.NORMAL)
        self.mute_check.config(state=tk.NORMAL)
        self.status_var.set("已断开")
        self.status_label.config(foreground="red")
        self._log("已断开连接")
        
        self._cleanup()
        # Re-enable button
        self.connect_btn.config(state=tk.NORMAL)
        
    def _cleanup(self):
        """Clean up all network and audio resources."""
        # Stop local listening first
        self._stop_local_listen()
        
        # Stop running flag to signal threads to exit
        self.running = False
        
        # Wait briefly for threads to notice the flag change
        import time
        time.sleep(0.2)
        
        # Stop player first (it may be using audio output)
        if self.player:
            try:
                self.player.stop()
            except Exception:
                pass
            self.player = None
            
        # Close network socket
        if self.sock_audio:
            try:
                self.sock_audio.close()
            except Exception:
                pass
            self.sock_audio = None
            
        # Terminate PyAudio - this will close all streams opened with this instance
        if self.p:
            try:
                self.p.terminate()
            except Exception:
                pass
            self.p = None
        
        # Clear audio encryptor for next connection
        self.audio_encryptor = None
            
    def _toggle_mute(self):
        """Toggle mute state."""
        self.mute = not self.mute
        self.config['mute'] = self.mute
        self._save_config()
        if self.mute:
            self.mute_btn.config(text="取消静音")
            self._log("已静音")
        else:
            self.mute_btn.config(text="静音")
            self._log("已取消静音")
            
    def _on_mute_var_change(self):
        """Handle mute checkbox state change. Only updates the preference, not actual mute state."""
        # Don't modify self.mute here - it's just a preference for next connection
        # The actual mute state will be applied when connecting
        pass
            
    def _update_volume_label(self, *args):
        """Update volume display label."""
        self.volume_label.config(text=f"{self.volume_var.get():.1f}")
        
    def _apply_volume(self, *args):
        """Apply volume setting to audio player."""
        if hasattr(self, 'player') and self.player:
            self.player.volume = self.volume_var.get()
        self.config['volume'] = self.volume_var.get()
        self._save_config()
        
    def _update_gain_label(self, *args):
        """Update gain display label."""
        self.gain_label.config(text=f"{self.gain_var.get():.1f}")
        
    def _apply_gain(self, *args):
        """Save gain setting to config."""
        self.config['gain'] = self.gain_var.get()
        self._save_config()
            
    def _toggle_listen_own(self):
        """Toggle local audio monitoring."""
        # Prevent rapid clicking
        if not hasattr(self, '_listen_btn_lock'):
            self._listen_btn_lock = False
        
        if self._listen_btn_lock:
            return
        
        self._listen_btn_lock = True
        
        try:
            if self.listen_own:
                self.listen_own = False
                self.config['listen_own'] = False
                self.listen_own_btn.config(text="监听自己")
                self._log("已关闭监听自己")
                self._save_config()
                self._stop_local_listen()
            else:
                self.listen_own = True
                self.config['listen_own'] = True
                self.listen_own_btn.config(text="关闭监听")
                self._log("已开启监听自己")
                self._save_config()
                self._start_local_listen()
        finally:
            # Release lock after a short delay
            self.root.after(500, self._release_listen_lock)
    
    def _release_listen_lock(self):
        """Release the listen button lock."""
        self._listen_btn_lock = False
            
    def _send_audio(self):
        """Capture microphone audio and send to server via TCP."""
        try:
            if not hasattr(self, 'audio_encryptor') or self.audio_encryptor is None:
                self._log("音频加密模块未初始化，无法发送音频")
                return
            
            gain = self.config.get('gain', 1.0)
            
            kwargs = {
                'format': FORMAT,
                'channels': CHANNELS,
                'rate': RATE,
                'input': True,
                'frames_per_buffer': CHUNK
            }
            stream = self.p.open(**kwargs)
            self._log(f"麦克风已打开，正在发送音频... (增益: {gain:.1f})")
            
            while self.running:
                try:
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    original_data = data
                    if self.mute:
                        import array
                        samples = array.array('h', data)
                        samples = [0] * len(samples)
                        data = samples.tobytes()
                    elif gain != 1.0:
                        import array
                        samples = array.array('h', data)
                        samples = array.array('h', [int(s * gain) for s in samples])
                        samples = array.array('h', [max(-32768, min(32767, s)) for s in samples])
                        data = samples.tobytes()
                        
                    compressed_data = self.compressor.compress(data)
                    encrypted_data = self.audio_encryptor.encrypt(compressed_data)
                    timestamp = time.time()
                    header = struct.pack('!B', MSG_TYPE_AUDIO) + struct.pack('!d', timestamp) + struct.pack('!I', len(encrypted_data))
                    packet = header + encrypted_data
                    self.sock_audio.sendall(packet)
                    
                    if self.listen_own and self.player and not self.local_listen_running:
                        self.player.push(original_data)
                except Exception as e:
                    if self.running and not self.mute:
                        self._log(f"发送音频失败: {e}")
                    time.sleep(0.01)
                    
            stream.stop_stream()
            stream.close()
        except Exception as e:
            if self.running:
                self._log(f"音频发送错误: {e}")
            
    def _start_local_listen(self):
        """Start local audio monitoring, independent of server connection."""
        if self.local_listen_running:
            return
            
        try:
            import pyaudio
            if self.local_p is None:
                self.local_p = pyaudio.PyAudio()
            
            self.local_listen_player = AudioPlayer(self.local_p)
            
            kwargs = {
                'format': FORMAT,
                'channels': CHANNELS,
                'rate': RATE,
                'input': True,
                'frames_per_buffer': CHUNK
            }
            self.local_listen_stream = self.local_p.open(**kwargs)
            
            # Set flag after resources are ready
            self.local_listen_running = True
            thread = threading.Thread(target=self._local_listen_loop, daemon=True)
            thread.start()
        except Exception as e:
            self.local_listen_running = False
            self._log(f"启动本地监听失败: {e}")
            
    def _stop_local_listen(self):
        """Stop local audio monitoring."""
        # Set flag first to stop the loop
        self.local_listen_running = False
        
        # Then clean up resources
        stream = self.local_listen_stream
        self.local_listen_stream = None
        
        player = self.local_listen_player
        self.local_listen_player = None
        
        if stream:
            try:
                stream.stop_stream()
                stream.close()
            except Exception:
                pass
        if player:
            try:
                player.stop()
            except Exception:
                pass
            
    def _local_listen_loop(self):
        """Local monitoring loop: capture microphone and play back."""
        # Capture local references to avoid race conditions
        local_stream = self.local_listen_stream
        local_player = self.local_listen_player
        gain = self.config.get('gain', 1.0)
        
        while self.local_listen_running:
            try:
                if local_stream:
                    data = local_stream.read(CHUNK, exception_on_overflow=False)
                    if self.local_listen_running and local_player:
                        if gain != 1.0:
                            import array
                            samples = array.array('h', data)
                            samples = array.array('h', [int(s * gain) for s in samples])
                            samples = array.array('h', [max(-32768, min(32767, s)) for s in samples])
                            data = samples.tobytes()
                        local_player.push(data)
                else:
                    break
            except Exception:
                if not self.local_listen_running:
                    break
                time.sleep(0.01)
            
    def _receive_audio(self):
        """Receive and process incoming audio from server via TCP."""
        self._log("开始接收音频...")
        audio_count = 0
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
                        
                        if not self.audio_encryptor:
                            continue
                            
                        audio_count += 1
                        compressed_data = self.audio_encryptor.decrypt(encrypted_data)
                        if compressed_data and self.compressor:
                            pcm_data = self.compressor.decompress(compressed_data)
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
        if self.connected:
            self._disconnect()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description='语音聊天客户端')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='服务器地址')
    parser.add_argument('--port', type=int, default=9090, help='服务器端口')
    parser.add_argument('--name', type=str, default=None, help='你的昵称')
    parser.add_argument('--password', type=str, default=None, help='加密密码')
    parser.add_argument('--listen-own', action='store_true', help='监听自己的语音')
    parser.add_argument('--no-listen-own', action='store_true', help='不监听自己的语音')
    parser.add_argument('--rate', type=int, default=16000, help='音频采样率 (默认: 16000)')
    parser.add_argument('--chunk', type=int, default=512, help='音频块大小 (默认: 512)')
    parser.add_argument('--channels', type=int, default=1, help='音频声道数 (默认: 1)')
    parser.add_argument('--compress-level', type=int, default=6, help='zlib压缩级别 1-9 (默认: 6)')
    parser.add_argument('--jitter-buffer', type=int, default=3, help='抖动缓冲区大小 (默认: 3)')
    parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='日志级别')
    parser.add_argument('--quiet', action='store_true', help='静默模式，不显示任何日志')
    parser.add_argument('--input-device', type=int, default=None, help='音频输入设备索引')
    parser.add_argument('--output-device', type=int, default=None, help='音频输出设备索引')
    parser.add_argument('--list-devices', action='store_true', help='列出所有音频设备')
    parser.add_argument('--mute', action='store_true', help='启动时静音')
    parser.add_argument('--no-mute', action='store_true', help='启动时非静音')
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
        app = VoiceChatGUI(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
        return

    if args.quiet:
        logging.disable(logging.CRITICAL)
    else:
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format='%(asctime)s [%(levelname)s] %(message)s',
            force=True
        )

    global RATE, CHUNK, CHANNELS, JITTER_BUFFER_SIZE
    RATE = args.rate
    CHUNK = args.chunk
    CHANNELS = args.channels
    JITTER_BUFFER_SIZE = args.jitter_buffer

    host = args.host
    port = args.port

    if args.name:
        name = args.name
    else:
        name = input("你的昵称: ").strip()
        if not name:
            name = "匿名用户"

    if args.list_devices:
        p = pyaudio.PyAudio()
        info = p.get_host_api_info_by_index(0)
        num_devices = info.get('deviceCount')
        print("可用音频设备:")
        for i in range(num_devices):
            device_info = p.get_device_info_by_host_api_device_index(0, i)
            print(f"  [{i}] {device_info.get('name')} (输入: {device_info.get('maxInputChannels')}, 输出: {device_info.get('maxOutputChannels')})")
        p.terminate()
        return

    if args.no_mute:
        mute = False
    elif args.mute:
        mute = True
    else:
        mute = False

    if args.no_listen_own:
        listen_own = False
    elif args.listen_own:
        listen_own = True
    elif args.name and args.password:
        listen_own = False
    else:
        listen_own_input = input("是否监听自己的语音？(y/n) [n]: ").strip().lower()
        listen_own = listen_own_input == 'y'

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
        struct.pack('!BI', MSG_TYPE_JOIN, len(name_bytes)) + name_bytes +
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
    
    logger.info(f"已加入服务器，昵称: {name}，监听自己: {'是' if listen_own else '否'}")
        
    print("=" * 50)
    print("语音聊天已连接！按 Ctrl+C 退出。")
    print("=" * 50)

    p = pyaudio.PyAudio()

    player = AudioPlayer(p, output_device=args.output_device)
    
    if listen_own:
        logger.info("已启用监听自己的语音功能")

    send_thread = threading.Thread(target=send_audio, args=(sock, p, listen_own, player, audio_encryptor, compressor, mute, args.input_device), daemon=True)
    send_thread.start()

    receive_thread = threading.Thread(target=receive_audio, args=(sock, player, audio_encryptor, compressor), daemon=True)
    receive_thread.start()

    try:
        send_thread.join()
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