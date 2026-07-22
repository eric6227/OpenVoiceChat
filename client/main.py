import socket
import threading
import struct
import sys
import logging
import time
import os
import hashlib
import getpass
import argparse
import yaml
import ctypes
import ctypes.wintypes
import json
import array

# Ensure the project root is in sys.path so shared module can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pyaudio
except ImportError:
    print("错误: 请先安装 pyaudio: pip install pyaudio")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
except ImportError:
    print("错误: 请先安装 pycryptodome: pip install pycryptodome")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

from shared import (
    get_device_fingerprint,
    AudioEncryptor, SessionKeyEncryptor,
    AudioCompressor, JitterBuffer, AudioPlayer,
    CHANNELS, RATE, CHUNK,
    MSG_TYPE_JOIN, MSG_TYPE_AUDIO,
    MSG_TYPE_USER_LIST, MSG_TYPE_USER_JOINED, MSG_TYPE_HEARTBEAT,
    MSG_TYPE_LEAVE, MSG_TYPE_AUTH_SUCCESS, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_BANNED, MSG_TYPE_ADMIN_NOT_ONLINE,
    MSG_TYPE_RECORDING_NOTICE, MSG_TYPE_RECORDING_CONSENT,
    JITTER_BUFFER_SIZE, MAX_PACKET_SIZE,
    init_audio_format,
    encrypt_password_dpapi, decrypt_password_dpapi,
    load_known_servers, save_known_servers,
    compute_server_fingerprint, verify_server_fingerprint,
)

init_audio_format(pyaudio)
FORMAT = pyaudio.paInt16

logger = logging.getLogger(__name__)


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
                    samples = array.array('h', data)
                    samples = array.array('h', [0] * len(samples))
                    data = samples.tobytes()
                elif gain != 1.0:
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
                break
    except Exception as e:
        logger.error(f"Error reading audio data: {e}")
    finally:
        stream.stop_stream()
        stream.close()


def send_heartbeat(sock, server_addr, name, encryptor=None):
    """Continuously send heartbeat packets to keep the connection alive."""
    heartbeat_interval = 3
    while True:
        try:
            name_bytes = name.encode('utf-8')
            if encryptor:
                # Encrypt heartbeat data: [name]
                encrypted_data = encryptor.encrypt(name_bytes)
                heartbeat_packet = struct.pack('!B', MSG_TYPE_HEARTBEAT) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                # Fallback to plaintext if no encryptor (pre-authentication)
                heartbeat_packet = struct.pack('!BI', MSG_TYPE_HEARTBEAT, len(name_bytes)) + name_bytes
            
            sock.sendall(heartbeat_packet)
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
                    # Format: [msg_type(1)][encrypted_len(4)][encrypted_data]
                    if len(buffer) < 5:
                        break
                    encrypted_len = struct.unpack('!I', buffer[1:5])[0]
                    if len(buffer) < 5 + encrypted_len:
                        break
                    encrypted_data = buffer[5:5+encrypted_len]
                    buffer = buffer[5+encrypted_len:]
                    decrypted_data = encryptor.decrypt(encrypted_data)
                    if decrypted_data:
                        user_list = decrypted_data.decode('utf-8')
                        print(f"\n[Online Users] {user_list}\n")
                elif msg_type == MSG_TYPE_USER_JOINED:
                    # Format: [msg_type(1)][encrypted_len(4)][encrypted_data]
                    if len(buffer) < 5:
                        break
                    encrypted_len = struct.unpack('!I', buffer[1:5])[0]
                    if len(buffer) < 5 + encrypted_len:
                        break
                    encrypted_data = buffer[5:5+encrypted_len]
                    buffer = buffer[5+encrypted_len:]
                    decrypted_data = encryptor.decrypt(encrypted_data)
                    if decrypted_data:
                        event = decrypted_data.decode('utf-8')
                        print(f"\n[User Joined] {event}\n")
                elif msg_type == MSG_TYPE_BANNED:
                    print("\n您的设备已被管理员封禁，连接将被断开\n")
                    return
                elif msg_type == MSG_TYPE_LEAVE:
                    print("\n管理员已退出，所有用户将被强制断开连接\n")
                    return
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
        self.root.title("Open Voice Chat Client")
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
        self.user_id_map = {}  # Maps user_id -> user_name for display
        self.my_user_id = None  # Own user_id assigned by server
        self.muted_users = set()  # Set of user_ids that are muted
        
        # Recording notice related
        self.server_recording_enabled = False  # Whether server has recording enabled
        self.server_recording_purpose = ""  # Recording purpose from server
        self.server_recording_storage = 0  # Storage duration in minutes
        
        # Threading protection
        self._connect_lock = False  # Prevent multiple simultaneous connections
        self._listen_btn_lock = False  # Prevent rapid listen button clicks
        self._active_threads = []  # Track active threads for cleanup
        self._send_lock = threading.Lock()  # Protect socket send operations
        
        # Local listening related
        self.local_listen_stream = None
        self.local_listen_player = None
        self.local_listen_running = False
        self.local_p = None
        self._local_listen_thread = None
        self.local_listen_lock = threading.Lock()  # Protect local listen operations from race conditions
        
        # Config file path (same directory as executable)
        if getattr(sys, 'frozen', False):
            # Packaged executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Development environment
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(base_dir, 'config.yaml')
        self.known_servers_file = os.path.join(base_dir, 'known_servers.json')
        self._load_config()
        self.known_servers = self._load_known_servers()
        
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
        return encrypt_password_dpapi(password)
        
    def _decrypt_password(self, encrypted_hex: str) -> str:
        """Decrypt password using Windows DPAPI."""
        return decrypt_password_dpapi(encrypted_hex)
    
    def _load_known_servers(self) -> dict:
        """Load known server fingerprints from JSON file."""
        return load_known_servers(self.known_servers_file)
    
    def _save_known_servers(self):
        """Save known server fingerprints to JSON file."""
        save_known_servers(self.known_servers, self.known_servers_file)
    
    def _verify_server_fingerprint(self, server_addr: str, public_key_bytes: bytes) -> bool:
        """Verify server's RSA public key fingerprint (SSH-style trust)."""
        fingerprint = compute_server_fingerprint(public_key_bytes)
        
        if server_addr in self.known_servers:
            if fingerprint != self.known_servers[server_addr]:
                logger.error(f"SECURITY WARNING: Server fingerprint mismatch for {server_addr}!")
                logger.error(f"Expected: {self.known_servers[server_addr]}")
                logger.error(f"Received: {fingerprint}")
                logger.error("This could be a man-in-the-middle attack!")
                return False
            logger.info(f"Server fingerprint verified for {server_addr}")
            return True
        
        logger.info(f"First connection to {server_addr}")
        logger.info(f"Server public key fingerprint: {fingerprint}")
        
        if HAS_GUI and self.root and self.root.winfo_exists():
            if not self._show_privacy_dialog():
                logger.warning("User rejected privacy agreement, connection aborted")
                return False
            
            if not self._show_fingerprint_dialog(server_addr, fingerprint):
                logger.warning("User rejected server fingerprint, connection aborted")
                return False
            
            self.known_servers[server_addr] = fingerprint
            self._save_known_servers()
            logger.info(f"Server fingerprint saved for {server_addr}")
            return True
        
        logger.warning("CLI mode: auto-accepting server fingerprint")
        self.known_servers[server_addr] = fingerprint
        self._save_known_servers()
        return True
    
    def _show_privacy_dialog(self) -> bool:
        """Show privacy agreement dialog (must be called from main thread)."""
        privacy_message = (
            f"【隐私与使用协议】\n\n"
            f"1. 设备指纹收集:\n"
            f"   为便于服务器管理，我们将收集您的设备指纹\n"
            f"   （包括MAC地址、CPU ID等硬件标识符的哈希值）\n"
            f"   软件会在本地获取信息并计算哈希值，仅发送哈希值，无法反向得到原始信息。\n\n"
            f"2. 人类管理员监听：\n"
            f"   服务器有人类管理员全程监听您的音频通信（通常是邀请您加入服务器的人），以确保安全和合规。\n\n"
            f"3. 免责声明:\n"
            f"   本软件基于MIT许可证发布，不提供任何担保。\n"
            f"   开发者 github/eric6227 不对因使用本软件造成的任何后果承担责任。\n"
            f"   请遵守当地法律法规，不当使用造成的后果由使用者自行承担。\n\n"
            f"{'='*44}\n\n"
            f"是否同意上述隐私与使用协议？点击“是”即代表您同意以上条款。"
        )
        
        result = messagebox.askyesno(
            "隐私与使用协议",
            privacy_message
        )
        return result
    
    def _show_fingerprint_dialog(self, server_addr: str, fingerprint: str) -> bool:
        """Show server fingerprint verification dialog (must be called from main thread)."""
        fingerprint_message = (
            f"您正在首次连接到服务器:\n{server_addr}\n\n"
            f"服务器公钥指纹 (SHA-256):\n{fingerprint}\n\n"
            f"请通过其他可信渠道（如管理员、网站等）验证此指纹。\n"
            f"如果指纹不匹配，可能是中间人攻击！\n\n"
            f"{'='*44}\n\n"
            f"是否信任此服务器？点击“是”继续连接。"
        )
        
        result = messagebox.askyesno(
            "验证服务器身份",
            fingerprint_message
        )
        return result
    
    def _show_recording_consent_dialog(self) -> bool:
        """Show recording consent dialog before sending audio.
        
        Returns True if user consents, False otherwise.
        """
        if self.server_recording_enabled:
            # Server has recording enabled, show detailed notice
            storage_days = self.server_recording_storage
            
            consent_message = (
                f"服务器录音提示\n\n"
                f"服务器状态: 已开启音频录制\n\n"
                f"录音目的:\n{self.server_recording_purpose}\n\n"
                f"存储期限:\n{storage_days} 天（超过期限的文件将被自动删除）\n\n"
                f"录音方式:\n"
                f"- 格式: WAV (PCM 32-bit)\n"
                f"- 采样率: 16000 Hz\n"
                f"- 声道: 单声道\n"
                f"- 存储位置: 服务器本地 recordings/ 目录\n"
                f"- 文件大小限制: 10 GB（总大小）\n\n"
                f"录音范围:\n"
                f"- 录制您发送的所有音频数据\n"
                f"- 解密后的原始音频保存到服务器\n"
                f"- 按用户分别存储，文件名格式: 用户名_时间戳.wav\n\n"
                f"{'='*44}\n\n"
                f"继续连接即表示您同意服务器录制您的音频。\n"
                f"如不同意，请点击“否”断开连接。"
            )
            
            result = messagebox.askyesno(
                "服务器录音提示",
                consent_message
            )
            
            # Send consent response to server
            try:
                if self.sock_audio and not self.sock_audio._closed:
                    consent_packet = struct.pack('!BB', MSG_TYPE_RECORDING_CONSENT, 1 if result else 0)
                    with self._send_lock:
                        self.sock_audio.sendall(consent_packet)
                    self.root.after(0, self._log, f"已发送录音同意响应: {'同意' if result else '拒绝'}")
                else:
                    self.root.after(0, self._log, "警告: 音频连接已断开，无法发送同意响应")
            except Exception as e:
                self.root.after(0, self._log, f"发送录音同意失败: {e}")
            
            return result
        else:
            # Server has recording disabled, show notice
            notice_message = (
                f"服务器未开启录音\n\n"
                f"服务器状态: 未开启音频录制\n\n"
                f"您的语音数据不会被服务器录制保存。\n\n"
                f"{'='*44}\n\n"
                f"点击“是”继续连接。"
            )
            
            result = messagebox.askyesno(
                "服务器录音状态",
                notice_message
            )
            
            # Send consent response to server (always consent=True when recording disabled)
            try:
                if self.sock_audio and not self.sock_audio._closed:
                    consent_packet = struct.pack('!BB', MSG_TYPE_RECORDING_CONSENT, 1)
                    with self._send_lock:
                        self.sock_audio.sendall(consent_packet)
                    self.root.after(0, self._log, "已发送录音同意响应: 同意（服务器未开启录音）")
                else:
                    self.root.after(0, self._log, "警告: 音频连接已断开，无法发送同意响应")
            except Exception as e:
                self.root.after(0, self._log, f"发送录音同意失败: {e}")
            
            return True
        
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
            self.mute_btn = ttk.Button(control_frame, text="取消静音", command=self._toggle_own_mute)
        else:
            self.mute_btn = ttk.Button(control_frame, text="静音", command=self._toggle_own_mute)
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
        
        # Create a scrollable frame for user list
        users_canvas = tk.Canvas(users_frame, highlightthickness=0)
        users_scrollbar = ttk.Scrollbar(users_frame, orient="vertical", command=users_canvas.yview)
        self.users_scroll_frame = ttk.Frame(users_canvas)
        
        self.users_scroll_frame.bind(
            "<Configure>",
            lambda e: users_canvas.configure(scrollregion=users_canvas.bbox("all"))
        )
        
        users_canvas.create_window((0, 0), window=self.users_scroll_frame, anchor="nw")
        users_canvas.configure(yscrollcommand=users_scrollbar.set)
        
        users_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Track solo and mute states per user_id
        self.solo_users = set()  # Users set to solo mode
        self.muted_users = set()  # Users set to mute mode
        self.user_volumes = {}  # Volume per user_id: {user_id: volume_value}
        self.user_buttons = {}  # Store button references: {user_id: {"solo": btn, "mute": btn, "volume_scale": scale, "volume_label": label}}
        
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
        # Clear user_id_map and rebuild
        self.user_id_map.clear()
        self.user_buttons.clear()
        
        # Clear scroll frame
        for widget in self.users_scroll_frame.winfo_children():
            widget.destroy()
        
        if message.startswith("Users: "):
            users_str = message[7:]
            # Parse format: "[ID:1]user1, [ID:2]user2"
            users = [u.strip() for u in users_str.split(",") if u.strip()]
            if users:
                for user in users:
                    # Extract user_id and name
                    if user.startswith("[ID:"):
                        try:
                            end_bracket = user.index("]")
                            user_id = int(user[4:end_bracket])
                            username = user[end_bracket+1:]
                            self.user_id_map[user_id] = username
                            
                            # Skip self from display
                            if self.my_user_id is not None and user_id == self.my_user_id:
                                continue
                            
                            # Create row frame for this user
                            row_frame = ttk.Frame(self.users_scroll_frame)
                            row_frame.pack(fill=tk.X, pady=2, padx=5)
                            
                            # Username label
                            name_label = ttk.Label(row_frame, text=username, width=15, anchor=tk.W)
                            name_label.pack(side=tk.LEFT, padx=5)
                            
                            # Solo button
                            solo_active = user_id in self.solo_users
                            solo_bg = "#228B22" if solo_active else "#90EE90"
                            solo_btn = tk.Button(row_frame, text="S", bg=solo_bg, width=3, height=1,
                                               command=lambda uid=user_id, uname=username: self._toggle_solo(uid, uname))
                            solo_btn.pack(side=tk.LEFT, padx=2)
                            
                            # Mute button
                            mute_active = user_id in self.muted_users
                            mute_bg = "#CC0000" if mute_active else "#FFB6C1"
                            mute_btn = tk.Button(row_frame, text="M", bg=mute_bg, width=3, height=1,
                                               command=lambda uid=user_id, uname=username: self._toggle_mute(uid, uname))
                            mute_btn.pack(side=tk.LEFT, padx=2)
                            
                            # Volume slider
                            user_volume = self.user_volumes.get(user_id, 1.0)
                            volume_var = tk.DoubleVar(value=user_volume)
                            volume_scale = ttk.Scale(row_frame, from_=0.0, to=2.0, variable=volume_var, orient=tk.HORIZONTAL)
                            volume_scale.pack(side=tk.LEFT, padx=2)
                            volume_label = ttk.Label(row_frame, text=f"{user_volume:.1f}", width=3)
                            volume_label.pack(side=tk.LEFT, padx=2)
                            volume_var.trace('w', lambda *args, uid=user_id, uname=username: self._on_user_volume_change(uid, uname))
                            
                            # Store button references
                            self.user_buttons[user_id] = {"solo": solo_btn, "mute": mute_btn, "volume_var": volume_var, "volume_scale": volume_scale, "volume_label": volume_label}
                            
                        except (ValueError, IndexError):
                            pass
            else:
                # No users online
                ttk.Label(self.users_scroll_frame, text="(暂无用户在线)", foreground="gray").pack(pady=10)
        else:
            ttk.Label(self.users_scroll_frame, text=message, foreground="gray").pack(pady=10)
    
    def _toggle_solo(self, user_id, username):
        """Toggle solo mode for a user."""
        if user_id in self.solo_users:
            self.solo_users.discard(user_id)
            self._log(f"已取消独听用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["solo"].config(bg="#90EE90")
        else:
            self.solo_users.add(user_id)
            self._log(f"已设置独听用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["solo"].config(bg="#228B22")
    
    def _toggle_mute(self, user_id, username):
        """Toggle mute mode for a user."""
        if user_id in self.muted_users:
            self.muted_users.discard(user_id)
            self._log(f"已取消静音用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["mute"].config(bg="#FFB6C1")
        else:
            self.muted_users.add(user_id)
            self._log(f"已静音用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["mute"].config(bg="#CC0000")
    
    def _on_user_volume_change(self, user_id, username):
        """Handle user volume slider change."""
        if user_id in self.user_buttons:
            new_volume = self.user_buttons[user_id]["volume_var"].get()
            self.user_volumes[user_id] = new_volume
            self.user_buttons[user_id]["volume_label"].config(text=f"{new_volume:.1f}")
            self._log(f"已设置用户 {username} 的音量为 {new_volume:.1f}")
    
    def _apply_user_volume(self, data: bytes, user_id: int) -> bytes:
        """Apply per-user volume to audio data."""
        volume = self.user_volumes.get(user_id, 1.0)
        if volume == 1.0:
            return data
        samples = array.array('h', data)
        samples = [int(s * volume) for s in samples]
        samples = [max(-32768, min(32767, s)) for s in samples]
        return array.array('h', samples).tobytes()
    
    def _show_banned_dialog(self):
        """Show banned device dialog."""
        messagebox.showerror(
            "设备已被封禁",
            "您的设备已被管理员封禁。\n\n"
            "如果您认为这是误封，请联系管理员申诉。\n\n"
            "封禁是基于设备硬件指纹的，更换昵称或IP无法绕过封禁。",
            parent=self.root
        )
        
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
                    t.join(timeout=2.0)
            self._active_threads.clear()
            
            # Clean up old resources
            self._cleanup()
            
            # Wait for socket to fully close
            time.sleep(0.3)
            
            self.compressor = AudioCompressor(level=6)
            
            # Step 1: Temporary connection to receive server's RSA public key for fingerprint verification
            self.sock_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_audio.settimeout(10)
            self.root.after(0, self._log, f"正在连接 {host}:{port}...")
            self.sock_audio.connect((host, port))
            self.sock_audio.settimeout(None)
            
            self.root.after(0, self._log, "接收服务器 RSA 公钥...")
            pub_key_len_data = self._recv_exact(4)
            if not pub_key_len_data:
                raise Exception("服务器响应格式错误")
            
            pub_key_len = struct.unpack('!I', pub_key_len_data)[0]
            public_key_bytes = self._recv_exact(pub_key_len)
            if not public_key_bytes:
                raise Exception("服务器公钥接收失败")
            
            # Step 2: Close temporary connection before showing fingerprint dialog
            self.sock_audio.close()
            self.sock_audio = None
            self.root.after(0, self._log, "等待用户确认服务器指纹...")
            
            # Step 3: Verify server fingerprint (SSH-style trust)
            server_addr = f"{host}:{port}"
            if not self._verify_server_fingerprint(server_addr, public_key_bytes):
                raise Exception("服务器指纹验证失败，连接已终止")
            
            # Step 4: User approved, establish actual connection
            self.sock_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_audio.settimeout(10)
            self.sock_audio.connect((host, port))
            # Keep 10s timeout for handshake, will set to None after auth success
            
            # Step 5: Receive RSA public key again (new connection)
            pub_key_len_data = self._recv_exact(4)
            if not pub_key_len_data:
                raise Exception("服务器响应格式错误")
            
            pub_key_len = struct.unpack('!I', pub_key_len_data)[0]
            public_key_bytes = self._recv_exact(pub_key_len)
            if not public_key_bytes:
                raise Exception("服务器公钥接收失败")
            
            # Step 6: Encrypt password with RSA public key
            public_key = RSA.import_key(public_key_bytes)
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_password = cipher.encrypt(password.encode('utf-8'))
            
            self.root.after(0, self._log, f"密码已使用 RSA-2048 加密")
            
            # Step 7: Get device fingerprints
            device_fingerprints = get_device_fingerprint()
            fp_summary = f"MAC:{device_fingerprints['mac'][:16]} CPU:{device_fingerprints['cpu'][:16]}"
            self.root.after(0, self._log, f"设备指纹: {fp_summary}")
            
            # Step 8: Send JOIN packet with encrypted password and device fingerprints
            name_bytes = name.encode('utf-8')
            fingerprints_json = json.dumps(device_fingerprints).encode('utf-8')
            join_packet = (
                struct.pack('!BI', MSG_TYPE_JOIN, len(name_bytes)) + name_bytes +
                struct.pack('!I', len(encrypted_password)) + encrypted_password +
                struct.pack('!I', len(fingerprints_json)) + fingerprints_json
            )
            self.root.after(0, self._log, f"发送加入请求，包大小: {len(join_packet)} 字节")
            with self._send_lock:
                self.sock_audio.sendall(join_packet)
            
            self.root.after(0, self._log, "等待服务器响应...")
            
            # Set timeout for receiving response
            self.sock_audio.settimeout(15)
            try:
                response_type_data = self._recv_exact(1)
                if not response_type_data:
                    raise Exception("服务器无响应，连接超时")
            except socket.timeout:
                raise Exception("等待服务器响应超时")
            
            response_type = struct.unpack('!B', response_type_data[:1])[0]
            self.root.after(0, self._log, f"收到响应类型: {response_type}")
            
            if response_type == MSG_TYPE_AUTH_FAIL:
                raise Exception("密码错误，身份验证失败")
            elif response_type == MSG_TYPE_BANNED:
                raise Exception("设备已被封禁")
            elif response_type == MSG_TYPE_ADMIN_NOT_ONLINE:
                raise Exception("服务器未允许加入：管理员未在线")
            elif response_type == MSG_TYPE_AUTH_SUCCESS:
                # Format: [salt(32)][nonce(12)][tag(16)][encrypted_session_key(32)][user_id(4)]
                response_data = self._recv_exact(96)
                if not response_data or len(response_data) < 96:
                    raise Exception("服务器响应格式错误")
                
                salt = response_data[0:32]
                nonce = response_data[32:44]
                tag = response_data[44:60]
                encrypted_session_key = response_data[60:92]
                self.my_user_id = struct.unpack('!I', response_data[92:96])[0]
                
                # Use server-provided random salt (more secure than deriving salt from password)
                derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
                cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                self.session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
                
                self.audio_encryptor = SessionKeyEncryptor(self.session_key)
                
                # Receive recording notice from server
                self.root.after(0, self._log, "接收服务器录音状态通知...")
                try:
                    self.sock_audio.settimeout(5)
                    notice_type_data = self._recv_exact(1)
                    if notice_type_data:
                        notice_type = struct.unpack('!B', notice_type_data)[0]
                        if notice_type == MSG_TYPE_RECORDING_NOTICE:
                            # Parse recording notice
                            recording_enabled_data = self._recv_exact(1)
                            recording_enabled = struct.unpack('!B', recording_enabled_data)[0] == 1
                            
                            purpose_len_data = self._recv_exact(4)
                            purpose_len = struct.unpack('!I', purpose_len_data)[0]
                            purpose_bytes = self._recv_exact(purpose_len)
                            purpose = purpose_bytes.decode('utf-8')
                            
                            storage_minutes_data = self._recv_exact(4)
                            storage_minutes = struct.unpack('!I', storage_minutes_data)[0]
                            
                            # Store recording info
                            self.server_recording_enabled = recording_enabled
                            self.server_recording_purpose = purpose
                            self.server_recording_storage = storage_minutes
                            
                            self.root.after(0, self._log, 
                                f"服务器录音状态: {'已开启' if recording_enabled else '未开启'}")
                        else:
                            self.root.after(0, self._log, f"收到未知消息类型: {notice_type}")
                    else:
                        self.root.after(0, self._log, "未收到服务器录音状态通知")
                except Exception as e:
                    self.root.after(0, self._log, f"接收录音通知失败: {e}")
                    self.server_recording_enabled = False
                
                connected = True
            else:
                raise Exception("未知的服务器响应")
            
            # Set socket to non-blocking for audio
            self.sock_audio.settimeout(None)
            
            # Show recording notice dialog before sending audio
            if not self._show_recording_consent_dialog():
                raise Exception("用户不同意录音条款，连接已取消")
            
            self.p = pyaudio.PyAudio()
            self.player = AudioPlayer(self.p)
            
            self.running = True
            self.connected = True
            
            # 启动独立的心跳线程，确保即使音频发送阻塞也能正常发送心跳
            heartbeat_thread = threading.Thread(target=self._send_heartbeat, name='heartbeat', daemon=True)
            heartbeat_thread.start()
            self._active_threads.append(heartbeat_thread)
            
            send_thread = threading.Thread(target=self._send_audio, name='send_audio', daemon=True)
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
        self._log("提示：点击用户列表中的 独听列 可独听，点击 静音列 可静音。")
        
        # Reset solo and mute state on new connection
        self.solo_users.clear()
        self.muted_users.clear()
        
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
        
        # Show popup for ban message
        if "封禁" in message:
            self.root.after(100, self._show_banned_dialog)
        
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
                if self.audio_encryptor:
                    # Encrypt leave data: [name]
                    encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                    leave_packet = struct.pack('!B', MSG_TYPE_LEAVE) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                else:
                    leave_packet = struct.pack('!BI', MSG_TYPE_LEAVE, len(name_bytes)) + name_bytes
                with self._send_lock:
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
        # Stop local listening first and wait for it to finish
        self._stop_local_listen()
        
        # Stop running flag to signal threads to exit
        self.running = False
        
        # Wait briefly for threads to notice the flag change
        import time
        time.sleep(0.3)
        
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
        
        # Close signal socket
        if self.sock_signal:
            try:
                self.sock_signal.close()
            except Exception:
                pass
            self.sock_signal = None
            
        # Wait for active threads to finish
        for t in self._active_threads:
            if t.is_alive():
                t.join(timeout=1.0)
        self._active_threads.clear()
            
        # Terminate PyAudio - this will close all streams opened with this instance
        if self.p:
            try:
                self.p.terminate()
            except Exception:
                pass
            self.p = None
        
        # Clear audio encryptor for next connection
        self.audio_encryptor = None
            
    def _toggle_own_mute(self):
        """Toggle own mute state (whether to send audio)."""
        self.mute = not self.mute
        self.config['mute'] = self.mute
        self._save_config()
        if self.mute:
            self.mute_btn.config(text="取消静音")
            self._log("已静音（不发送音频）")
        else:
            self.mute_btn.config(text="静音")
            self._log("已取消静音（发送音频）")
            # If send thread has exited, restart it
            if self.connected and self.running:
                send_thread_alive = any(
                    t.is_alive() and t.name == 'send_audio'
                    for t in threading.enumerate()
                )
                if not send_thread_alive:
                    self._log("检测到音频发送线程已退出，正在重新创建...")
                    send_thread = threading.Thread(target=self._send_audio, name='send_audio', daemon=True)
                    send_thread.start()
                    self._active_threads.append(send_thread)
            
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
                
                # Only start local listen if not already running
                if not self.local_listen_running:
                    self._start_local_listen()
        except Exception as e:
            self._log(f"切换监听失败: {e}")
        finally:
            # Release lock after a short delay
            self.root.after(500, self._release_listen_lock)
    
    def _release_listen_lock(self):
        """Release the listen button lock."""
        self._listen_btn_lock = False
            
    def _send_heartbeat(self):
        """独立的心跳线程，确保即使音频发送阻塞也能正常发送心跳。"""
        try:
            if not hasattr(self, 'audio_encryptor') or self.audio_encryptor is None:
                return
            
            heartbeat_interval = 3  # 每3秒发送一次心跳
            last_heartbeat_time = 0
            
            while self.running and self.connected:
                try:
                    current_time = time.time()
                    if current_time - last_heartbeat_time >= heartbeat_interval:
                        name_bytes = self.name.encode('utf-8')
                        encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                        heartbeat_packet = struct.pack('!B', MSG_TYPE_HEARTBEAT) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                        with self._send_lock:
                            self.sock_audio.sendall(heartbeat_packet)
                        last_heartbeat_time = current_time
                    time.sleep(0.5)  # 短暂休眠，避免CPU占用过高
                except Exception as e:
                    if self.running:
                        self._log(f"心跳发送失败: {e}")
                    break
        except Exception as e:
            if self.running:
                self._log(f"心跳线程错误: {e}")
    
    def _send_audio(self):
        """Capture microphone audio and send to server via TCP."""
        try:
            if not hasattr(self, 'audio_encryptor') or self.audio_encryptor is None:
                self._log("音频加密模块未初始化，无法发送音频")
                return
            
            kwargs = {
                'format': FORMAT,
                'channels': CHANNELS,
                'rate': RATE,
                'input': True,
                'frames_per_buffer': CHUNK
            }
            stream = self.p.open(**kwargs)
            self._log("麦克风已打开，正在发送音频...")
            
            packet_count = 0
            
            while self.running:
                try:
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    original_data = data
                    gain = self.config.get('gain', 1.0)
                    if self.mute:
                        # Generate silence by creating zero bytes of same length
                        data = b'\x00' * len(data)
                    elif gain != 1.0:
                        samples = array.array('h', data)
                        samples = array.array('h', [int(s * gain) for s in samples])
                        samples = array.array('h', [max(-32768, min(32767, s)) for s in samples])
                        data = samples.tobytes()
                        
                    compressed_data = self.compressor.compress(data)
                    encrypted_data = self.audio_encryptor.encrypt(compressed_data)
                    timestamp = time.time()
                    header = struct.pack('!B', MSG_TYPE_AUDIO) + struct.pack('!d', timestamp) + struct.pack('!I', len(encrypted_data))
                    packet = header + encrypted_data
                    with self._send_lock:
                        self.sock_audio.sendall(packet)
                    
                    packet_count += 1
                    if packet_count <= 3:
                        self._log(f"已发送第 {packet_count} 个音频包，大小: {len(packet)}")
                    
                    if self.listen_own and self.player:
                        self.player.push(original_data)
                except Exception as e:
                    # Always log send failures regardless of mute state
                    if self.running:
                        self._log(f"发送音频失败: {e}")
                    break
                    
            stream.stop_stream()
            stream.close()
        except Exception as e:
            if self.running:
                self._log(f"音频发送错误: {e}")
            
    def _start_local_listen(self):
        """Start local audio monitoring, independent of server connection."""
        if self.local_listen_running:
            return
        
        # If already connected with main player, _send_audio will push directly to self.player
        if self.player is not None:
            self.local_listen_running = True
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
            
            self.local_listen_running = True
            thread = threading.Thread(target=self._local_listen_loop, daemon=True)
            self._local_listen_thread = thread
            thread.start()
        except Exception as e:
            self.local_listen_running = False
            self._log(f"启动本地监听失败: {e}")
            
    def _stop_local_listen(self):
        """Stop local audio monitoring."""
        # Set flag first to stop the loop
        self.local_listen_running = False
        
        # Wait for thread to finish (with timeout)
        if self._local_listen_thread and self._local_listen_thread.is_alive():
            self._local_listen_thread.join(timeout=2.0)
        
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
        
        while self.local_listen_running:
            try:
                if local_stream:
                    data = local_stream.read(CHUNK, exception_on_overflow=False)
                    if self.local_listen_running and local_player:
                        gain = self.config.get('gain', 1.0)
                        if gain != 1.0:
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
                        # New format: [msg_type(1)][sender_id(4)][sender_name_len(1)][sender_name(N)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                        if len(buffer) < 14:  # 1 + 4 + 1 + 8 minimum
                            break
                        
                        sender_id = struct.unpack('!I', buffer[1:5])[0]
                        sender_name_len = struct.unpack('!B', buffer[5:6])[0]
                        
                        if len(buffer) < 6 + sender_name_len + 12:
                            break
                        
                        sender_name = buffer[6:6+sender_name_len].decode('utf-8')
                        offset = 6 + sender_name_len
                        
                        timestamp = struct.unpack('!d', buffer[offset:offset+8])[0]
                        encrypted_len = struct.unpack('!I', buffer[offset+8:offset+12])[0]
                        
                        if len(buffer) < offset + 12 + encrypted_len:
                            break
                        
                        encrypted_data = buffer[offset+12:offset+12+encrypted_len]
                        buffer = buffer[offset+12+encrypted_len:]
                        
                        # Check solo/mute logic: solo has higher priority than mute
                        # If there are solo users, only play their audio
                        if self.solo_users:
                            if sender_id not in self.solo_users:
                                continue
                        else:
                            # No solo users, check mute list
                            if sender_id in self.muted_users:
                                continue
                        
                        if not self.audio_encryptor:
                            continue
                            
                        audio_count += 1
                        compressed_data = self.audio_encryptor.decrypt(encrypted_data)
                        if compressed_data and self.compressor:
                            pcm_data = self.compressor.decompress(compressed_data)
                            # Apply per-user volume
                            pcm_data = self._apply_user_volume(pcm_data, sender_id)
                            if self.player:
                                self.player.push(pcm_data)
                    elif msg_type == MSG_TYPE_USER_LIST:
                        # Format: [msg_type(1)][encrypted_len(4)][encrypted_data]
                        if len(buffer) < 5:
                            break
                        encrypted_len = struct.unpack('!I', buffer[1:5])[0]
                        if len(buffer) < 5 + encrypted_len:
                            break
                        encrypted_data = buffer[5:5+encrypted_len]
                        buffer = buffer[5+encrypted_len:]
                        if self.audio_encryptor:
                            decrypted_data = self.audio_encryptor.decrypt(encrypted_data)
                            if decrypted_data:
                                user_list = decrypted_data.decode('utf-8')
                                self.root.after(0, self._update_users, user_list)
                    elif msg_type == MSG_TYPE_USER_JOINED:
                        # Format: [msg_type(1)][encrypted_len(4)][encrypted_data]
                        if len(buffer) < 5:
                            break
                        encrypted_len = struct.unpack('!I', buffer[1:5])[0]
                        if len(buffer) < 5 + encrypted_len:
                            break
                        encrypted_data = buffer[5:5+encrypted_len]
                        buffer = buffer[5+encrypted_len:]
                        if self.audio_encryptor:
                            decrypted_data = self.audio_encryptor.decrypt(encrypted_data)
                            if decrypted_data:
                                event = decrypted_data.decode('utf-8')
                                self.root.after(0, self._log, f"[用户事件] {event}")
                    elif msg_type == MSG_TYPE_BANNED:
                        buffer = b''
                        self._log("您的设备已被管理员封禁，连接将被断开")
                        self.running = False
                        self.root.after(0, self._show_banned_dialog)
                        self.root.after(100, self._disconnect)
                        break
                    elif msg_type == MSG_TYPE_LEAVE:
                        buffer = b''
                        self._log("管理员已退出，所有用户将被强制断开连接")
                        self.running = False
                        self.root.after(0, self._disconnect)
                        break
                    else:
                        buffer = buffer[1:]
            except ConnectionResetError:
                self._log("连接被服务器重置")
                break
            except socket.timeout:
                # Ignore timeout when no other users are online
                if len(self.user_id_map) > 1:  # More than just self
                    if self.running:
                        self._log(f"接收音频超时")
                time.sleep(0.1)
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
    
    # Step 1: Receive RSA public key from server
    logger.info("接收服务器 RSA 公钥...")
    pub_key_len_data = b''
    while len(pub_key_len_data) < 4:
        chunk = sock.recv(4 - len(pub_key_len_data))
        if not chunk:
            logger.error("服务器响应格式错误")
            sock.close()
            return
        pub_key_len_data += chunk
    
    pub_key_len = struct.unpack('!I', pub_key_len_data)[0]
    public_key_bytes = b''
    while len(public_key_bytes) < pub_key_len:
        chunk = sock.recv(pub_key_len - len(public_key_bytes))
        if not chunk:
            logger.error("服务器公钥接收失败")
            sock.close()
            return
        public_key_bytes += chunk
    
    # Step 2: Show fingerprint for verification
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    server_addr = f"{host}:{port}"
    logger.info(f"服务器公钥指纹: {fingerprint}")
    
    # Load known servers for fingerprint verification
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    known_servers_file = os.path.join(base_dir, 'known_servers.json')
    known_servers = load_known_servers(known_servers_file)
    
    # Verify fingerprint against known servers
    if server_addr in known_servers:
        if fingerprint != known_servers[server_addr]:
            logger.error(f"SECURITY WARNING: Server fingerprint mismatch for {server_addr}!")
            logger.error(f"Expected: {known_servers[server_addr]}")
            logger.error(f"Received: {fingerprint}")
            logger.error("This could be a man-in-the-middle attack!")
            print("\n" + "="*60)
            print("⚠️ 安全警告：服务器指纹不匹配！")
            print("="*60)
            print(f"之前记录的指纹: {known_servers[server_addr]}")
            print(f"当前收到的指纹: {fingerprint}")
            print("\n这可能是中间人攻击！")
            override = input("是否仍然连接？(y/n) [n]: ").strip().lower()
            if override != 'y':
                logger.info("用户拒绝不匹配的指纹，连接已取消")
                sock.close()
                return
            logger.warning("用户覆盖了指纹不匹配警告")
        else:
            logger.info(f"Server fingerprint verified for {server_addr}")
            print(f"✅ 服务器指纹已验证: {fingerprint}")
    else:
        logger.info("请通过其他可信渠道验证此指纹")
        
        # Show user consent notice for CLI mode
        print("\n" + "="*60)
        print("【隐私与使用协议】")
        print("="*60)
        print("\n1. 设备指纹收集:")
        print("   为便于服务器管理，我们将收集您的设备信息")
        print("   （包括MAC地址、CPU ID等硬件标识符）")
        print("\n2. 同意声明:")
        print("   继续连接即表示您同意上述数据收集和使用")
        print("\n3. 免责声明:")
        print("   本软件基于MIT许可证发布，不提供任何担保。")
        print("   开发者不对因使用本软件造成的任何后果承担责任。")
        print("   请遵守当地法律法规，不当使用造成的后果由使用者自行承担。")
        print("\n" + "="*60)
        print(f"\n服务器公钥指纹 (SHA-256):\n  {fingerprint}\n")
        print("（录音提示将在连接成功后单独显示）")
        
        consent = input("\n是否继续连接？(y/n) [n]: ").strip().lower()
        if consent != 'y':
            logger.info("用户拒绝同意条款，连接已取消")
            sock.close()
            return
        
        logger.info("用户已同意条款，保存服务器指纹")
        known_servers[server_addr] = fingerprint
        save_known_servers(known_servers, known_servers_file)
        logger.info(f"Server fingerprint saved for {server_addr}")
    
    # Step 3: Encrypt password with RSA public key
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_password = cipher.encrypt(password.encode('utf-8'))
    logger.info("密码已使用 RSA-2048 加密")
    
    # Step 4: Get device fingerprints
    device_fingerprints = get_device_fingerprint()
    fp_summary = f"MAC:{device_fingerprints['mac'][:16]} CPU:{device_fingerprints['cpu'][:16]}"
    logger.info(f"设备指纹: {fp_summary}")
    
    # Step 5: Send JOIN packet with encrypted password and device fingerprints
    name_bytes = name.encode('utf-8')
    fingerprints_json = json.dumps(device_fingerprints).encode('utf-8')
    join_packet = (
        struct.pack('!BI', MSG_TYPE_JOIN, len(name_bytes)) + name_bytes +
        struct.pack('!I', len(encrypted_password)) + encrypted_password +
        struct.pack('!I', len(fingerprints_json)) + fingerprints_json
    )
    sock.sendall(join_packet)
    
    response_type_data = b''
    while len(response_type_data) < 1:
        chunk = sock.recv(1 - len(response_type_data))
        if not chunk:
            logger.error("服务器响应格式错误")
            sock.close()
            return
        response_type_data += chunk
    
    response_type = struct.unpack('!B', response_type_data[:1])[0]
    
    if response_type == MSG_TYPE_AUTH_FAIL:
        logger.error("密码错误，身份验证失败")
        sock.close()
        return
    elif response_type == MSG_TYPE_BANNED:
        logger.error("设备已被封禁")
        sock.close()
        return
    elif response_type == MSG_TYPE_ADMIN_NOT_ONLINE:
        logger.error("服务器未允许加入：管理员未在线")
        sock.close()
        return
    elif response_type != MSG_TYPE_AUTH_SUCCESS:
        logger.error("未知的服务器响应")
        sock.close()
        return
    
    response_data = b''
    while len(response_data) < 96:
        chunk = sock.recv(96 - len(response_data))
        if not chunk:
            logger.error("服务器响应不完整")
            sock.close()
            return
        response_data += chunk
    
    salt = response_data[0:32]
    nonce = response_data[32:44]
    tag = response_data[44:60]
    encrypted_session_key = response_data[60:92]
    my_user_id = struct.unpack('!I', response_data[92:96])[0]
    
    # Use server-provided random salt (more secure than deriving salt from password)
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
    
    audio_encryptor = SessionKeyEncryptor(session_key)
    
    # Receive recording notice from server
    logger.info("接收服务器录音状态通知...")
    try:
        sock.settimeout(5)
        notice_type_data = b''
        while len(notice_type_data) < 1:
            chunk = sock.recv(1 - len(notice_type_data))
            if not chunk:
                break
            notice_type_data += chunk
        
        if notice_type_data:
            notice_type = struct.unpack('!B', notice_type_data)[0]
            if notice_type == MSG_TYPE_RECORDING_NOTICE:
                # Parse recording notice
                recording_enabled_data = b''
                while len(recording_enabled_data) < 1:
                    chunk = sock.recv(1 - len(recording_enabled_data))
                    if not chunk:
                        break
                    recording_enabled_data += chunk
                recording_enabled = struct.unpack('!B', recording_enabled_data)[0] == 1
                
                purpose_len_data = b''
                while len(purpose_len_data) < 4:
                    chunk = sock.recv(4 - len(purpose_len_data))
                    if not chunk:
                        break
                    purpose_len_data += chunk
                purpose_len = struct.unpack('!I', purpose_len_data)[0]
                
                purpose_bytes = b''
                while len(purpose_bytes) < purpose_len:
                    chunk = sock.recv(purpose_len - len(purpose_bytes))
                    if not chunk:
                        break
                    purpose_bytes += chunk
                purpose = purpose_bytes.decode('utf-8')
                
                storage_minutes_data = b''
                while len(storage_minutes_data) < 4:
                    chunk = sock.recv(4 - len(storage_minutes_data))
                    if not chunk:
                        break
                    storage_minutes_data += chunk
                storage_minutes = struct.unpack('!I', storage_minutes_data)[0]
                
                # Show recording notice
                if recording_enabled:
                    storage_hours = storage_minutes / 60
                    if storage_hours >= 1:
                        storage_text = f"{storage_hours:.1f} 小时"
                    else:
                        storage_text = f"{storage_minutes} 分钟"
                    
                    print("\n" + "="*60)
                    print("⚠️ 服务器录音提示")
                    print("="*60)
                    print(f"\n服务器状态: 已开启音频录制\n")
                    print(f"录音目的:\n  {purpose}\n")
                    print(f"存储期限:\n  {storage_text}（按文件大小自动轮转）\n")
                    print(f"录音方式:\n")
                    print(f"  - 格式: WAV (PCM 32-bit)")
                    print(f"  - 采样率: 16000 Hz")
                    print(f"  - 声道: 单声道")
                    print(f"  - 文件轮转: 每 {storage_minutes} 分钟生成新文件")
                    print(f"  - 存储位置: 服务器本地 recordings/ 目录\n")
                    print(f"录音范围:\n")
                    print(f"  - 录制您发送的所有音频数据")
                    print(f"  - 解密后的原始音频保存到服务器")
                    print(f"  - 按用户分别存储，文件名格式: 用户名_时间戳.wav\n")
                    print("="*60)
                    print("\n继续连接即表示您同意服务器录制您的音频。")
                    print("如不同意，请输入 'n' 断开连接。")
                    
                    consent = input("\n是否同意并继续？(y/n) [y]: ").strip().lower()
                    user_consent = consent != 'n'
                    
                    # Send consent response to server
                    consent_packet = struct.pack('!BB', MSG_TYPE_RECORDING_CONSENT, 1 if user_consent else 0)
                    sock.sendall(consent_packet)
                    logger.info(f"已发送录音同意响应: {'同意' if user_consent else '拒绝'}")
                    
                    if not user_consent:
                        logger.info("用户不同意录音条款，连接已取消")
                        sock.close()
                        return
                else:
                    print("\n" + "="*60)
                    print("✅ 服务器未开启录音")
                    print("="*60)
                    print(f"\n服务器状态: 未开启音频录制\n")
                    print(f"您的语音数据不会被服务器录制保存。\n")
                    print("="*60)
                    input("\n按回车键继续...")
                    
                    # Send consent response to server (always consent=True when recording disabled)
                    consent_packet = struct.pack('!BB', MSG_TYPE_RECORDING_CONSENT, 1)
                    sock.sendall(consent_packet)
                    logger.info("已发送录音同意响应: 同意（服务器未开启录音）")
            else:
                logger.warning(f"收到未知消息类型: {notice_type}")
        else:
            logger.warning("未收到服务器录音状态通知")
    except Exception as e:
        logger.warning(f"接收录音通知失败: {e}")
    
    # Set socket to non-blocking
    sock.settimeout(None)
    
    logger.info(f"已加入服务器，昵称: {name}，监听自己: {'是' if listen_own else '否'}")
        
    print("=" * 50)
    print("语音聊天已连接！按 Ctrl+C 退出。")
    print("=" * 50)

    p = pyaudio.PyAudio()

    player = AudioPlayer(p, output_device=args.output_device)
    
    if listen_own:
        logger.info("已启用监听自己的语音功能")

    # Start heartbeat thread to keep connection alive
    heartbeat_thread = threading.Thread(
        target=send_heartbeat,
        args=(sock, (args.host, args.port), name, audio_encryptor),
        daemon=True
    )
    heartbeat_thread.start()

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
            if audio_encryptor:
                encrypted_data = audio_encryptor.encrypt(name_bytes)
                leave_packet = struct.pack('!B', MSG_TYPE_LEAVE) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
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