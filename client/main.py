import socket
import threading
import struct
import sys
import logging
import time
import os
import hashlib
import yaml
import ctypes
import ctypes.wintypes
import json
import array
import queue

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

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from shared import (
    get_device_fingerprint,
    AudioEncryptor, SessionKeyEncryptor,
    AudioCompressor, JitterBuffer, AudioPlayer, NoiseSuppressor,
    CHANNELS, RATE, CHUNK,
    MSG_TYPE_JOIN, MSG_TYPE_AUDIO,
    MSG_TYPE_USER_LIST, MSG_TYPE_USER_JOINED, MSG_TYPE_HEARTBEAT,
    MSG_TYPE_LEAVE, MSG_TYPE_AUTH_SUCCESS, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_BANNED, MSG_TYPE_ADMIN_NOT_ONLINE,
    MSG_TYPE_RECORDING_NOTICE, MSG_TYPE_RECORDING_CONSENT,
    MSG_TYPE_ADMIN_ONLINE, MSG_TYPE_ADMIN_OFFLINE,
    MSG_TYPE_DUPLICATE_NAME,
    MSG_TYPE_TEXT_CHAT, MSG_TYPE_TEXT_MESSAGE,
    MSG_TYPE_UDP_PORT, UDP_AUDIO_PORT,
    JITTER_BUFFER_SIZE, MAX_PACKET_SIZE,
    init_audio_format,
    encrypt_password_dpapi, decrypt_password_dpapi,
    load_known_servers, save_known_servers,
    compute_server_fingerprint, verify_server_fingerprint,
)
from shared.rudp import RUDPEndpoint, pack_rudp_message, unpack_rudp_message

init_audio_format(pyaudio)
FORMAT = pyaudio.paInt16

logger = logging.getLogger(__name__)


class VoiceChatGUI:
    """Main GUI class for the voice chat client."""
    def __init__(self, root, name_override=None):
        self.root = root
        self.root.title("Open Voice Chat Client")
        self.root.resizable(True, True)
        
        # Automatically set window size to 1/5 width and 2/3 height of screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = screen_width // 5
        window_height = screen_height * 2 // 3
        self.root.geometry(f"{window_width}x{window_height}")
        
        self.connected = False
        self.running = False
        self.mute = False
        self.listen_own = False
        
        self.sock_audio = None  # Will be replaced by udp_sock
        self.sock_signal = None  # No longer used
        self.udp_sock = None  # Single UDP socket for all communication
        self.rudp_endpoint = None  # RUDP endpoint for reliable control messages
        self.server_addr = None  # (host, port) of server's UDP port
        self.player = None
        self.p = None
        self.encryptor = None
        self.compressor = None
        self.noise_suppressor = NoiseSuppressor(threshold=0)  # Noise gate, 0=off
        self.audio_encryptor = None  # Session key based encryptor
        self.session_key = None
        self.server_addr = None
        self.signal_addr = None
        self.name = None
        self.user_id_map = {}  # Maps user_id -> user_name for display
        self.my_user_id = None  # Own user_id assigned by server
        self.muted_users = set()  # Set of user_ids that are muted
        self._packet_queue = None  # Queue for decoupling recv from processing
        self.last_packet_time = 0  # Timestamp of last received packet
        self._auto_reconnect = True  # Auto-reconnect on server disconnect
        self._reconnect_params = None  # (host, port, name, password) for reconnection
        self._admin_online = True  # Whether admin is currently online
        self._active_audio_users = {}  # user_id -> last_audio_time for volume normalization
        self._text_allowed = True  # Whether text chat is allowed (gated by _admin_online if REQUIRE_ADMIN)
        
        # Recording notice related
        self.server_recording_enabled = False  # Whether server has recording enabled
        self.server_recording_purpose = ""  # Recording purpose from server
        self.server_recording_storage = 0  # Storage duration in minutes
        self.server_recording_max_size = 10240  # Max total size in MB
        
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

        if name_override:
            self.config['name'] = name_override

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
            'gain': 1.0,
            'noise_threshold': 0
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
        
        if self.root and self.root.winfo_exists():
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
            storage_minutes = self.server_recording_storage
            storage_text = f"{storage_minutes} 分钟"
            if storage_minutes >= 60:
                storage_text = f"{storage_minutes // 60} 小时 {storage_minutes % 60} 分钟"
            
            max_size = self.server_recording_max_size
            size_text = f"{max_size} MB"
            if max_size >= 1024:
                size_text = f"{max_size / 1024:.1f} GB"
            
            consent_message = (
                f"服务器录音与管理提示\n\n"
                f"管理员监听: 服务器有人类管理员全程监听您的音频通信\n"
                f"（通常是邀请您加入服务器的人），以确保安全和合规。\n\n"
                f"服务器状态: 已开启音频录制\n\n"
                f"录音目的:\n{self.server_recording_purpose}\n\n"
                f"存储期限:\n{storage_text}（超过期限的文件将被自动删除）\n\n"
                f"录音方式:\n"
                f"- 格式: WAV (PCM 32-bit)\n"
                f"- 采样率: 16000 Hz\n"
                f"- 声道: 单声道\n"
                f"- 存储位置: 服务器本地 recordings/ 目录\n"
                f"- 文件大小限制: {size_text}（总大小）\n\n"
                f"录音范围:\n"
                f"- 录制您发送的所有音频数据\n"
                f"- 解密后的原始音频保存到服务器\n"
                f"- 按用户分别存储，文件名格式: 用户名_时间戳.wav\n\n"
                f"{'='*44}\n\n"
                f"继续连接即表示您同意服务器录制您的音频及管理员监听。\n"
                f"如不同意，请点击“否”断开连接。"
            )
            
            result = messagebox.askyesno(
                "服务器录音与管理提示",
                consent_message
            )
            
            # Send consent response to server
            try:
                if self.rudp_endpoint:
                    consent_data = struct.pack('!B', 1 if result else 0)
                    self.rudp_endpoint.send_raw(MSG_TYPE_RECORDING_CONSENT, consent_data)
                    self.root.after(0, self._log, f"已发送录音同意响应: {'同意' if result else '拒绝'}")
                else:
                    self.root.after(0, self._log, "警告: RUDP端点未初始化，无法发送同意响应")
            except Exception as e:
                self.root.after(0, self._log, f"发送录音同意失败: {e}")
            
            return result
        else:
            # Server has recording disabled, show notice
            notice_message = (
                f"服务器录音与管理提示\n\n"
                f"管理员监听: 服务器有人类管理员全程监听您的音频通信\n"
                f"（通常是邀请您加入服务器的人），以确保安全和合规。\n\n"
                f"服务器状态: 未开启音频录制\n\n"
                f"您的语音数据不会被服务器录制保存。\n\n"
                f"{'='*44}\n\n"
                f"点击“是”继续连接。"
            )
            
            result = messagebox.askyesno(
                "服务器录音与管理提示",
                notice_message
            )
            
            # Send consent response to server (always consent=True when recording disabled)
            try:
                if self.rudp_endpoint:
                    consent_data = struct.pack('!B', 1)
                    self.rudp_endpoint.send_raw(MSG_TYPE_RECORDING_CONSENT, consent_data)
                    self.root.after(0, self._log, "已发送录音同意响应: 同意（服务器未开启录音）")
                else:
                    self.root.after(0, self._log, "警告: RUDP端点未初始化，无法发送同意响应")
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
        
        ttk.Label(config_frame, text="降噪:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.noise_var = tk.IntVar(value=self.config.get('noise_threshold', 0))
        ttk.Scale(config_frame, from_=0, to=100, variable=self.noise_var, orient=tk.HORIZONTAL).grid(row=5, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        self.noise_label = ttk.Label(config_frame, text=f"{self.config.get('noise_threshold', 0)}%")
        self.noise_label.grid(row=5, column=2, padx=5, pady=5)
        self.noise_var.trace('w', self._update_noise_label)
        self.noise_var.trace('w', self._apply_noise)
        
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
        
        # Text chat frame
        chat_frame = ttk.LabelFrame(main_frame, text="文字聊天", padding="10")
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.chat_text = scrolledtext.ScrolledText(chat_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.chat_text.pack(fill=tk.BOTH, expand=True)
        
        chat_input_frame = ttk.Frame(chat_frame)
        chat_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.chat_input = ttk.Entry(chat_input_frame)
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.chat_input.bind("<Return>", self._send_text_message)
        
        self.chat_send_btn = ttk.Button(chat_input_frame, text="发送", command=self._send_text_message)
        self.chat_send_btn.pack(side=tk.RIGHT)
        
        # Log frame (reduced height for chat)
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=False)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=2, state=tk.DISABLED, wrap=tk.WORD)
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
        """Update the online users list display incrementally.
        
        Only adds new users and removes departed users. Users that
        remain unchanged are not refreshed, preventing UI flicker.
        """
        try:
            new_user_list = json.loads(message)
            new_ids = set()
            new_id_to_name = {}
            
            # Build new user set (excluding self)
            for user in new_user_list:
                user_id = user["id"]
                new_ids.add(user_id)
                new_id_to_name[user_id] = user["name"]
            
            # Get current user IDs (excluding self from display set)
            old_ids = set(self.user_id_map.keys())
            if self.my_user_id is not None:
                old_ids.discard(self.my_user_id)
                new_ids.discard(self.my_user_id)
            
            # Remove departed users
            removed_ids = old_ids - new_ids
            for user_id in removed_ids:
                if user_id in self.user_buttons:
                    buttons = self.user_buttons[user_id]
                    if "row_frame" in buttons:
                        try:
                            buttons["row_frame"].destroy()
                        except Exception:
                            pass
                    del self.user_buttons[user_id]
                if user_id in self.user_id_map:
                    del self.user_id_map[user_id]
            
            # Add new users
            added_ids = new_ids - old_ids
            for user_id in added_ids:
                username = new_id_to_name[user_id]
                self.user_id_map[user_id] = username
                self._add_user_row(user_id, username)
            
            # Update user_id_map with latest names
            self.user_id_map.clear()
            for user_id, username in new_id_to_name.items():
                self.user_id_map[user_id] = username
            
            # Show/hide "no users" label
            has_visible_users = any(
                uid != self.my_user_id for uid in self.user_id_map
            ) if self.user_id_map else False
            self._update_empty_label(has_visible_users)
            
        except Exception:
            ttk.Label(self.users_scroll_frame, text=message, foreground="gray").pack(pady=10)
    
    def _add_user_row(self, user_id, username):
        """Add a single user row to the display."""
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
        self.user_buttons[user_id] = {
            "solo": solo_btn, "mute": mute_btn,
            "volume_var": volume_var, "volume_scale": volume_scale,
            "volume_label": volume_label, "row_frame": row_frame
        }
    
    def _update_empty_label(self, has_visible_users):
        """Show or hide the 'no users online' label."""
        # Find and manage the empty label
        for widget in self.users_scroll_frame.winfo_children():
            if isinstance(widget, ttk.Label) and widget.cget("text") == "(暂无用户在线)":
                if has_visible_users:
                    widget.pack_forget()
                return
        
        if not has_visible_users:
            ttk.Label(self.users_scroll_frame, text="(暂无用户在线)", foreground="gray").pack(pady=10)
    
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
        """Apply per-user volume to audio data with active speaker normalization.
        
        actual_volume = volume_setting * (1 / unmuted_active_speaker_count)
        Clean up stale speakers (no audio for >2 seconds).
        Only unmuted (not in muted_users) active speakers count toward normalization.
        If listen_own is enabled, count includes self (+1).
        """
        volume = self.user_volumes.get(user_id, 1.0)
        # Clean up stale speakers and count active ones
        now = time.time()
        stale = [uid for uid, t in self._active_audio_users.items() if now - t > 2.0]
        for uid in stale:
            del self._active_audio_users[uid]
        # Only count unmuted users in active_count
        unmuted_active = [uid for uid in self._active_audio_users if uid not in self.muted_users]
        active_count = len(unmuted_active)
        if self.listen_own:
            active_count += 1
        active_count = max(1, active_count)
        volume = volume / active_count
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
        """Background thread to establish connection to server using UDP+RUDP."""
        # Store params for auto-reconnection
        self._reconnect_params = (host, port, name, password)
        self._auto_reconnect = True
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
            
            self.compressor = AudioCompressor(bitrate=32000)
            self.server_addr = (host, port)
            
            # Step 1: Create UDP socket for all communication
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.settimeout(5)  # 5 second timeout for auth
            self.udp_sock.bind(('0.0.0.0', 0))
            self.root.after(0, self._log, f"UDP套接字已创建，本地端口: {self.udp_sock.getsockname()[1]}")
            
            # Step 2: Create RUDP endpoint for reliable control messages
            self.rudp_endpoint = RUDPEndpoint(self.udp_sock, self.server_addr)
            
            # Step 3: Request RSA public key from server (empty payload)
            self.root.after(0, self._log, f"正在连接 {host}:{port}...")
            self.root.after(0, self._log, "请求服务器 RSA 公钥...")
            
            # Use send_and_wait for reliable delivery of RSA key request
            result = self.rudp_endpoint.send_and_wait(MSG_TYPE_JOIN, b'', timeout=10)
            if result is None:
                raise Exception("服务器无响应，获取RSA公钥超时")
            
            msg_type, payload = result
            if msg_type != MSG_TYPE_JOIN:
                raise Exception(f"收到意外的消息类型: {msg_type}")
            
            # Parse public key: [pub_key_len(4)][public_key_bytes]
            if len(payload) < 4:
                raise Exception("服务器响应格式错误")
            pub_key_len = struct.unpack('!I', payload[:4])[0]
            public_key_bytes = payload[4:4+pub_key_len]
            
            # Step 5: Verify server fingerprint (SSH-style trust)
            server_addr_str = f"{host}:{port}"
            if not self._verify_server_fingerprint(server_addr_str, public_key_bytes):
                raise Exception("服务器指纹验证失败，连接已终止")
            
            self.root.after(0, self._log, "服务器指纹验证通过")
            
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
            join_data = (
                struct.pack('!I', len(name_bytes)) + name_bytes +
                struct.pack('!I', len(encrypted_password)) + encrypted_password +
                struct.pack('!I', len(fingerprints_json)) + fingerprints_json
            )
            
            self.root.after(0, self._log, f"发送加入请求，包大小: {len(join_data)} 字节")
            
            # Use RUDP send_and_wait for reliable delivery
            result = self.rudp_endpoint.send_and_wait(MSG_TYPE_JOIN, join_data, timeout=15)
            if result is None:
                raise Exception("服务器无响应，认证超时")
            
            msg_type, payload = result
            self.root.after(0, self._log, f"收到响应类型: {msg_type}")
            
            if msg_type == MSG_TYPE_AUTH_FAIL:
                raise Exception("密码错误，身份验证失败")
            elif msg_type == MSG_TYPE_BANNED:
                raise Exception("设备已被封禁")
            elif msg_type == MSG_TYPE_DUPLICATE_NAME:
                raise Exception("昵称已被占用，请更换昵称后重试")
            elif msg_type == MSG_TYPE_AUTH_SUCCESS:
                # Format: [salt(32)][nonce(12)][tag(16)][encrypted_session_key(32)][user_id(4)]
                if len(payload) < 96:
                    raise Exception("服务器响应格式错误")
                
                salt = payload[0:32]
                nonce = payload[32:44]
                tag = payload[44:60]
                encrypted_session_key = payload[60:92]
                self.my_user_id = struct.unpack('!I', payload[92:96])[0]
                
                # Derive session key
                derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
                cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                self.session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
                
                self.audio_encryptor = SessionKeyEncryptor(self.session_key)
                self.root.after(0, self._log, f"认证成功，user_id: {self.my_user_id}")
                
                # Receive recording notice from server
                self.root.after(0, self._log, "接收服务器录音状态通知...")
                try:
                    result = self.rudp_endpoint.handle_incoming_wait(timeout=5)
                    if result is not None:
                        notice_type, notice_payload = result
                        if notice_type == MSG_TYPE_RECORDING_NOTICE:
                            # Decrypt the recording notice
                            if self.audio_encryptor:
                                notice_payload = self.audio_encryptor.decrypt(notice_payload)
                                if notice_payload is None:
                                    raise Exception("录音通知解密失败")
                            
                            # Parse recording notice
                            recording_enabled = struct.unpack('!B', notice_payload[:1])[0] == 1
                            purpose_len = struct.unpack('!I', notice_payload[1:5])[0]
                            purpose = notice_payload[5:5+purpose_len].decode('utf-8')
                            storage_minutes = struct.unpack('!I', notice_payload[5+purpose_len:5+purpose_len+4])[0]
                            
                            # Try to parse max_size_mb if present (newer server format)
                            expected_len = 5 + purpose_len + 4
                            max_size_mb = 10240  # Default
                            if len(notice_payload) >= expected_len + 4:
                                max_size_mb = struct.unpack('!I', notice_payload[expected_len:expected_len+4])[0]
                            
                            self.server_recording_enabled = recording_enabled
                            self.server_recording_purpose = purpose
                            self.server_recording_storage = storage_minutes
                            self.server_recording_max_size = max_size_mb
                            
                            self.root.after(0, self._log, 
                                f"服务器录音状态: {'已开启' if recording_enabled else '未开启'}")
                        else:
                            self.root.after(0, self._log, f"收到未知消息类型: {notice_type}")
                    else:
                        self.root.after(0, self._log, "未收到服务器录音状态通知")
                except Exception as e:
                    self.root.after(0, self._log, f"接收录音通知失败: {e}")
                    self.server_recording_enabled = False
            else:
                raise Exception("未知的服务器响应")
            
            # Check admin online status
            self._admin_online = True  # Default: assume admin is online
            try:
                result = self.rudp_endpoint.handle_incoming_wait(timeout=2)
                if result is not None:
                    check_msg_type, check_payload = result
                    if check_msg_type == MSG_TYPE_ADMIN_OFFLINE:
                        self._admin_online = False
                        self.root.after(0, self._log, "管理员未在线，等待管理员上线...")
                    # Other messages (USER_JOINED, USER_LIST) are consumed here,
                    # but user list is periodically re-broadcast by server
            except Exception:
                pass  # Timeout or error, assume admin is online
            
            # Show recording consent dialog before sending audio
            if not self._show_recording_consent_dialog():
                raise Exception("用户不同意录音条款，连接已取消")
            
            # Initialize audio
            self.p = pyaudio.PyAudio()
            self.player = AudioPlayer(self.p)
            
            self.running = True
            self.connected = True
            
            # Drain stale audio packets from OS socket buffer.
            # Between auth success and thread start, the server is already
            # forwarding audio from existing clients. These packets accumulate
            # in the OS socket buffer and would flood the JitterBuffer on startup,
            # causing a multi-second initial delay. We discard them here so the
            # JitterBuffer starts fresh with only new, real-time packets.
            self.udp_sock.settimeout(0.05)
            stale_count = 0
            while True:
                try:
                    data, _ = self.udp_sock.recvfrom(MAX_PACKET_SIZE)
                    if data and len(data) >= 1:
                        stale_count += 1
                except socket.timeout:
                    break
                except OSError:
                    break
            if stale_count > 0:
                self.root.after(0, self._log, f"丢弃了 {stale_count} 个连接延迟的音频包")
            self.udp_sock.settimeout(5)  # Reset for auth, receive loop will override
            
            # Start heartbeat thread (via RUDP)
            heartbeat_thread = threading.Thread(target=self._send_heartbeat, name='heartbeat', daemon=True)
            heartbeat_thread.start()
            self._active_threads.append(heartbeat_thread)
            
            # Start audio send thread (UDP)
            send_thread = threading.Thread(target=self._send_audio, name='send_audio', daemon=True)
            send_thread.start()
            self._active_threads.append(send_thread)
            
            # Start unified receive thread (UDP + RUDP)
            self._packet_queue = queue.Queue(maxsize=2000)
            receive_thread = threading.Thread(target=self._receive_loop, name='receive_loop', daemon=True)
            receive_thread.start()
            self._active_threads.append(receive_thread)
            
            # Start packet processing thread (decrypt + decompress offloaded from recv)
            process_thread = threading.Thread(target=self._process_loop, name='process_loop', daemon=True)
            process_thread.start()
            self._active_threads.append(process_thread)
            
            # Initialize last packet time and start connection watchdog
            self.last_packet_time = time.time()
            watchdog_thread = threading.Thread(target=self._connection_watchdog, name='watchdog', daemon=True)
            watchdog_thread.start()
            self._active_threads.append(watchdog_thread)
            
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
        self._log(f"已加入服务器，昵称: {name}")
        
        if self._admin_online:
            self.status_var.set(f"已连接 ({name})")
            self.status_label.config(foreground="green")
            self._log("提示：点击用户列表中的 独听列 可独听，点击 静音列 可静音。")
        else:
            self.status_var.set("管理员未在线，等待中...")
            self.status_label.config(foreground="orange")
            self._log("管理员未在线，等待管理员上线...")
            messagebox.showwarning(
                "管理员未在线",
                "管理员当前未在线，您已连接但无法发送语音。\n管理员上线后语音将自动恢复。",
                parent=self.root
            )
        
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
        
        # Show popup and status for duplicate name
        if "昵称已被占用" in message:
            self.status_var.set("昵称已被占用")
            self.root.after(100, lambda: messagebox.showwarning(
                "昵称已被占用",
                "该昵称已被其他用户使用，请更换昵称后重试。",
                parent=self.root
            ))
        
    def _disconnect(self, server_initiated=False):
        """Disconnect from server and clean up resources.
        
        Args:
            server_initiated: True if disconnect was initiated by server
                              (e.g., admin left). In this case, auto-reconnect
                              remains enabled so the client can rejoin later.
        """
        if not server_initiated:
            self._auto_reconnect = False  # User manually disconnected
        # Disable button during disconnect
        self.connect_btn.config(state=tk.DISABLED)
        
        self.running = False
        self.connected = False
        
        # Send LEAVE message via RUDP
        try:
            if self.name and self.rudp_endpoint:
                name_bytes = self.name.encode('utf-8')
                if self.audio_encryptor:
                    # Encrypt leave data: [name]
                    encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                    leave_data = struct.pack('!I', len(encrypted_data)) + encrypted_data
                else:
                    leave_data = struct.pack('!I', len(name_bytes)) + name_bytes
                # Fire-and-forget, don't wait for response
                self.rudp_endpoint.send_raw(MSG_TYPE_LEAVE, leave_data)
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
        
        # If server initiated disconnect and auto-reconnect is allowed,
        # start a new watchdog for auto-reconnection
        if server_initiated and self._reconnect_params and self._auto_reconnect:
            self._log("服务器断开连接，将自动尝试重连...")
            self.running = True
            self.last_packet_time = time.time()
            watchdog_thread = threading.Thread(target=self._connection_watchdog, name='watchdog', daemon=True)
            watchdog_thread.start()
            self._active_threads.append(watchdog_thread)
        elif server_initiated:
            self._log("服务器断开连接，不自动重连")
        
    def _cleanup(self):
        """Clean up all network and audio resources."""
        # Stop local listening first and wait for it to finish
        self._stop_local_listen()
        
        # Stop running flag to signal threads to exit
        self.running = False
        
        # Stop player first (it may be using audio output)
        if self.player:
            try:
                self.player.stop()
            except Exception:
                pass
            self.player = None
        
        # Close RUDP endpoint
        if self.rudp_endpoint:
            try:
                self.rudp_endpoint.close()
            except Exception:
                pass
            self.rudp_endpoint = None
        
        # Close UDP socket
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None
        
        # Clean up old TCP socket references (no longer used)
        self.sock_audio = None
        self.sock_signal = None
            
        # Wait for active threads to finish (skip current thread)
        current = threading.current_thread()
        for t in self._active_threads:
            if t is not current and t.is_alive():
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
    
    def _update_noise_label(self, *args):
        """Update noise suppression display label."""
        self.noise_label.config(text=f"{self.noise_var.get()}%")
    
    def _apply_noise(self, *args):
        """Apply noise suppression threshold setting."""
        threshold = self.noise_var.get()
        self.noise_suppressor.threshold = threshold
        self.config['noise_threshold'] = threshold
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
        """独立的心跳线程，通过RUDP发送心跳。"""
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
                        heartbeat_data = struct.pack('!I', len(encrypted_data)) + encrypted_data
                        self.rudp_endpoint.send_raw(MSG_TYPE_HEARTBEAT, heartbeat_data)
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
        """Capture microphone audio and send to server via UDP."""
        try:
            if not hasattr(self, 'audio_encryptor') or self.audio_encryptor is None:
                self._log("音频加密模块未初始化，无法发送音频")
                return
            
            if self.udp_sock is None or self.server_addr is None:
                self._log("UDP套接字或服务器地址未配置，无法发送音频")
                return
            
            kwargs = {
                'format': FORMAT,
                'channels': CHANNELS,
                'rate': RATE,
                'input': True,
                'frames_per_buffer': CHUNK
            }
            stream = self.p.open(**kwargs)
            self._log("麦克风已打开")
            
            packet_count = 0
            
            while self.running:
                try:
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    original_data = data
                    
                    # Admin offline: don't send audio (not even silence), but still provide local monitoring
                    if not self._admin_online:
                        if self.listen_own and self.player:
                            self.player.push(self.my_user_id or 0, original_data)
                        continue
                    
                    # Apply noise suppression before gain/mute (noise gate)
                    data = self.noise_suppressor.process(data)
                    
                    gain = self.config.get('gain', 1.0)
                    if self.mute:
                        data = b'\x00' * len(data)
                    elif gain != 1.0:
                        samples = array.array('h', data)
                        samples = array.array('h', [int(s * gain) for s in samples])
                        samples = array.array('h', [max(-32768, min(32767, s)) for s in samples])
                        data = samples.tobytes()
                        
                    compressed_data = self.compressor.compress(data)
                    encrypted_data = self.audio_encryptor.encrypt(compressed_data)
                    timestamp = time.time()
                    
                    # UDP packet format: [msg_type(1)][user_id(4)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                    header = (
                        struct.pack('!B', MSG_TYPE_AUDIO) +
                        struct.pack('!I', self.my_user_id) +
                        struct.pack('!d', timestamp) +
                        struct.pack('!I', len(encrypted_data))
                    )
                    packet = header + encrypted_data
                    
                    try:
                        self.udp_sock.sendto(packet, self.server_addr)
                    except Exception as e:
                        if self.running:
                            self._log(f"UDP发送音频失败: {e}")
                    
                    packet_count += 1
                    if packet_count <= 3:
                        self._log(f"UDP已发送第 {packet_count} 个音频包，大小: {len(packet)}")
                    
                    if self.listen_own and self.player:
                        self.player.push(self.my_user_id or 0, original_data)
                except Exception as e:
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
                        local_player.push(0, data)
                else:
                    break
            except Exception:
                if not self.local_listen_running:
                    break
                time.sleep(0.01)
            
    def _receive_loop(self):
        """Fast packet reader - reads raw packets and queues them.
        
        Decryption, decompression, and audio mixing are offloaded to
        _process_loop to keep the UDP receive buffer from filling up
        when 6+ users send 180+ packets/sec.
        """
        self._log("开始通过UDP接收音频和控制消息...")
        
        while self.running:
            if self.udp_sock is None:
                time.sleep(0.1)
                continue
            
            try:
                data, addr = self.udp_sock.recvfrom(MAX_PACKET_SIZE)
                if not data or len(data) < 1:
                    continue
                
                try:
                    self._packet_queue.put_nowait((data, addr))
                except queue.Full:
                    pass  # Drop oldest implicitly by not putting
                    
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    time.sleep(0.01)
                continue
            except Exception as e:
                if self.running:
                    self._log(f"UDP接收出错: {e}")
                time.sleep(0.1)
    
    def _process_loop(self):
        """Process packets from the queue: decrypt, decompress, mix audio.
        
        Runs in a separate thread so the receive loop never blocks on
        CPU-intensive operations like AES-GCM decryption and zlib decompression.
        """
        audio_count = 0
        
        while self.running:
            try:
                data, addr = self._packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
            self.last_packet_time = time.time()
            
            try:
                msg_type = struct.unpack('!B', data[:1])[0]
                
                if msg_type == MSG_TYPE_AUDIO:
                    # Parse audio packet: [msg_type(1)][sender_id(4)][sender_name_len(1)][sender_name(N)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                    if len(data) < 14:
                        continue
                    
                    sender_id = struct.unpack('!I', data[1:5])[0]
                    sender_name_len = struct.unpack('!B', data[5:6])[0]
                    
                    if len(data) < 6 + sender_name_len + 12:
                        continue
                    
                    sender_name = data[6:6+sender_name_len].decode('utf-8')
                    offset = 6 + sender_name_len
                    
                    encrypted_len = struct.unpack('!I', data[offset+8:offset+12])[0]
                    if len(data) < offset + 12 + encrypted_len:
                        continue
                    
                    encrypted_data = data[offset+12:offset+12+encrypted_len]
                    
                    # Check solo/mute logic
                    if self.solo_users:
                        if sender_id not in self.solo_users:
                            continue
                    else:
                        if sender_id in self.muted_users:
                            continue
                    
                    if not self.audio_encryptor:
                        continue
                    
                    audio_count += 1
                    compressed_data = self.audio_encryptor.decrypt(encrypted_data)
                    if compressed_data and self.compressor:
                        pcm_data = self.compressor.decompress(compressed_data, user_id=sender_id)
                        self._active_audio_users[sender_id] = time.time()
                        pcm_data = self._apply_user_volume(pcm_data, sender_id)
                        if self.player:
                            self.player.push(sender_id, pcm_data)
                    
                else:
                    # Control message - handle via RUDP
                    result = self.rudp_endpoint.handle_incoming(data)
                    if result is not None:
                        ctrl_msg_type, payload = result
                        self._handle_control_message(ctrl_msg_type, payload)
                        
            except Exception as e:
                if self.running:
                    self._log(f"包处理出错: {e}")
    
    def _handle_control_message(self, msg_type, payload):
        """Handle a control message received via RUDP."""
        if msg_type == MSG_TYPE_USER_LIST:
            if self.audio_encryptor:
                decrypted_data = self.audio_encryptor.decrypt(payload)
                if decrypted_data:
                    user_list = decrypted_data.decode('utf-8')
                    self.root.after(0, self._update_users, user_list)
        elif msg_type == MSG_TYPE_USER_JOINED:
            if self.audio_encryptor:
                decrypted_data = self.audio_encryptor.decrypt(payload)
                if decrypted_data:
                    event = decrypted_data.decode('utf-8')
                    self.root.after(0, self._log, f"[用户事件] {event}")
        elif msg_type == MSG_TYPE_BANNED:
            self._log("您的设备已被管理员封禁，连接将被断开")
            self._auto_reconnect = False
            self.running = False
            self.root.after(0, self._show_banned_dialog)
            self.root.after(100, self._disconnect)
        elif msg_type == MSG_TYPE_LEAVE:
            self._log("服务器要求断开连接（被踢出）")
            self._auto_reconnect = False
            self.running = False
            self.root.after(0, self._disconnect, True)  # server_initiated=True
        elif msg_type == MSG_TYPE_ADMIN_ONLINE:
            self._admin_online = True
            self.root.after(0, self._log, "管理员已上线，恢复音频传输")
            self.root.after(0, lambda: self.status_var.set(f"已连接 ({self.name})"))
            self.root.after(0, lambda: self.status_label.config(foreground="green"))
            self.root.after(0, self._update_text_allowed, True)
        elif msg_type == MSG_TYPE_ADMIN_OFFLINE:
            self._admin_online = False
            self.root.after(0, self._log, "管理员已下线，等待管理员上线...")
            self.root.after(0, lambda: self.status_var.set("管理员未在线，等待中..."))
            self.root.after(0, lambda: self.status_label.config(foreground="orange"))
            self.root.after(0, self._update_text_allowed, False)
        elif msg_type == MSG_TYPE_HEARTBEAT:
            # ACK for heartbeat, no action needed
            pass
        elif msg_type == MSG_TYPE_TEXT_MESSAGE:
            if self.audio_encryptor:
                decrypted_data = self.audio_encryptor.decrypt(payload)
                if decrypted_data:
                    text = decrypted_data.decode('utf-8')
                    self.root.after(0, self._display_text_message, text)
        else:
            self._log(f"收到未知控制消息类型: {msg_type}")
    
    def _display_text_message(self, text: str):
        """Display a text chat message in the chat panel."""
        if hasattr(self, 'chat_text') and self.chat_text.winfo_exists():
            self.chat_text.config(state=tk.NORMAL)
            self.chat_text.insert(tk.END, text + "\n")
            self.chat_text.see(tk.END)
            self.chat_text.config(state=tk.DISABLED)
    
    def _send_text_message(self, event=None):
        """Send a text chat message via RUDP."""
        if not hasattr(self, 'chat_input') or not self.chat_input.winfo_exists():
            return
        if not self.connected:
            self._log("未连接，无法发送文字消息")
            return
        if not self._text_allowed:
            self._log("文字聊天不可用（管理员未在线）")
            return
        
        text = self.chat_input.get().strip()
        if not text:
            return
        if len(text) > 200:
            self._log(f"文字消息过长（{len(text)}字符），限制200字符")
            return
        
        try:
            encrypted = self.audio_encryptor.encrypt(text.encode('utf-8'))
            self.rudp_endpoint.send_raw(MSG_TYPE_TEXT_CHAT, encrypted)
            self.chat_input.delete(0, tk.END)
        except Exception as e:
            self._log(f"发送文字消息失败: {e}")
    
    def _update_text_allowed(self, allowed: bool):
        """Update text chat input availability based on admin online status."""
        self._text_allowed = allowed
        if hasattr(self, 'chat_input') and self.chat_input.winfo_exists():
            if allowed:
                self.chat_input.config(state=tk.NORMAL)
            else:
                self.chat_input.config(state=tk.DISABLED)

    def _connection_watchdog(self):
        """Monitor connection health and trigger auto-reconnection.
        
        If no packets are received for 10 seconds, the server is
        considered dead. The watchdog triggers a full reconnection
        with exponential backoff (1s, 2s, 4s, ... up to 60s).
        
        When disconnected but auto-reconnect is enabled, the watchdog
        will keep trying to reconnect with backoff.
        """
        backoff = 1
        
        while self.running or self._auto_reconnect:
            time.sleep(2)
            
            if not self._auto_reconnect:
                if not self.running:
                    break  # User manually disconnected, stop entirely
                continue
            
            if not self.connected:
                # Disconnected state: keep trying to reconnect
                if self._reconnect_params:
                    host, port, name, password = self._reconnect_params
                    self._log(f"正在重连 {host}:{port}...")
                    self.root.after(0, lambda: self.status_var.set("正在重连..."))
                    try:
                        self._connect_thread(host, port, name, password)
                        backoff = 1  # Reset backoff on success
                    except Exception as e:
                        self._log(f"重连失败: {e}，{backoff}秒后重试...")
                        time.sleep(backoff)
                        backoff = min(backoff * 2, 60)
                continue
            
            # Normal monitoring when connected
            elapsed = time.time() - self.last_packet_time
            if elapsed > 10:
                self._log(f"服务器连接丢失（{elapsed:.0f}秒无数据），{backoff}秒后重连...")
                self.root.after(0, lambda: self.status_var.set("连接丢失，正在重连..."))
                
                # Stop current connection
                self.connected = False
                self.running = False
                
                # Wait for threads to stop
                time.sleep(1)
                
                # Cleanup
                self._cleanup()
                
                # Wait before reconnecting
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                
                # Reconnect
                if self._reconnect_params and self._auto_reconnect:
                    host, port, name, password = self._reconnect_params
                    self._log(f"正在重连 {host}:{port}...")
                    try:
                        self._connect_thread(host, port, name, password)
                        backoff = 1  # Reset backoff on success
                    except Exception as e:
                        self._log(f"重连失败: {e}")
                        self.running = True  # Keep watchdog alive for retry
            else:
                backoff = 1  # Reset backoff when connection is healthy
                
    def on_closing(self):
        if self.connected:
            self._disconnect()
        self.root.destroy()


def main():
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(2)

    name_override = None
    if '--name' in sys.argv:
        try:
            idx = sys.argv.index('--name')
            name_override = sys.argv[idx + 1]
        except (ValueError, IndexError):
            pass

    root = tk.Tk()
    app = VoiceChatGUI(root, name_override=name_override)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()