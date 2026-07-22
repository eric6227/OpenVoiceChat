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
    from tkinter import ttk, messagebox, scrolledtext, simpledialog
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

from shared import (
    get_device_fingerprint,
    AudioEncryptor, SessionKeyEncryptor,
    AudioCompressor, JitterBuffer, AudioPlayer,
    CHANNELS, RATE, CHUNK,
    MSG_TYPE_JOIN, MSG_TYPE_AUDIO, MSG_TYPE_ADMIN_JOIN,
    MSG_TYPE_USER_LIST, MSG_TYPE_USER_JOINED, MSG_TYPE_HEARTBEAT,
    MSG_TYPE_LEAVE, MSG_TYPE_AUTH_SUCCESS, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_ADMIN_BAN, MSG_TYPE_BANNED,
    MSG_TYPE_ADMIN_GET_BAN_LIST, MSG_TYPE_BAN_LIST, MSG_TYPE_ADMIN_UNBAN,
    JITTER_BUFFER_SIZE, MAX_PACKET_SIZE,
    init_audio_format,
    encrypt_password_dpapi, decrypt_password_dpapi,
    load_known_servers, save_known_servers,
    compute_server_fingerprint, verify_server_fingerprint,
)

init_audio_format(pyaudio)
FORMAT = pyaudio.paInt16

logger = logging.getLogger(__name__)


def send_heartbeat(sock, server_addr, name, is_admin=False, encryptor=None):
    """Continuously send heartbeat packets to keep the connection alive."""
    heartbeat_interval = 3
    msg_type = MSG_TYPE_HEARTBEAT
    while True:
        try:
            name_bytes = name.encode('utf-8')
            if encryptor:
                # Encrypt heartbeat data: [name]
                encrypted_data = encryptor.encrypt(name_bytes)
                heartbeat_packet = struct.pack('!B', msg_type) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                # Fallback to plaintext if no encryptor (pre-authentication)
                heartbeat_packet = struct.pack('!BI', msg_type, len(name_bytes)) + name_bytes
            sock.sendall(heartbeat_packet)
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
                elif msg_type == MSG_TYPE_BAN_LIST:
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
                        ban_list_json = decrypted_data.decode('utf-8')
                        print(f"\n[Ban List Updated] {ban_list_json}\n")
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
        self.root.title("Open Voice Chat Admin")
        self.root.resizable(True, True)
        
        # Automatically set window size to 1/3 width and 2/3 height of screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = screen_width // 3
        window_height = screen_height * 2 // 3
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
        self.user_id_map = {}  # Maps user_id -> user_name for display
        self.my_user_id = None  # Own user_id assigned by server
        self.muted_users = set()  # Set of user_ids that are muted
        self.monitoring_user_id = None  # None means monitor all, otherwise specific user_id
        
        # Threading protection
        self._connect_lock = False  # Prevent rapid connect/disconnect clicks
        self._active_threads = []  # Track active threads for cleanup
        
        # Config file path (same directory as executable)
        if getattr(sys, 'frozen', False):
            # Packaged executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Development environment
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(base_dir, 'config_admin.yaml')
        self.known_servers_file = os.path.join(base_dir, 'known_servers_admin.json')
        self._load_config()
        self.known_servers = self._load_known_servers()
        
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
            f"2. 音频录制提示:\n"
            f"   服务器可能会录制用户的音频通话内容\n\n"
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
        
        # Online users frame with notebook (tabs)
        notebook_frame = ttk.LabelFrame(main_frame, text="管理面板", padding="10")
        notebook_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Online users
        users_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(users_tab, text="在线用户")
        
        # Create a scrollable frame for user list
        users_container = ttk.Frame(users_tab)
        users_container.pack(fill=tk.BOTH, expand=True)
        
        # Scrollable area - header and rows share the same grid
        users_canvas = tk.Canvas(users_container, highlightthickness=0)
        users_scrollbar = ttk.Scrollbar(users_container, orient="vertical", command=users_canvas.yview)
        self.users_scroll_frame = ttk.Frame(users_canvas)
        
        self.users_scroll_frame.bind(
            "<Configure>",
            lambda e: users_canvas.configure(scrollregion=users_canvas.bbox("all"))
        )
        
        users_canvas.create_window((0, 0), window=self.users_scroll_frame, anchor="nw")
        users_canvas.configure(yscrollcommand=users_scrollbar.set)
        
        users_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Column widths in pixels
        col_username = 120
        col_s = 40
        col_m = 40
        col_device = 100
        col_ip = 120
        col_fp = 250
        
        # Configure scroll frame columns
        self.users_scroll_frame.columnconfigure(0, minsize=col_username, weight=0)
        self.users_scroll_frame.columnconfigure(1, minsize=col_s, weight=0)
        self.users_scroll_frame.columnconfigure(2, minsize=col_m, weight=0)
        self.users_scroll_frame.columnconfigure(3, minsize=col_device, weight=0)
        self.users_scroll_frame.columnconfigure(4, minsize=col_ip, weight=0)
        self.users_scroll_frame.columnconfigure(5, minsize=col_fp, weight=0)
        
        # Store column widths and starting row for user data
        self._col_widths = (col_username, col_s, col_m, col_device, col_ip, col_fp)
        self._user_row_start = 1  # Row 0 is header
        
        # Header row (row 0 in scrollable frame)
        ttk.Label(self.users_scroll_frame, text="用户", font=('', 9, 'bold'), anchor=tk.W).grid(row=0, column=0, sticky=tk.W, padx=(5, 0), pady=2)
        ttk.Label(self.users_scroll_frame, text="S", font=('', 9, 'bold'), anchor=tk.CENTER).grid(row=0, column=1, sticky=tk.EW, padx=2, pady=2)
        ttk.Label(self.users_scroll_frame, text="M", font=('', 9, 'bold'), anchor=tk.CENTER).grid(row=0, column=2, sticky=tk.EW, padx=2, pady=2)
        ttk.Label(self.users_scroll_frame, text="音量", font=('', 9, 'bold'), anchor=tk.CENTER).grid(row=0, column=3, padx=2, pady=2)
        ttk.Label(self.users_scroll_frame, text="", font=('', 9, 'bold'), anchor=tk.CENTER).grid(row=0, column=4, padx=2, pady=2)
        ttk.Label(self.users_scroll_frame, text="设备ID", font=('', 9, 'bold'), anchor=tk.W).grid(row=0, column=5, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.users_scroll_frame, text="IP地址", font=('', 9, 'bold'), anchor=tk.W).grid(row=0, column=6, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.users_scroll_frame, text="硬件指纹", font=('', 9, 'bold'), anchor=tk.W).grid(row=0, column=7, sticky=tk.W, padx=5, pady=2)
        
        # Track solo and mute states
        self.solo_users = set()
        self.muted_users = set()
        self.user_volumes = {}  # Volume per user_id: {user_id: volume_value}
        self.user_buttons = {}  # Store button references
        self.selected_user_id = None
        
        # Ban button frame
        ban_frame = ttk.Frame(users_tab)
        ban_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.ban_btn = ttk.Button(ban_frame, text="封禁选中用户", command=self._ban_selected_user, state=tk.DISABLED)
        self.ban_btn.pack(side=tk.LEFT, padx=5)
        
        self.selected_user_var = tk.StringVar(value="未选择用户")
        ttk.Label(ban_frame, textvariable=self.selected_user_var).pack(side=tk.LEFT, padx=10)
        
        # Tab 2: Ban list
        banlist_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(banlist_tab, text="封禁列表")
        
        # Ban list treeview with scrollbar
        banlist_tree_frame = ttk.Frame(banlist_tab)
        banlist_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.ban_tree = ttk.Treeview(
            banlist_tree_frame,
            columns=("device", "names", "ips", "fingerprints", "banned_by", "banned_at", "expires_at", "reason"),
            show="headings",
            height=12
        )
        
        self.ban_tree.heading("device", text="设备ID")
        self.ban_tree.heading("names", text="关联昵称")
        self.ban_tree.heading("ips", text="关联IP")
        self.ban_tree.heading("fingerprints", text="硬件指纹")
        self.ban_tree.heading("banned_by", text="封禁管理员")
        self.ban_tree.heading("banned_at", text="封禁时间")
        self.ban_tree.heading("expires_at", text="过期时间")
        self.ban_tree.heading("reason", text="封禁原因")
        
        self.ban_tree.column("device", width=120)
        self.ban_tree.column("names", width=150)
        self.ban_tree.column("ips", width=180)
        self.ban_tree.column("fingerprints", width=250)
        self.ban_tree.column("banned_by", width=120)
        self.ban_tree.column("banned_at", width=140)
        self.ban_tree.column("expires_at", width=140)
        self.ban_tree.column("reason", width=180)
        
        # Set row height to avoid overlapping content
        style = ttk.Style()
        style.configure("Treeview", rowheight=30)
        
        banlist_scrollbar = ttk.Scrollbar(banlist_tree_frame, orient=tk.VERTICAL, command=self.ban_tree.yview)
        self.ban_tree.configure(yscrollcommand=banlist_scrollbar.set)
        
        self.ban_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        banlist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind click to select ban entry
        self.ban_tree.bind('<<TreeviewSelect>>', self._on_ban_select)
        
        # Unban button frame
        unban_frame = ttk.Frame(banlist_tab)
        unban_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.unban_btn = ttk.Button(unban_frame, text="一键解封选中设备", command=self._unban_selected, state=tk.DISABLED)
        self.unban_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_ban_btn = ttk.Button(unban_frame, text="刷新封禁列表", command=self._refresh_ban_list)
        self.refresh_ban_btn.pack(side=tk.LEFT, padx=5)
        
        self.selected_ban_var = tk.StringVar(value="未选择设备")
        ttk.Label(unban_frame, textvariable=self.selected_ban_var).pack(side=tk.LEFT, padx=10)
        
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
            except socket.timeout:
                return None
            except BlockingIOError:
                # Non-blocking mode: no data available, wait a bit
                import time
                time.sleep(0.01)
                continue
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
        # Parse user list from message: "Users: [ID:1] user1 [Device:xxx] [IP:xxx] [FP:xxx], [ID:2] user2 ..."
        self.user_id_map.clear()
        self.user_buttons.clear()
        
        # Clear scroll frame (keep header at row 0)
        for widget in self.users_scroll_frame.winfo_children():
            info = widget.grid_info()
            if info and info.get('row', 0) > 0:
                widget.destroy()
        
        if message.startswith("Users: "):
            users_str = message[7:]
            # Split by ", [ID:" to get each user
            users = [u.strip() for u in users_str.split(", [ID:") if u.strip()]
            if users and not users[0].startswith("[ID:"):
                # First user doesn't have the split prefix
                users[0] = "[ID:" + users[0]
            
            row_idx = self._user_row_start
            for user in users:
                if not user.startswith("[ID:"):
                    continue
                    
                try:
                    end_bracket = user.index("]")
                    user_id = int(user[4:end_bracket])
                    rest = user[end_bracket+1:].strip()
                    
                    # Parse username
                    if '[' in rest:
                        username = rest[:rest.index('[')].strip()
                    else:
                        username = rest
                    
                    self.user_id_map[user_id] = username
                    
                    # Skip self from display
                    if self.my_user_id is not None and user_id == self.my_user_id:
                        continue
                    
                    # Extract device ID, IP, and fingerprint
                    device_id = ""
                    ip_addr = ""
                    fingerprint = ""
                    
                    # Parse [Device:xxx]
                    if '[Device:' in rest:
                        dev_start = rest.index('[Device:') + 8
                        dev_end = rest.index(']', dev_start)
                        device_id = rest[dev_start:dev_end]
                    
                    # Parse [IP:xxx]
                    if '[IP:' in rest:
                        ip_start = rest.index('[IP:') + 4
                        ip_end = rest.index(']', ip_start)
                        ip_addr = rest[ip_start:ip_end]
                    
                    # Parse [FP:xxx]
                    if '[FP:' in rest:
                        fp_start = rest.index('[FP:') + 4
                        fp_end = rest.index(']', fp_start)
                        fingerprint = rest[fp_start:fp_end]
                    
                    # Place widgets directly on scroll_frame using grid for alignment
                    # Username label (clickable for selection)
                    name_label = tk.Label(self.users_scroll_frame, text=username, anchor=tk.W, cursor="hand2")
                    name_label.grid(row=row_idx, column=0, sticky=tk.W, padx=(5, 0), pady=1)
                    name_label.bind('<Button-1>', lambda e, uid=user_id, uname=username: self._select_user(uid, uname))
                    
                    # Solo button
                    solo_active = user_id in self.solo_users
                    solo_bg = "#228B22" if solo_active else "#90EE90"
                    solo_btn = tk.Button(self.users_scroll_frame, text="S", bg=solo_bg, width=3, height=1,
                                       command=lambda uid=user_id, uname=username: self._toggle_solo(uid, uname))
                    solo_btn.grid(row=row_idx, column=1, sticky=tk.EW, padx=2, pady=1)
                    
                    # Mute button
                    mute_active = user_id in self.muted_users
                    mute_bg = "#CC0000" if mute_active else "#FFB6C1"
                    mute_btn = tk.Button(self.users_scroll_frame, text="M", bg=mute_bg, width=3, height=1,
                                       command=lambda uid=user_id, uname=username: self._toggle_mute(uid, uname))
                    mute_btn.grid(row=row_idx, column=2, sticky=tk.EW, padx=2, pady=1)
                    
                    # Volume slider
                    user_volume = self.user_volumes.get(user_id, 1.0)
                    volume_var = tk.DoubleVar(value=user_volume)
                    volume_scale = ttk.Scale(self.users_scroll_frame, from_=0.0, to=2.0, variable=volume_var, orient=tk.HORIZONTAL)
                    volume_scale.grid(row=row_idx, column=3, padx=2, pady=1)
                    volume_label = ttk.Label(self.users_scroll_frame, text=f"{user_volume:.1f}", width=3)
                    volume_label.grid(row=row_idx, column=4, padx=2, pady=1)
                    volume_var.trace('w', lambda *args, uid=user_id, uname=username: self._on_user_volume_change(uid, uname))
                    
                    # Device ID label
                    ttk.Label(self.users_scroll_frame, text=device_id, anchor=tk.W).grid(row=row_idx, column=5, sticky=tk.W, padx=5, pady=1)
                    
                    # IP address label
                    ttk.Label(self.users_scroll_frame, text=ip_addr, anchor=tk.W).grid(row=row_idx, column=6, sticky=tk.W, padx=5, pady=1)
                    
                    # Fingerprint label
                    ttk.Label(self.users_scroll_frame, text=fingerprint, anchor=tk.W).grid(row=row_idx, column=7, sticky=tk.W, padx=5, pady=1)
                    
                    # Store button references
                    self.user_buttons[user_id] = {
                        "solo": solo_btn, 
                        "mute": mute_btn, 
                        "name_label": name_label,
                        "volume_var": volume_var,
                        "volume_scale": volume_scale,
                        "volume_label": volume_label
                    }
                    
                    row_idx += 1
                    
                except (ValueError, IndexError):
                    pass
        else:
            ttk.Label(self.users_scroll_frame, text=message, foreground="gray").grid(row=self._user_row_start, column=0, columnspan=8, pady=10)
    
    def _extract_username(self, user_text: str) -> str:
        """Extract username from user list text format: [ID:123] username [...]"""
        if '] ' in user_text:
            # Format: [ID:123] username [...]
            rest = user_text[user_text.index('] ')+2:].strip()
            if '[' in rest:
                return rest[:rest.index('[')].strip()
            else:
                return rest
        else:
            return user_text.strip()
    
    def _select_user(self, user_id, username):
        """Handle user selection for ban."""
        self.selected_user_id = user_id
        self.selected_user_var.set(f"已选择: {username}")
        self.ban_btn.config(state=tk.NORMAL)
        
        # Highlight selected user name
        for uid, btns in self.user_buttons.items():
            if uid == user_id:
                btns["name_label"].config(foreground="blue", font=('', 9, 'bold'))
            else:
                btns["name_label"].config(foreground="black", font=('', 9, 'normal'))
    
    def _toggle_solo(self, user_id, username):
        """Toggle solo mode for a user."""
        if user_id in self.solo_users:
            self.solo_users.discard(user_id)
            self._log(f"已取消独听用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["solo"].config(bg="#90EE90")
        else:
            # Mute has higher priority: if user is muted, unmute first
            if user_id in self.muted_users:
                self.muted_users.discard(user_id)
                if user_id in self.user_buttons:
                    self.user_buttons[user_id]["mute"].config(bg="#FFB6C1")
            self.solo_users.add(user_id)
            self._log(f"已设置独听用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["solo"].config(bg="#228B22")
    
    def _toggle_mute(self, user_id, username):
        """Toggle mute mode for a user. Mute has higher priority than solo."""
        if user_id in self.muted_users:
            self.muted_users.discard(user_id)
            self._log(f"已取消静音用户: {username}")
            if user_id in self.user_buttons:
                self.user_buttons[user_id]["mute"].config(bg="#FFB6C1")
        else:
            # Mute has higher priority: remove from solo when muting
            if user_id in self.solo_users:
                self.solo_users.discard(user_id)
                if user_id in self.user_buttons:
                    self.user_buttons[user_id]["solo"].config(bg="#90EE90")
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
    
    def _ban_selected_user(self):
        """Ban the selected user."""
        if not hasattr(self, 'selected_user_id') or self.selected_user_id is None:
            messagebox.showwarning("警告", "请先选择一个用户")
            return
        
        user_id = self.selected_user_id
        username = self.user_id_map.get(user_id, f"ID:{user_id}")
        
        # Show ban reason dialog
        reason = simpledialog.askstring(
            "封禁用户",
            f"确定要封禁用户 '{username}' 吗？\n\n请输入封禁原因（可选）：",
            parent=self.root
        )
        
        if reason is None:  # User cancelled
            return
        
        reason = reason.strip() if reason else ""
        
        # Send ban command to server
        if not self.sock_audio:
            messagebox.showerror("错误", "未连接到服务器")
            return
        
        try:
            target_name_bytes = username.encode('utf-8')
            reason_bytes = reason.encode('utf-8')
            
            ban_data = (
                struct.pack('!I', len(target_name_bytes)) + target_name_bytes +
                struct.pack('!I', len(reason_bytes)) + reason_bytes
            )
            
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(ban_data)
                ban_packet = struct.pack('!B', MSG_TYPE_ADMIN_BAN) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                ban_packet = struct.pack('!B', MSG_TYPE_ADMIN_BAN) + struct.pack('!I', len(ban_data)) + ban_data
            
            self.sock_audio.sendall(ban_packet)
            self._log(f"已发送封禁命令: 用户 '{username}' (原因: {reason or '无'})")
            
            # Clear selection
            self.selected_user_id = None
            self.selected_user_var.set("未选择用户")
            self.ban_btn.config(state=tk.DISABLED)
            # Reset name label highlighting
            for uid, btns in self.user_buttons.items():
                btns["name_label"].config(foreground="black", font=('', 9, 'normal'))
            
        except Exception as e:
            self._log(f"发送封禁命令失败: {e}")
            messagebox.showerror("错误", f"发送封禁命令失败: {e}")
    
    def _extract_user_id(self, user_text: str) -> int:
        """Extract user_id from user list text format: [ID:123] username [...]"""
        if user_text.startswith("[ID:"):
            try:
                end_bracket = user_text.index("]")
                return int(user_text[4:end_bracket])
            except (ValueError, IndexError):
                pass
        return None
    
    def _on_ban_select(self, event):
        """Handle ban list selection."""
        selection = self.ban_tree.selection()
        if selection:
            item = self.ban_tree.item(selection[0])
            device_id = item['values'][0]
            self.selected_ban_var.set(f"已选中: {device_id[:32]}...")
            self.unban_btn.config(state=tk.NORMAL)
        else:
            self.selected_ban_var.set("未选择设备")
            self.unban_btn.config(state=tk.DISABLED)
    
    def _refresh_ban_list(self):
        """Request ban list from server."""
        if not self.sock_audio:
            messagebox.showwarning("警告", "请先连接服务器")
            return
        
        try:
            # Send request: [msg_type(1)][encrypted_len(4)][encrypted_data]
            request_data = b''
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(request_data)
                request_packet = struct.pack('!B', MSG_TYPE_ADMIN_GET_BAN_LIST) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                request_packet = struct.pack('!B', MSG_TYPE_ADMIN_GET_BAN_LIST) + struct.pack('!I', len(request_data)) + request_data
            self.sock_audio.sendall(request_packet)
            self._log("已请求刷新封禁列表")
        except Exception as e:
            self._log(f"发送请求失败: {e}")
    
    def _update_ban_list(self, ban_list_data):
        """Update ban list UI with data from server."""
        # Clear existing entries
        for item in self.ban_tree.get_children():
            self.ban_tree.delete(item)
        
        # Add new entries
        for device in ban_list_data:
            device_id = device.get("device_id", "")
            names = ", ".join(device.get("names", [])) or "无"
            ips = ", ".join(device.get("ips", [])) or "无"
            
            # Format fingerprints: group hardware and IP separately
            fps = device.get("fingerprints", [])
            hw_fps = [fp for fp in fps if fp['type'] != 'ip']
            ip_fps = [fp for fp in fps if fp['type'] == 'ip']
            
            # Hardware fingerprints summary
            hw_parts = []
            for fp in hw_fps:
                fp_str = f"{fp['type']}:{fp['value_short']}"
                hw_parts.append(fp_str)
            
            # Add IP info to hardware fingerprints if present
            if ip_fps:
                ip_count = len(ip_fps)
                # Show IP expiration info
                has_expiry = any(fp.get("expires_at") for fp in ip_fps)
                ip_label = f"[{ip_count}个IP{'(7天过期)' if has_expiry else ''}]"
                fp_summary = ", ".join(hw_parts) + " " + ip_label if hw_parts else ip_label
            else:
                fp_summary = ", ".join(hw_parts) if hw_parts else "无"
            
            banned_by = device.get("banned_by", "未知")
            banned_at = device.get("first_banned", "未知")
            reason = hw_fps[0].get("reason", "无") if hw_fps else (ip_fps[0].get("reason", "无") if ip_fps else "无")
            
            # Get expiration time: show earliest IP expiration if present
            expires_at = ""
            if ip_fps:
                # Find earliest expiration time among IPs
                expiry_times = [fp.get("expires_at") for fp in ip_fps if fp.get("expires_at")]
                if expiry_times:
                    expires_at = min(expiry_times)
            
            if not expires_at:
                expires_at = "永久"
            
            display_id = device_id[:32] + "..." if len(device_id) > 32 else device_id
            
            # Use full device_id as the tree item iid for retrieval during unban
            self.ban_tree.insert("", tk.END, iid=device_id, values=(
                display_id,
                names,
                ips,
                fp_summary,
                banned_by,
                banned_at,
                expires_at,
                reason
            ))
        
        self._log(f"封禁列表已更新: {len(ban_list_data)} 个设备")
    
    def _unban_selected(self):
        """Unban the selected device."""
        selection = self.ban_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # Use the item's iid (which stores the full device_id)
        device_id = selection[0]
        
        # Confirm unban
        if not messagebox.askyesno("确认解封", f"确定要解封设备 '{device_id}' 吗？\n\n解封后该设备的所有硬件指纹将不再被封禁。"):
            return
        
        if not self.sock_audio:
            messagebox.showerror("错误", "未连接到服务器")
            return
        
        try:
            # Send unban command: [msg_type(1)][encrypted_len(4)][encrypted_data]
            device_key_bytes = device_id.encode('utf-8')
            unban_data = struct.pack('!I', len(device_key_bytes)) + device_key_bytes
            
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(unban_data)
                unban_packet = struct.pack('!B', MSG_TYPE_ADMIN_UNBAN) + struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                unban_packet = struct.pack('!B', MSG_TYPE_ADMIN_UNBAN) + struct.pack('!I', len(unban_data)) + unban_data
            
            self.sock_audio.sendall(unban_packet)
            self._log(f"已发送解封命令: 设备 '{device_id}'")
            
            # Clear selection
            self.ban_tree.selection_remove(selection[0])
            self.selected_ban_var.set("未选择设备")
            self.unban_btn.config(state=tk.DISABLED)
            
        except Exception as e:
            self._log(f"发送解封命令失败: {e}")
            messagebox.showerror("错误", f"发送解封命令失败: {e}")
        
    def _toggle_connection(self):
        """Toggle between connect and disconnect."""
        if not self.connected:
            self._connect()
        else:
            self._disconnect()
            
    def _connect(self):
        """Validate inputs and initiate connection."""
        # Prevent rapid clicking
        if self._connect_lock:
            return
        
        self._connect_lock = True
        
        try:
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
        except Exception as e:
            self._log(f"连接初始化失败: {e}")
        finally:
            self._connect_lock = False
        
    def _connect_thread(self, host, port, name, password, volume):
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
            self.sock_audio.connect((host, port))
            
            # Step 2: Receive RSA public key from server
            pub_key_len_data = self._recv_exact(4)
            if not pub_key_len_data:
                self.root.after(0, self._connect_failed, "服务器响应格式错误")
                return
            
            pub_key_len = struct.unpack('!I', pub_key_len_data)[0]
            public_key_bytes = self._recv_exact(pub_key_len)
            if not public_key_bytes:
                self.root.after(0, self._connect_failed, "服务器公钥接收失败")
                return
            
            # Step 3: Close temporary connection before showing fingerprint dialog
            self.sock_audio.close()
            self.sock_audio = None
            self.root.after(0, self._log, "等待用户确认服务器指纹...")
            
            # Step 4: Verify server fingerprint (SSH-style trust)
            server_addr = f"{host}:{port}"
            if not self._verify_server_fingerprint(server_addr, public_key_bytes):
                self.root.after(0, self._connect_failed, "服务器指纹验证失败，连接已终止")
                return
            
            # Step 5: User approved, establish actual connection
            self.sock_audio = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_audio.settimeout(10)
            self.sock_audio.connect((host, port))
            # Keep blocking mode with timeout for handshake
            
            # Step 6: Receive RSA public key again (new connection)
            pub_key_len_data = self._recv_exact(4)
            if not pub_key_len_data:
                self.root.after(0, self._connect_failed, "服务器响应格式错误")
                return
            
            pub_key_len = struct.unpack('!I', pub_key_len_data)[0]
            public_key_bytes = self._recv_exact(pub_key_len)
            if not public_key_bytes:
                self.root.after(0, self._connect_failed, "服务器公钥接收失败")
                return
            
            # Step 7: Encrypt password with RSA public key
            public_key = RSA.import_key(public_key_bytes)
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_password = cipher.encrypt(password.encode('utf-8'))
            
            # Step 8: Get device fingerprints
            device_fingerprints = get_device_fingerprint()
            
            # Step 9: Send JOIN packet with encrypted password and device fingerprints
            name_bytes = name.encode('utf-8')
            fingerprints_json = json.dumps(device_fingerprints).encode('utf-8')
            join_packet = (
                struct.pack('!BI', MSG_TYPE_ADMIN_JOIN, len(name_bytes)) + name_bytes +
                struct.pack('!I', len(encrypted_password)) + encrypted_password +
                struct.pack('!I', len(fingerprints_json)) + fingerprints_json
            )
            self.sock_audio.sendall(join_packet)
            
            # Set timeout for receiving response
            self.sock_audio.settimeout(15)
            try:
                response_type_data = self._recv_exact(1)
                if not response_type_data:
                    self.root.after(0, self._connect_failed, "服务器无响应，连接超时")
                    return
            except socket.timeout:
                self.root.after(0, self._connect_failed, "等待服务器响应超时")
                return
            
            response_type = struct.unpack('!B', response_type_data[:1])[0]
            
            if response_type == MSG_TYPE_AUTH_FAIL:
                self.root.after(0, self._connect_failed, "密码错误，身份验证失败")
                return
            elif response_type == MSG_TYPE_AUTH_SUCCESS:
                # Format: [salt(32)][nonce(12)][tag(16)][encrypted_session_key(32)][user_id(4)]
                response_data = self._recv_exact(96)
                if not response_data or len(response_data) < 96:
                    self.root.after(0, self._connect_failed, "服务器响应格式错误")
                    return
                
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
            self._active_threads.append(receive_thread)
            
            # Start heartbeat thread to keep connection alive
            heartbeat_thread = threading.Thread(target=self._send_heartbeat, daemon=True)
            heartbeat_thread.start()
            self._active_threads.append(heartbeat_thread)
            
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
        self._log("管理员可监听所有用户的语音，点击用户列表中的 S 按钮可独听，点击 M 按钮可静音。")
        
        # Reset solo and mute state
        self.solo_users.clear()
        self.muted_users.clear()
        self.selected_user_id = None
        
        # Auto-request ban list after connecting
        self.root.after(500, self._refresh_ban_list)
        
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
                if self.audio_encryptor:
                    # Encrypt leave data
                    encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                    leave_packet = struct.pack('!B', MSG_TYPE_LEAVE) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                else:
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
        # Stop running flag first to signal threads to exit
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
        
        # Reset monitoring, solo and mute state
        self.user_id_map.clear()
        self.solo_users.clear()
        self.muted_users.clear()
        self.monitoring_user_id = None
            
    def _send_heartbeat(self):
        """Send heartbeat packets to server to keep connection alive."""
        import time
        while self.running and self.connected:
            try:
                if self.sock_audio and self.name:
                    name_bytes = self.name.encode('utf-8')
                    if self.audio_encryptor:
                        # Encrypt heartbeat data
                        encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                        heartbeat_packet = struct.pack('!B', MSG_TYPE_HEARTBEAT) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                    else:
                        # Fallback to plaintext
                        heartbeat_packet = struct.pack('!BI', MSG_TYPE_HEARTBEAT, len(name_bytes)) + name_bytes
                    self.sock_audio.sendall(heartbeat_packet)
                time.sleep(3)
            except Exception:
                time.sleep(3)
                
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
                        # New format for admin: [msg_type(1)][sender_id(4)][sender_name_len(1)][sender_name(N)][timestamp(8)][encrypted_len(4)][encrypted_audio]
                        if len(buffer) < 14:  # 1 + 4 + 1 + 8 + 4 minimum
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
                        
                        packet_count += 1
                        if packet_count <= 3:
                            self._log(f"收到第 {packet_count} 个音频包 [ID:{sender_id}] {sender_name}，大小: {len(encrypted_data)}")
                        
                        # Check mute first: mute has highest priority, even over solo
                        if sender_id in self.muted_users:
                            if packet_count <= 3:
                                self._log(f"跳过静音用户 [{sender_id}] {sender_name} 的音频")
                            continue

                        # If there are solo users, only play their audio
                        if self.solo_users:
                            if sender_id not in self.solo_users:
                                if packet_count <= 3:
                                    self._log(f"跳过非独听用户 [{sender_id}] {sender_name} 的音频")
                                continue

                        # Check if we should play this audio based on monitoring target
                        if self.monitoring_user_id is not None and sender_id != self.monitoring_user_id:
                            if packet_count <= 3:
                                self._log(f"跳过非监听用户 [{sender_id}] {sender_name} 的音频")
                            continue
                        
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
                                user_list_data = decrypted_data.decode('utf-8')
                                self.root.after(0, self._update_users, user_list_data)
                    elif msg_type == MSG_TYPE_BAN_LIST:
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
                                try:
                                    ban_list_data = json.loads(decrypted_data.decode('utf-8'))
                                    self.root.after(0, self._update_ban_list, ban_list_data)
                                except Exception as e:
                                    self._log(f"解析封禁列表失败: {e}")
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
                                event_data = decrypted_data.decode('utf-8')
                                self.root.after(0, self._log, f"[用户事件] {event_data}")
                    else:
                        buffer = buffer[1:]
            except ConnectionResetError:
                self._log("连接被服务器重置")
                break
            except BlockingIOError:
                # Non-blocking socket has no data available, this is normal
                time.sleep(0.01)
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
        print("\n2. 音频录制提示:")
        print("   服务器可能会录制您的音频通话内容")
        print("   （具体取决于服务器配置）")
        print("\n3. 同意声明:")
        print("   继续连接即表示您同意上述数据收集和使用")
        print("\n4. 免责声明:")
        print("   本软件基于MIT许可证发布，不提供任何担保。")
        print("   开发者不对因使用本软件造成的任何后果承担责任。")
        print("   请遵守当地法律法规，不当使用造成的后果由使用者自行承担。")
        print("\n" + "="*60)
        print(f"\n服务器公钥指纹 (SHA-256):\n  {fingerprint}\n")
        
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
        struct.pack('!BI', MSG_TYPE_ADMIN_JOIN, len(name_bytes)) + name_bytes +
        struct.pack('!I', len(encrypted_password)) + encrypted_password +
        struct.pack('!I', len(fingerprints_json)) + fingerprints_json
    )
    sock.sendall(join_packet)
    
    response_data = b''
    while len(response_data) < 93:
        chunk = sock.recv(93 - len(response_data))
        if not chunk:
            logger.error("服务器响应不完整")
            sock.close()
            return
        response_data += chunk
    
    if len(response_data) < 93:
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
    
    nonce = response_data[33:45]
    tag = response_data[45:61]
    encrypted_session_key = response_data[61:93]
    
    salt = response_data[1:33]
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
    
    # Start heartbeat thread
    def send_heartbeat_cli():
        while True:
            try:
                name_bytes = name.encode('utf-8')
                if audio_encryptor:
                    # Encrypt heartbeat data
                    encrypted_data = audio_encryptor.encrypt(name_bytes)
                    heartbeat_packet = struct.pack('!B', MSG_TYPE_HEARTBEAT) + struct.pack('!I', len(encrypted_data)) + encrypted_data
                else:
                    # Fallback to plaintext
                    heartbeat_packet = struct.pack('!BI', MSG_TYPE_HEARTBEAT, len(name_bytes)) + name_bytes
                sock.sendall(heartbeat_packet)
                time.sleep(3)
            except Exception:
                time.sleep(3)
    
    heartbeat_thread = threading.Thread(target=send_heartbeat_cli, daemon=True)
    heartbeat_thread.start()

    try:
        while receive_thread.is_alive():
            receive_thread.join(timeout=0.5)
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