import socket
import threading
import struct
import sys
import logging
import time
import os
import hashlib
import argparse
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
from tkinter import ttk, messagebox, scrolledtext, simpledialog

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
    MSG_TYPE_ADMIN_KICK,
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


class AdminGUI:
    """Main GUI class for the voice chat admin."""
    def __init__(self, root):
        self.root = root
        self.root.title("Open Voice Chat Admin")
        self.root.resizable(True, True)
        
        # Automatically set window size to 1/3 width and 3/4 height of screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = screen_width // 3
        window_height = screen_height * 3 // 4
        self.root.geometry(f"{window_width}x{window_height}")
        
        self.connected = False
        self.running = False
        
        self.sock_audio = None  # Will be replaced by udp_sock
        self.sock_signal = None  # No longer used
        self.udp_sock = None  # Single UDP socket for all communication
        self.rudp_endpoint = None  # RUDP endpoint for reliable control messages
        self.server_addr = None  # (host, port) of server's UDP port
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
        self.last_packet_time = 0  # Timestamp of last received packet
        self._auto_reconnect = True  # Auto-reconnect on server disconnect
        self._reconnect_params = None  # (host, port, name, password, volume) for reconnection
        self.monitoring_user_id = None  # None means monitor all, otherwise specific user_id
        self._packet_queue = None  # Queue for decoupling recv from processing
        
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
        
        # Header row (uses pack, same as user rows)
        header_frame = ttk.Frame(self.users_scroll_frame)
        header_frame.pack(fill=tk.X, pady=2, padx=2)
        ttk.Label(header_frame, text="用户", font=('', 9, 'bold'), width=12, anchor=tk.W).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Label(header_frame, text="S", font=('', 9, 'bold'), width=2).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="M", font=('', 9, 'bold'), width=2).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="音量", font=('', 9, 'bold'), width=4).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="", font=('', 9, 'bold'), width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="设备ID", font=('', 9, 'bold'), width=18, anchor=tk.W).pack(side=tk.LEFT, padx=5)
        ttk.Label(header_frame, text="IP地址", font=('', 9, 'bold'), width=15, anchor=tk.W).pack(side=tk.LEFT, padx=5)
        ttk.Label(header_frame, text="硬件指纹", font=('', 9, 'bold'), anchor=tk.W).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Track solo and mute states
        self.solo_users = set()
        self.muted_users = set()
        self.user_volumes = {}  # Volume per user_id: {user_id: volume_value}
        self._active_audio_users = {}  # user_id -> last_audio_time for volume normalization
        self.user_buttons = {}  # Store button references
        self.selected_user_id = None
        
        # Ban button frame
        ban_frame = ttk.Frame(users_tab)
        ban_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.ban_btn = ttk.Button(ban_frame, text="封禁选中用户", command=self._ban_selected_user, state=tk.DISABLED)
        self.ban_btn.pack(side=tk.LEFT, padx=5)
        
        self.kick_btn = ttk.Button(ban_frame, text="踢出选中用户", command=self._kick_selected_user, state=tk.DISABLED)
        self.kick_btn.pack(side=tk.LEFT, padx=5)
        
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
        """Update the online users list display incrementally.
        
        Only adds new users and removes departed users. Users that
        remain unchanged are not refreshed, preventing UI flicker.
        """
        try:
            new_user_list = json.loads(message)
            new_ids = set()
            new_user_data = {}
            
            # Build new user set
            for user in new_user_list:
                user_id = user["id"]
                new_ids.add(user_id)
                new_user_data[user_id] = user
            
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
                user = new_user_data[user_id]
                username = user["name"]
                self.user_id_map[user_id] = username
                self._add_user_row(user_id, user)
            
            # Update user_id_map with latest names
            self.user_id_map.clear()
            for user_id, user in new_user_data.items():
                self.user_id_map[user_id] = user["name"]
            
            # Show/hide "no users" label
            has_visible_users = any(
                uid != self.my_user_id for uid in self.user_id_map
            ) if self.user_id_map else False
            self._update_empty_label(has_visible_users)
            
        except Exception:
            ttk.Label(self.users_scroll_frame, text=message, foreground="gray").pack(pady=10)
    
    def _clear_user_list(self):
        """Clear all user rows from the display."""
        for user_id in list(self.user_buttons.keys()):
            buttons = self.user_buttons[user_id]
            if "row_frame" in buttons:
                try:
                    buttons["row_frame"].destroy()
                except Exception:
                    pass
        self.user_buttons.clear()
        self.user_id_map.clear()
        self._update_empty_label(False)
    
    def _add_user_row(self, user_id, user):
        """Add a single user row to the admin display."""
        username = user["name"]
        ip_addr = user.get("ip", "")
        fingerprints = user.get("fingerprints", {})
        device_id = fingerprints.get("mac", "")[:16] if fingerprints.get("mac") else ""
        fingerprint = ", ".join(f"{k}: {v}" for k, v in fingerprints.items())
        
        row_frame = ttk.Frame(self.users_scroll_frame)
        row_frame.pack(fill=tk.X, pady=1, padx=2)
        
        # Username label (clickable for selection)
        name_label = tk.Label(row_frame, text=username, anchor=tk.W, cursor="hand2", width=12)
        name_label.pack(side=tk.LEFT, padx=(5, 0))
        name_label.bind('<Button-1>', lambda e, uid=user_id, uname=username: self._select_user(uid, uname))
        
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
        volume_scale.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        volume_label = ttk.Label(row_frame, text=f"{user_volume:.1f}", width=3)
        volume_label.pack(side=tk.LEFT, padx=2)
        volume_var.trace('w', lambda *args, uid=user_id, uname=username: self._on_user_volume_change(uid, uname))
        
        # Device ID label
        ttk.Label(row_frame, text=device_id, anchor=tk.W, width=18).pack(side=tk.LEFT, padx=5)
        
        # IP address label
        ttk.Label(row_frame, text=ip_addr, anchor=tk.W, width=15).pack(side=tk.LEFT, padx=5)
        
        # Fingerprint label
        ttk.Label(row_frame, text=fingerprint, anchor=tk.W).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Store button references
        self.user_buttons[user_id] = {
            "solo": solo_btn,
            "mute": mute_btn,
            "name_label": name_label,
            "volume_var": volume_var,
            "volume_scale": volume_scale,
            "volume_label": volume_label,
            "row_frame": row_frame
        }
    
    def _update_empty_label(self, has_visible_users):
        """Show or hide the 'no users online' label."""
        for widget in self.users_scroll_frame.winfo_children():
            if isinstance(widget, ttk.Label) and widget.cget("text") == "(暂无用户在线)":
                if has_visible_users:
                    widget.pack_forget()
                return
        
        if not has_visible_users:
            ttk.Label(self.users_scroll_frame, text="(暂无用户在线)", foreground="gray").pack(pady=10)
    
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
        self.kick_btn.config(state=tk.NORMAL)
        
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
        """Apply per-user volume to audio data with active speaker normalization.
        
        actual_volume = volume_setting * (1 / unmuted_active_speaker_count)
        Clean up stale speakers (no audio for >2 seconds).
        Only unmuted (not in muted_users) active speakers count toward normalization.
        """
        volume = self.user_volumes.get(user_id, 1.0)
        # Clean up stale speakers and count active ones
        now = time.time()
        stale = [uid for uid, t in self._active_audio_users.items() if now - t > 2.0]
        for uid in stale:
            del self._active_audio_users[uid]
        # Only count unmuted users in active_count
        unmuted_active = [uid for uid in self._active_audio_users if uid not in self.muted_users]
        active_count = max(1, len(unmuted_active))
        volume = volume / active_count
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
        
        # Send ban command to server via RUDP
        if not self.rudp_endpoint:
            messagebox.showerror("错误", "未连接到服务器")
            return
        
        try:
            ban_data = json.dumps({"user_id": user_id, "reason": reason}).encode('utf-8')
            
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(ban_data)
                ban_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                ban_payload = struct.pack('!I', len(ban_data)) + ban_data
            
            self.rudp_endpoint.send(MSG_TYPE_ADMIN_BAN, ban_payload, timeout=5)
            self._log(f"已发送封禁命令: 用户 '{username}' (原因: {reason or '无'})")
            
            # Clear selection
            self.selected_user_id = None
            self.selected_user_var.set("未选择用户")
            self.ban_btn.config(state=tk.DISABLED)
            self.kick_btn.config(state=tk.DISABLED)
            # Reset name label highlighting
            for uid, btns in self.user_buttons.items():
                btns["name_label"].config(foreground="black", font=('', 9, 'normal'))
            
        except Exception as e:
            self._log(f"发送封禁命令失败: {e}")
            messagebox.showerror("错误", f"发送封禁命令失败: {e}")
    
    def _kick_selected_user(self):
        """Kick selected user (disconnect without banning)."""
        user_id = self.selected_user_id
        if user_id is None:
            messagebox.showwarning("未选择用户", "请先在用户列表中选择一个用户")
            return
        
        if not self.connected or not self.rudp_endpoint:
            messagebox.showerror("错误", "未连接到服务器")
            return
        
        try:
            kick_data = json.dumps({"user_id": user_id}).encode('utf-8')
            
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(kick_data)
                kick_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                kick_payload = struct.pack('!I', len(kick_data)) + kick_data
            
            self.rudp_endpoint.send(MSG_TYPE_ADMIN_KICK, kick_payload, timeout=5)
            self._log(f"已发送踢出命令: 用户 '{user_id}'")
            
            # Clear selection
            self.selected_user_id = None
            self.selected_user_var.set("未选择用户")
            self.ban_btn.config(state=tk.DISABLED)
            self.kick_btn.config(state=tk.DISABLED)
            # Reset name label highlighting
            for uid, btns in self.user_buttons.items():
                btns["name_label"].config(foreground="black", font=('', 9, 'normal'))
            
        except Exception as e:
            self._log(f"发送踢出命令失败: {e}")
            messagebox.showerror("错误", f"发送踢出命令失败: {e}")
    
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
        """Request ban list from server via RUDP."""
        if not self.rudp_endpoint:
            messagebox.showwarning("警告", "请先连接服务器")
            return
        
        try:
            # Send request via RUDP
            request_data = b''
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(request_data)
                request_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                request_payload = struct.pack('!I', len(request_data)) + request_data
            self.rudp_endpoint.send(MSG_TYPE_ADMIN_GET_BAN_LIST, request_payload, timeout=5)
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
            if not isinstance(fps, list):
                # Handle old format where fingerprints was a dict
                fps = []
            hw_fps = [fp for fp in fps if isinstance(fp, dict) and fp.get('type') != 'ip']
            ip_fps = [fp for fp in fps if isinstance(fp, dict) and fp.get('type') == 'ip']
            
            # Hardware fingerprints summary
            hw_parts = []
            for fp in hw_fps:
                fp_str = f"{fp.get('type', '?')}:{fp.get('value_short', fp.get('value', '?')[:8] + '...')}"
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
        
        if not self.rudp_endpoint:
            messagebox.showerror("错误", "未连接到服务器")
            return
        
        try:
            # Send unban command via RUDP
            unban_data = json.dumps({"device_key": device_id}).encode('utf-8')
            
            if self.audio_encryptor:
                encrypted_data = self.audio_encryptor.encrypt(unban_data)
                unban_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
            else:
                unban_payload = struct.pack('!I', len(unban_data)) + unban_data
            
            self.rudp_endpoint.send(MSG_TYPE_ADMIN_UNBAN, unban_payload, timeout=5)
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
        """Background thread to establish connection to server using UDP+RUDP."""
        # Store params for auto-reconnection
        self._reconnect_params = (host, port, name, password, volume)
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
            result = self.rudp_endpoint.send_and_wait(MSG_TYPE_ADMIN_JOIN, b'', timeout=10)
            if result is None:
                raise Exception("服务器无响应，获取RSA公钥超时")
            
            msg_type, payload = result
            if msg_type != MSG_TYPE_ADMIN_JOIN:
                raise Exception(f"收到意外的消息类型: {msg_type}")
            
            # Parse public key: [pub_key_len(4)][public_key_bytes]
            if len(payload) < 4:
                raise Exception("服务器响应格式错误")
            pub_key_len = struct.unpack('!I', payload[:4])[0]
            public_key_bytes = payload[4:4+pub_key_len]
            
            # Step 4: Verify server fingerprint (SSH-style trust)
            server_addr_str = f"{host}:{port}"
            if not self._verify_server_fingerprint(server_addr_str, public_key_bytes):
                raise Exception("服务器指纹验证失败，连接已终止")
            
            self.root.after(0, self._log, "服务器指纹验证通过")
            
            # Step 5: Encrypt password with RSA public key
            public_key = RSA.import_key(public_key_bytes)
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_password = cipher.encrypt(password.encode('utf-8'))
            
            self.root.after(0, self._log, f"密码已使用 RSA-2048 加密")
            
            # Step 6: Get device fingerprints
            device_fingerprints = get_device_fingerprint()
            fp_summary = f"MAC:{device_fingerprints['mac'][:16]} CPU:{device_fingerprints['cpu'][:16]}"
            self.root.after(0, self._log, f"设备指纹: {fp_summary}")
            
            # Step 7: Send ADMIN_JOIN packet with encrypted password and device fingerprints
            name_bytes = name.encode('utf-8')
            fingerprints_json = json.dumps(device_fingerprints).encode('utf-8')
            join_data = (
                struct.pack('!I', len(name_bytes)) + name_bytes +
                struct.pack('!I', len(encrypted_password)) + encrypted_password +
                struct.pack('!I', len(fingerprints_json)) + fingerprints_json
            )
            
            self.root.after(0, self._log, f"发送加入请求，包大小: {len(join_data)} 字节")
            
            # Use RUDP send_and_wait for reliable delivery
            result = self.rudp_endpoint.send_and_wait(MSG_TYPE_ADMIN_JOIN, join_data, timeout=15)
            if result is None:
                raise Exception("服务器无响应，认证超时")
            
            msg_type, payload = result
            self.root.after(0, self._log, f"收到响应类型: {msg_type}")
            
            if msg_type == MSG_TYPE_AUTH_FAIL:
                raise Exception("密码错误，身份验证失败")
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
            else:
                raise Exception("未知的服务器响应")
            
            self.p = pyaudio.PyAudio()
            self.player = AudioPlayer(self.p, volume=volume)
            
            self.running = True
            self.connected = True
            
            # Create packet queue for decoupling recv from processing
            self._packet_queue = queue.Queue(maxsize=2000)
            
            # Start heartbeat thread (via RUDP)
            heartbeat_thread = threading.Thread(target=self._send_heartbeat, name='heartbeat', daemon=True)
            heartbeat_thread.start()
            self._active_threads.append(heartbeat_thread)
            
            # Start receive thread (UDP only, fast path)
            receive_thread = threading.Thread(target=self._receive_loop, name='receive_loop', daemon=True)
            receive_thread.start()
            self._active_threads.append(receive_thread)
            
            # Start process thread (handles audio + control messages)
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
        self.status_var.set(f"已连接 ({name})")
        self.status_label.config(foreground="green")
        self._log(f"已以管理员身份加入服务器，昵称: {name}")
        self._log("管理员可监听所有用户的语音，点击用户列表中的 S 按钮可独听，点击 M 按钮可静音。")
        
        # Reset solo and mute state
        self.solo_users.clear()
        self.muted_users.clear()
        self.selected_user_id = None
        self.ban_btn.config(state=tk.DISABLED)
        self.kick_btn.config(state=tk.DISABLED)
        
        # Clear old user list display (prevent duplicates after reconnect)
        self._clear_user_list()
        
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
        
        # Clear user list display
        self.root.after(0, self._clear_user_list)
    
    def _disconnect(self):
        """Disconnect from server and clean up resources."""
        self._auto_reconnect = False  # User manually disconnected
        self.running = False
        self.connected = False
        
        # Send LEAVE message via RUDP
        try:
            if self.name and self.rudp_endpoint:
                name_bytes = self.name.encode('utf-8')
                if self.audio_encryptor:
                    # Encrypt leave data
                    encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                    leave_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
                else:
                    leave_payload = struct.pack('!I', len(name_bytes)) + name_bytes
                self.rudp_endpoint.send_raw(MSG_TYPE_LEAVE, leave_payload)
                import time
                time.sleep(0.2)
        except Exception:
            pass
        
        self.connect_btn.config(text="连接")
        self.status_var.set("已断开")
        self.status_label.config(foreground="red")
        self._log("已断开连接")
        self._cleanup()
        
        # Clear user list display
        self.root.after(0, self._clear_user_list)
        
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
            
        # Close network socket (TCP, no longer used)
        if self.sock_audio:
            try:
                self.sock_audio.close()
            except Exception:
                pass
            self.sock_audio = None
        
        # Close UDP socket
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None
        
        # Close RUDP endpoint
        if self.rudp_endpoint:
            try:
                self.rudp_endpoint.close()
            except Exception:
                pass
            self.rudp_endpoint = None
        
        # Close signal socket (no longer used)
        if self.sock_signal:
            try:
                self.sock_signal.close()
            except Exception:
                pass
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
        
        # Reset monitoring, solo and mute state
        self.user_id_map.clear()
        self.solo_users.clear()
        self.muted_users.clear()
        self.monitoring_user_id = None
            
    def _send_heartbeat(self):
        """Send heartbeat packets to server via RUDP to keep connection alive."""
        import time
        while self.running and self.connected:
            try:
                if self.name and self.rudp_endpoint:
                    name_bytes = self.name.encode('utf-8')
                    if self.audio_encryptor:
                        # Encrypt heartbeat data
                        encrypted_data = self.audio_encryptor.encrypt(name_bytes)
                        heartbeat_payload = struct.pack('!I', len(encrypted_data)) + encrypted_data
                    else:
                        # Fallback to plaintext
                        heartbeat_payload = struct.pack('!I', len(name_bytes)) + name_bytes
                    # Fire-and-forget, no ACK needed for heartbeat
                    self.rudp_endpoint.send_raw(MSG_TYPE_HEARTBEAT, heartbeat_payload)
                time.sleep(3)
            except Exception:
                time.sleep(3)
                
    def _receive_loop(self):
        """Fast receive loop - only queues packets, no processing.
        
        All processing (audio decryption, control message handling) is done
        in the separate _process_loop to prevent control messages from
        blocking audio packet reception.
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
                
                self.last_packet_time = time.time()
                
                try:
                    self._packet_queue.put_nowait((data, addr))
                except queue.Full:
                    pass  # Drop oldest implicitly
                    
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
        """Process loop - handles audio and control messages from the queue.
        
        Runs in a separate thread from _receive_loop so that control message
        processing (e.g., ban list decryption + JSON parsing) never blocks
        audio packet reception.
        """
        audio_count = 0
        
        while self.running:
            try:
                data, addr = self._packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
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
                    
                    # Check mute/solo/monitoring logic
                    if sender_id in self.muted_users:
                        continue
                    
                    if self.solo_users:
                        if sender_id not in self.solo_users:
                            continue
                    
                    if self.monitoring_user_id is not None and sender_id != self.monitoring_user_id:
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
                    self._log(f"处理数据包出错: {e}")
    
    def _handle_control_message(self, msg_type, payload):
        """Handle a control message received via RUDP."""
        try:
            if msg_type == MSG_TYPE_USER_LIST:
                if self.audio_encryptor:
                    decrypted_data = self.audio_encryptor.decrypt(payload)
                    if decrypted_data:
                        user_list_data = decrypted_data.decode('utf-8')
                        self.root.after(0, self._update_users, user_list_data)
                        
            elif msg_type == MSG_TYPE_BAN_LIST:
                if self.audio_encryptor:
                    decrypted_data = self.audio_encryptor.decrypt(payload)
                    if decrypted_data:
                        try:
                            ban_list_data = json.loads(decrypted_data.decode('utf-8'))
                            self.root.after(0, self._update_ban_list, ban_list_data)
                        except Exception as e:
                            self._log(f"解析封禁列表失败: {e}")
                            
            elif msg_type == MSG_TYPE_USER_JOINED:
                if self.audio_encryptor:
                    decrypted_data = self.audio_encryptor.decrypt(payload)
                    if decrypted_data:
                        event_data = decrypted_data.decode('utf-8')
                        self.root.after(0, self._log, f"[用户事件] {event_data}")
                        
            elif msg_type == MSG_TYPE_LEAVE:
                if self.audio_encryptor:
                    decrypted_data = self.audio_encryptor.decrypt(payload)
                    if decrypted_data:
                        event_data = decrypted_data.decode('utf-8')
                        self.root.after(0, self._log, f"[用户离开] {event_data}")
                        
            elif msg_type == MSG_TYPE_HEARTBEAT:
                # Server heartbeat response, ignore
                pass
                
            elif msg_type == MSG_TYPE_TEXT_MESSAGE:
                if self.audio_encryptor:
                    decrypted_data = self.audio_encryptor.decrypt(payload)
                    if decrypted_data:
                        text = decrypted_data.decode('utf-8')
                        self.root.after(0, self._display_text_message, text)
                
            else:
                self._log(f"收到未知控制消息类型: {msg_type}")
                
        except Exception as e:
            self._log(f"处理控制消息失败: {e}")
    
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
    
    def _connection_watchdog(self):
        """Monitor connection health and trigger auto-reconnection.
        
        If no packets are received for 5 seconds, the server is
        considered dead. The watchdog triggers a full reconnection
        with exponential backoff (1s, 2s, 4s, ... up to 60s).
        """
        backoff = 1
        
        while self.running:
            time.sleep(1)
            
            if not self._auto_reconnect:
                continue
            
            if not self.connected:
                continue
            
            elapsed = time.time() - self.last_packet_time
            if elapsed > 5:
                self._log(f"服务器连接丢失（{elapsed:.0f}秒无数据），{backoff}秒后重连...")
                self.root.after(0, lambda: self.status_var.set("连接丢失，正在重连..."))
                
                self.connected = False
                self.running = False
                
                time.sleep(1)
                self._cleanup()
                
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                
                if self._reconnect_params and self._auto_reconnect:
                    host, port, name, password, volume = self._reconnect_params
                    self._log(f"正在重连 {host}:{port}...")
                    try:
                        self._connect_thread(host, port, name, password, volume)
                        backoff = 1
                    except Exception as e:
                        self._log(f"重连失败: {e}")
            else:
                backoff = 1
    
    def _receive_control(self):
        """Receive and process control messages from server via TCP.
        
        Audio is now handled by _receive_audio_udp via UDP.
        This method handles TCP control messages (user list, ban list, events, etc.).
        """
        self._log("开始接收控制消息...")
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
                        # Audio now comes via UDP, skip TCP audio packets
                        if len(buffer) < 14:
                            break
                        sender_name_len = struct.unpack('!B', buffer[5:6])[0]
                        offset = 6 + sender_name_len
                        if len(buffer) < offset + 12:
                            break
                        encrypted_len = struct.unpack('!I', buffer[offset+8:offset+12])[0]
                        if len(buffer) < offset + 12 + encrypted_len:
                            break
                        buffer = buffer[offset+12+encrypted_len:]
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
    args = parser.parse_args()

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

    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(2)

    root = tk.Tk()
    app = AdminGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()