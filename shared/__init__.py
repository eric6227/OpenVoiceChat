# OpenVoiceChat shared module
# Common classes and utilities shared between client and admin

from shared.constants import (
    CHANNELS, RATE, CHUNK,
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
    JITTER_BUFFER_SIZE, MAX_PACKET_SIZE,
    init_audio_format,
)

from shared.device_fingerprint import DATA_BLOB, get_device_fingerprint
from shared.crypto import AudioEncryptor, SessionKeyEncryptor, NoncePool, _global_nonce_pool
from shared.audio_utils import AudioCompressor, JitterBuffer, AudioPlayer
from shared.noise import NoiseSuppressor
from shared.security_utils import (
    encrypt_password_dpapi, decrypt_password_dpapi,
    load_known_servers, save_known_servers,
    compute_server_fingerprint, verify_server_fingerprint,
)
from shared.rudp import (
    pack_rudp_message, unpack_rudp_message,
    pack_ack, pack_response, pack_request,
    RUDP_FLAG_NEEDS_ACK, RUDP_FLAG_IS_ACK, RUDP_FLAG_IS_RESPONSE,
    RUDP_HEADER_SIZE, RUDPEndpoint, RUDPServer,
)