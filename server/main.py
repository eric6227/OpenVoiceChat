import socket
import threading
import struct
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

HOST = '0.0.0.0'
PORT = 9090
CHUNK_SIZE = 1024

clients = {}
clients_lock = threading.Lock()


def broadcast_audio(data, sender_conn):
    with clients_lock:
        client_list = list(clients.items())

    for conn, info in client_list:
        if conn != sender_conn:
            try:
                conn.sendall(data)
            except Exception:
                with clients_lock:
                    if conn in clients:
                        removed = clients.pop(conn)
                        logger.info(f"用户 [{removed['name']}] 已断开 (发送失败)")
                        try:
                            conn.close()
                        except Exception:
                            pass


def handle_client(conn, addr):
    conn.settimeout(None)
    name = None
    try:
        name_len_data = conn.recv(4)
        if not name_len_data or len(name_len_data) < 4:
            return
        name_len = struct.unpack('!I', name_len_data)[0]
        if name_len == 0 or name_len > 128:
            return
        name_data = conn.recv(name_len)
        if not name_data:
            return
        name = name_data.decode('utf-8')

        with clients_lock:
            clients[conn] = {'name': name, 'addr': addr}
        logger.info(f"用户 [{name}] 已连接 from {addr}")

        while True:
            data = conn.recv(CHUNK_SIZE)
            if not data:
                break
            broadcast_audio(data, conn)

    except ConnectionResetError:
        pass
    except Exception as e:
        logger.error(f"处理用户 [{name or 'unknown'}] 时出错: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                info = clients.pop(conn)
                logger.info(f"用户 [{info['name']}] 已断开")
        try:
            conn.close()
        except Exception:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    logger.info(f"语音聊天服务器已启动，监听 {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("服务器正在关闭...")
    finally:
        server.close()


if __name__ == '__main__':
    main()
