import socket
import threading
import struct
import sys
import logging

try:
    import pyaudio
except ImportError:
    print("错误: 请先安装 pyaudio: pip install pyaudio")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
CHUNK = 1024


def send_audio(conn, p):
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE,
                    input=True, frames_per_buffer=CHUNK)
    logger.info("麦克风已打开，开始发送音频...")
    try:
        while True:
            data = stream.read(CHUNK, exception_on_overflow=False)
            try:
                conn.sendall(data)
            except Exception:
                logger.error("发送音频失败，服务器连接已断开")
                break
    except Exception as e:
        logger.error(f"读取音频数据出错: {e}")
    finally:
        stream.stop_stream()
        stream.close()


def receive_audio(conn, p):
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE,
                    output=True, frames_per_buffer=CHUNK)
    logger.info("扬声器已打开，开始接收音频...")
    try:
        while True:
            data = conn.recv(CHUNK)
            if not data:
                break
            stream.write(data)
    except Exception as e:
        logger.error(f"接收/播放音频出错: {e}")
    finally:
        stream.stop_stream()
        stream.close()


def main():
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        host = input("服务器地址 [127.0.0.1]: ").strip() or '127.0.0.1'
        port = int(input("服务器端口 [9090]: ").strip() or '9090')

    name = input("你的昵称: ").strip()
    if not name:
        name = "匿名用户"

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((host, port))
    except ConnectionRefusedError:
        print(f"错误: 无法连接到服务器 {host}:{port}")
        return
    except Exception as e:
        print(f"错误: 连接失败 - {e}")
        return

    name_bytes = name.encode('utf-8')
    conn.sendall(struct.pack('!I', len(name_bytes)) + name_bytes)
    logger.info(f"已连接到服务器，昵称: {name}")
    print("=" * 40)
    print("语音聊天已连接！按 Ctrl+C 退出。")
    print("=" * 40)

    p = pyaudio.PyAudio()

    send_thread = threading.Thread(target=send_audio, args=(conn, p), daemon=True)
    send_thread.start()

    try:
        receive_audio(conn, p)
    except KeyboardInterrupt:
        print("\n正在断开连接...")
    finally:
        conn.close()
        p.terminate()
        logger.info("已断开连接")


if __name__ == '__main__':
    main()
