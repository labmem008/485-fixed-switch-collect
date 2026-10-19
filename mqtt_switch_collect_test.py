
import socket
import struct

HOST = "192.168.14.11"
PORT = 1883

USERNAME = "3333@admin"
PASSWORD = "password123"

# 收到第一次订阅后，等待后续订阅报文的时间（秒）
SUBSCRIBE_WAIT = 2

# accept 的轮询超时（秒），用于让 Ctrl+C 能及时打断阻塞等待
ACCEPT_TIMEOUT = 1


def recv_exact(sock, length):
    """读取指定长度的数据。"""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("客户端已断开连接")
        data += chunk
    return data


def recv_packet(sock):
    """读取一条完整的 MQTT 报文。"""
    header = recv_exact(sock, 1)[0]

    remaining = 0
    multiplier = 1

    while True:
        digit = recv_exact(sock, 1)[0]
        remaining += (digit & 0x7F) * multiplier

        if not digit & 0x80:
            break

        multiplier *= 128
        if multiplier > 128 ** 3:
            raise ValueError("MQTT 报文长度编码错误")

    payload = recv_exact(sock, remaining)
    return header, payload


def read_string(data, pos):
    """读取 MQTT UTF-8 字符串。"""
    length = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    value = data[pos:pos + length].decode("utf-8")
    return value, pos + length


def parse_connect(payload):
    """解析 MQTT CONNECT 报文。"""
    protocol, pos = read_string(payload, 0)

    if protocol != "MQTT":
        raise ValueError("仅支持 MQTT 3.1.1")

    level = payload[pos]
    pos += 1

    if level != 4:
        raise ValueError("仅支持 MQTT 3.1.1")

    flags = payload[pos]
    pos += 1

    # 跳过 Keep Alive
    pos += 2

    client_id, pos = read_string(payload, pos)

    # 如果包含 Will，跳过 Will Topic 和 Will Message
    if flags & 0x04:
        _, pos = read_string(payload, pos)
        _, pos = read_string(payload, pos)

    username = None
    password = None

    if flags & 0x80:
        username, pos = read_string(payload, pos)

    if flags & 0x40:
        password, pos = read_string(payload, pos)

    return client_id, username, password


def parse_subscribe(payload):
    """解析 SUBSCRIBE 报文中的主题过滤器。"""
    pos = 2  # 跳过 Packet Identifier
    topics = []

    while pos < len(payload):
        topic, pos = read_string(payload, pos)

        if pos >= len(payload):
            raise ValueError("SUBSCRIBE 报文格式错误")

        qos = payload[pos]
        pos += 1
        topics.append((topic, qos))

    return topics


def encode_remaining_length(length):
    """编码 MQTT Remaining Length。"""
    encoded = bytearray()

    while True:
        digit = length % 128
        length //= 128

        if length > 0:
            digit |= 0x80

        encoded.append(digit)

        if length == 0:
            return bytes(encoded)


def send_packet(sock, header, payload):
    """发送 MQTT 报文。"""
    packet = (
        bytes([header])
        + encode_remaining_length(len(payload))
        + payload
    )
    sock.sendall(packet)


def handle_client(conn, addr):
    client_id = None
    subscriptions = []
    subscribed = False

    try:
        conn.settimeout(None)

        # 等待 CONNECT
        header, payload = recv_packet(conn)

        if header >> 4 != 1:
            print("收到的第一条报文不是 CONNECT")
            return

        client_id, username, password = parse_connect(payload)

        print(f"客户端连接请求：{addr}")
        print(f"Client ID：{client_id}")
        print(f"Username：{username}")

        # 校验用户名和密码
        if username != USERNAME or password != PASSWORD:
            print("认证失败，拒绝连接")
            conn.sendall(b"\x20\x02\x00\x04")
            return

        # 发送成功的 CONNACK
        conn.sendall(b"\x20\x02\x00\x00")
        print("认证成功，等待客户端订阅主题……")

        while True:
            try:
                header, payload = recv_packet(conn)
            except socket.timeout:
                if subscribed:
                    break
                raise

            packet_type = header >> 4

            if packet_type == 8:  # SUBSCRIBE
                if len(payload) < 2:
                    raise ValueError("SUBSCRIBE 报文过短")

                packet_id = payload[:2]
                topics = parse_subscribe(payload)

                for topic, qos in topics:
                    subscriptions.append(topic)

                # 回复 SUBACK，授予 QoS 0
                granted_qos = bytes(
                    0 if qos in (0, 1, 2) else 0x80
                    for _, qos in topics
                )

                send_packet(
                    conn,
                    0x90,
                    packet_id + granted_qos
                )

                subscribed = True

                # 首次订阅后继续等待可能到来的其他订阅
                conn.settimeout(SUBSCRIBE_WAIT)

            elif packet_type == 12:  # PINGREQ
                send_packet(conn, 0xD0, b"")

            elif packet_type == 14:  # DISCONNECT
                break

        if subscribed:
            print("\n========== 终端订阅信息 ==========")
            print(f"Client ID：{client_id}")
            print(f"用户名：{USERNAME}")
            print("订阅主题：")

            for index, topic in enumerate(
                dict.fromkeys(subscriptions), 1
            ):
                print(f"  {index}. {topic}")

            print("==================================")
        else:
            print("客户端已连接，但未订阅任何主题")

    except KeyboardInterrupt:
        print("\n检测到 Ctrl+C，正在断开客户端连接……")
        raise

    except (ConnectionError, OSError, ValueError,
            UnicodeDecodeError, struct.error) as exc:
        print(f"客户端处理异常：{exc}")

    finally:
        conn.close()


def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(5)

            # 设置超时，保证 Windows 上 Ctrl+C 能及时打断 accept
            server.settimeout(ACCEPT_TIMEOUT)

            print(f"MQTT Broker 正在监听 {HOST}:{PORT}")
            print(f"仅允许用户名：{USERNAME}")
            print("等待终端连接……（Ctrl+C 退出）")

            while True:
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue

                handle_client(conn, addr)

                # 处理完一个客户端后退出程序
                print("监测结束，程序退出")
                break

    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，正在关闭监听……")
        print("程序已安全退出")


if __name__ == "__main__":
    main()
