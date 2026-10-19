
import socket
import struct
import time

HOST = "192.168.14.11"
PORT = 1883

USERNAME = "3333@admin"
PASSWORD = "password123"

# 收到第一次订阅后，等待后续订阅报文的时间（秒）
SUBSCRIBE_WAIT = 2

# 订阅收集完成后，监控消息往来的时长（秒）
MONITOR_DURATION = 180

# 监控阶段轮询超时（秒），用于定期检查监控是否到期
MONITOR_POLL_TIMEOUT = 1


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


def parse_publish(header, payload):
    """解析 PUBLISH 报文，返回 (topic, packet_id, qos, message)。"""
    qos = (header >> 1) & 0x03

    topic, pos = read_string(payload, 0)

    packet_id = None
    if qos > 0:
        packet_id = struct.unpack_from("!H", payload, pos)[0]
        pos += 2

    message = payload[pos:]
    return topic, packet_id, qos, message


def topic_matches(topic_filter, topic):
    """判断主题是否匹配订阅过滤器（支持 + 和 # 通配符）。"""
    filter_levels = topic_filter.split("/")
    topic_levels = topic.split("/")

    for index, level in enumerate(filter_levels):
        if level == "#":
            return True
        if index >= len(topic_levels):
            return False
        if level != "+" and level != topic_levels[index]:
            return False

    return len(filter_levels) == len(topic_levels)


def format_message(message):
    """把消息内容格式化为可读字符串。"""
    try:
        text = message.decode("utf-8")
    except UnicodeDecodeError:
        return f"<二进制 {len(message)} 字节> {message.hex(' ').upper()}"
    return text


def timestamp():
    """当前时间字符串，用于日志前缀。"""
    return time.strftime("%H:%M:%S")


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


def encode_string(value):
    """编码 MQTT UTF-8 字符串。"""
    encoded = value.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def send_publish(sock, topic, message, qos=0, packet_id=None):
    """向客户端发送 PUBLISH 报文。"""
    header = 0x30 | (qos << 1)
    payload = encode_string(topic)

    if qos > 0:
        payload += struct.pack("!H", packet_id)

    payload += message
    send_packet(sock, header, payload)


def handle_client(conn, addr):
    client_id = None
    subscriptions = []
    subscribed = False

    message_count = 0
    monitor_deadline = None

    try:
        conn.settimeout(None)

        # 等待 CONNECT
        header, payload = recv_packet(conn)

        if header >> 4 != 1:
            print("收到的第一条报文不是 CONNECT")
            return

        client_id, username, password = parse_connect(payload)

        print(f"[{timestamp()}] 客户端连接请求：{addr}")
        print(f"[{timestamp()}] Client ID：{client_id}")
        print(f"[{timestamp()}] Username：{username}")

        # 校验用户名和密码
        if username != USERNAME or password != PASSWORD:
            print(f"[{timestamp()}] 认证失败，拒绝连接")
            conn.sendall(b"\x20\x02\x00\x04")
            return

        # 发送成功的 CONNACK
        conn.sendall(b"\x20\x02\x00\x00")
        print(f"[{timestamp()}] 认证成功，等待客户端订阅主题……")

        while True:
            # 监控阶段到期后退出
            if monitor_deadline is not None and time.monotonic() >= monitor_deadline:
                print(f"\n[{timestamp()}] 监控时长 "
                      f"{MONITOR_DURATION} 秒已到，停止监控")
                break

            try:
                header, payload = recv_packet(conn)
            except socket.timeout:
                if monitor_deadline is not None:
                    # 监控阶段：超时后回到循环开头检查是否到期
                    continue
                if subscribed:
                    # 订阅等待阶段结束，进入监控阶段
                    monitor_deadline = time.monotonic() + MONITOR_DURATION
                    conn.settimeout(MONITOR_POLL_TIMEOUT)

                    print("\n========== 终端订阅信息 ==========")
                    print(f"Client ID：{client_id}")
                    print(f"用户名：{USERNAME}")
                    print("订阅主题：")

                    unique_topics = list(dict.fromkeys(subscriptions))
                    for index, topic in enumerate(unique_topics, 1):
                        print(f"  {index}. {topic}")

                    print("==================================")
                    print(f"\n[{timestamp()}] 开始监控消息往来，"
                          f"持续 {MONITOR_DURATION // 60} 分钟……\n")
                    continue
                raise

            packet_type = header >> 4

            if packet_type == 8:  # SUBSCRIBE
                if len(payload) < 2:
                    raise ValueError("SUBSCRIBE 报文过短")

                packet_id = payload[:2]
                topics = parse_subscribe(payload)

                for topic, qos in topics:
                    subscriptions.append(topic)
                    print(f"[{timestamp()}] [订阅] {topic} (QoS {qos})")

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

            elif packet_type == 3:  # PUBLISH
                topic, packet_id, qos, message = parse_publish(header, payload)

                message_count += 1
                print(f"[{timestamp()}] [收 ← 终端] 主题: {topic} "
                      f"(QoS {qos}) 内容: {format_message(message)}")

                # QoS 1：回复 PUBACK
                if qos == 1 and packet_id is not None:
                    send_packet(conn, 0x40, struct.pack("!H", packet_id))
                # QoS 2：回复 PUBREC
                elif qos == 2 and packet_id is not None:
                    send_packet(conn, 0x50, struct.pack("!H", packet_id))

                # 如果发布的主题命中客户端自己的订阅，
                # 像真实 Broker 一样把消息投递回去
                matched = any(
                    topic_matches(f, topic) for f in subscriptions
                )

                if matched:
                    send_publish(conn, topic, message, qos=0)
                    print(f"[{timestamp()}] [发 → 终端] 主题: {topic} "
                          f"(QoS 0) 内容: {format_message(message)}")

            elif packet_type == 6:  # PUBREL（QoS 2 第三步）
                packet_id = struct.unpack_from("!H", payload, 0)[0]
                # 回复 PUBCOMP
                send_packet(conn, 0x70, struct.pack("!H", packet_id))

            elif packet_type == 12:  # PINGREQ
                send_packet(conn, 0xD0, b"")
                print(f"[{timestamp()}] [心跳] PINGREQ → PINGRESP")

            elif packet_type == 14:  # DISCONNECT
                print(f"[{timestamp()}] 客户端主动断开连接")
                break

        # 输出监控统计
        if subscribed:
            print("\n========== 监控结果统计 ==========")
            print(f"Client ID：{client_id}")
            print(f"监控时长：{MONITOR_DURATION} 秒")
            print(f"收到消息数：{message_count}")
            print("==================================")

    except (ConnectionError, OSError, ValueError,
            UnicodeDecodeError, struct.error) as exc:
        print(f"[{timestamp()}] 客户端处理异常：{exc}")

    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        print(f"MQTT Broker 正在监听 {HOST}:{PORT}")
        print(f"仅允许用户名：{USERNAME}")
        print("等待终端连接……")

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)

            # 处理完一个客户端后退出程序
            print("监测结束，程序退出")
            break


if __name__ == "__main__":
    main()
