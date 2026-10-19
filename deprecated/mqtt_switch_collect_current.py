
import json
import re
import socket
import struct
import time

HOST = "192.168.14.11"
PORT = 1883

USERNAME = "3333@admin"
PASSWORD = "password123"

# 收到第一次订阅后，等待后续订阅报文的时间（秒）
SUBSCRIBE_WAIT = 2

# 目标主题过滤器：收到该主题的任意消息后提取设备信息并退出
TARGET_TOPIC_FILTER = "/v1/devices/+/topo/add"

# 第二个退出条件主题：收到该主题的消息后打印第一个 deviceId 并退出
UPDATE_TOPIC_FILTER = "/v1/devices/+/topo/update"


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


def timestamp():
    """当前时间字符串，用于日志前缀。"""
    return time.strftime("%H:%M:%S")


def find_device_group(node):
    """在 JSON 结构中递归查找第一个同时包含
    manufacturerId、model、nodeId 的对象。"""
    if isinstance(node, dict):
        if ("manufacturerId" in node
                and "model" in node
                and "nodeId" in node):
            return node

        for value in node.values():
            found = find_device_group(value)
            if found is not None:
                return found

    elif isinstance(node, list):
        for item in node:
            found = find_device_group(item)
            if found is not None:
                return found

    return None


def extract_device_info(message):
    """从消息内容中提取第一个
    manufacturerId、model、nodeId 组，返回三元组。"""
    text = message.decode("utf-8", errors="replace")

    # 优先按 JSON 解析
    try:
        group = find_device_group(json.loads(text))
        if group is not None:
            return (
                str(group["manufacturerId"]),
                str(group["model"]),
                str(group["nodeId"]),
            )
    except (ValueError, TypeError):
        pass

    # JSON 解析失败时退回正则提取
    fields = {}
    for key in ("manufacturerId", "model", "nodeId"):
        match = re.search(
            rf'"{key}"\s*:\s*"?([^",}}\s]+)"?', text
        )
        if match:
            fields[key] = match.group(1)

    if len(fields) == 3:
        return (
            fields["manufacturerId"],
            fields["model"],
            fields["nodeId"],
        )

    return None


def find_device_id(node):
    """在 JSON 结构中递归查找第一个 deviceId 字段的值。"""
    if isinstance(node, dict):
        if "deviceId" in node:
            return str(node["deviceId"])

        for value in node.values():
            found = find_device_id(value)
            if found is not None:
                return found

    elif isinstance(node, list):
        for item in node:
            found = find_device_id(item)
            if found is not None:
                return found

    return None


def extract_device_id(message):
    """从消息内容中提取第一个 deviceId 字段的内容。"""
    text = message.decode("utf-8", errors="replace")

    # 优先按 JSON 解析
    try:
        device_id = find_device_id(json.loads(text))
        if device_id is not None:
            return device_id
    except (ValueError, TypeError):
        pass

    # JSON 解析失败时退回正则提取
    match = re.search(r'"deviceId"\s*:\s*"?([^",}\s]+)"?', text)
    if match:
        return match.group(1)

    return None


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
    """处理单个客户端，返回 True 表示已获取目标信息、程序应退出。"""
    client_id = None
    subscriptions = []
    subscribed = False

    try:
        conn.settimeout(None)

        # 等待 CONNECT
        header, payload = recv_packet(conn)

        if header >> 4 != 1:
            print("收到的第一条报文不是 CONNECT")
            return False

        client_id, username, password = parse_connect(payload)

        print(f"[{timestamp()}] 客户端连接请求：{addr}")
        print(f"[{timestamp()}] Client ID：{client_id}")
        print(f"[{timestamp()}] Username：{username}")

        # 校验用户名和密码
        if username != USERNAME or password != PASSWORD:
            print(f"[{timestamp()}] 认证失败，拒绝连接")
            conn.sendall(b"\x20\x02\x00\x04")
            return False

        # 发送成功的 CONNACK
        conn.sendall(b"\x20\x02\x00\x00")
        print(f"[{timestamp()}] 认证成功，等待客户端订阅主题……")
        print(f"[{timestamp()}] 目标主题：{TARGET_TOPIC_FILTER}")
        print(f"[{timestamp()}] 目标主题：{UPDATE_TOPIC_FILTER}")

        while True:
            try:
                header, payload = recv_packet(conn)
            except socket.timeout:
                if subscribed:
                    # 订阅等待窗口结束，恢复阻塞模式，
                    # 继续等待目标主题消息
                    conn.settimeout(None)

                    print("\n========== 终端订阅信息 ==========")
                    print(f"Client ID：{client_id}")
                    print(f"用户名：{USERNAME}")
                    print("订阅主题：")

                    unique_topics = list(dict.fromkeys(subscriptions))
                    for index, topic in enumerate(unique_topics, 1):
                        print(f"  {index}. {topic}")

                    print("==================================")
                    print(f"\n[{timestamp()}] 等待 "
                          f"{TARGET_TOPIC_FILTER} 或 "
                          f"{UPDATE_TOPIC_FILTER} 消息……")
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

                print(f"[{timestamp()}] [收 ← 终端] 主题: {topic} (QoS {qos})")

                # QoS 1：回复 PUBACK
                if qos == 1 and packet_id is not None:
                    send_packet(conn, 0x40, struct.pack("!H", packet_id))
                # QoS 2：回复 PUBREC
                elif qos == 2 and packet_id is not None:
                    send_packet(conn, 0x50, struct.pack("!H", packet_id))

                # 命中目标主题：提取设备信息并退出
                if topic_matches(TARGET_TOPIC_FILTER, topic):
                    info = extract_device_info(message)

                    if info is None:
                        print(f"[{timestamp()}] 目标消息中未找到 "
                              f"manufacturerId/model/nodeId 组")
                        print(f"[{timestamp()}] 原始内容: "
                              f"{message.decode('utf-8', errors='replace')}")
                        return False

                    manufacturer_id, model, node_id = info
                    result = manufacturer_id + model + node_id

                    print("\n========== 设备信息提取结果 ==========")
                    print(f"manufacturerId：{manufacturer_id}")
                    print(f"model：{model}")
                    print(f"nodeId：{node_id}")
                    print(f"拼接结果：{result}")
                    print("======================================")
                    return True

                # 命中 update 主题：打印第一个 deviceId 并退出
                elif topic_matches(UPDATE_TOPIC_FILTER, topic):
                    device_id = extract_device_id(message)

                    if device_id is None:
                        print(f"[{timestamp()}] 目标消息中未找到 deviceId 字段")
                        print(f"[{timestamp()}] 原始内容: "
                              f"{message.decode('utf-8', errors='replace')}")
                        return False

                    print("\n========== deviceId 提取结果 ==========")
                    print(f"deviceId：{device_id}")
                    print("=======================================")
                    return True

            elif packet_type == 6:  # PUBREL（QoS 2 第三步）
                packet_id = struct.unpack_from("!H", payload, 0)[0]
                # 回复 PUBCOMP
                send_packet(conn, 0x70, struct.pack("!H", packet_id))

            elif packet_type == 12:  # PINGREQ
                send_packet(conn, 0xD0, b"")

            elif packet_type == 14:  # DISCONNECT
                print(f"[{timestamp()}] 客户端主动断开连接")
                return False

    except (ConnectionError, OSError, ValueError,
            UnicodeDecodeError, struct.error) as exc:
        print(f"[{timestamp()}] 客户端处理异常：{exc}")

    finally:
        conn.close()

    return False


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
            done = handle_client(conn, addr)

            if done:
                print("已获取目标信息，程序退出")
                break

            # 客户端断开但未获取到目标信息，继续等待下一个连接
            print("客户端已断开，继续等待下一个连接……")


if __name__ == "__main__":
    main()
