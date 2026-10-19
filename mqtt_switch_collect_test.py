
import json
import socket
import struct
import time
from datetime import datetime, timedelta, timezone

HOST = "192.168.14.11"
PORT = 1883

USERNAME = "3333@admin"
PASSWORD = "password123"

# 收到第一次订阅后，等待后续订阅报文的时间（秒）
SUBSCRIBE_WAIT = 2

# accept 的轮询超时（秒），用于让 Ctrl+C 能及时打断阻塞等待
ACCEPT_TIMEOUT = 1

# 客户端连接的轮询超时（秒），保证 Ctrl+C 能及时打断 recv
POLL_TIMEOUT = 1

# 等待终端 commandResponse 的超时时间（秒）
COMMAND_WAIT_TIMEOUT = 60

# 档案删除 / 档案下发命令的 mid
MID_ACQ_FILES_DELETE = 1016102
MID_ACQ_FILES_ADD = 1016103

# 记录 topo/add 应答中生成的 deviceId，供 topo/update 应答使用
LAST_DEVICE_ID = "1234TERMAI0000900000000001810100000000AB74"


class BrokerShutdown(Exception):
    """需要主动结束整个程序时抛出。"""


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


def encode_string(value):
    """编码 MQTT UTF-8 字符串。"""
    data = value.encode("utf-8")
    return struct.pack("!H", len(data)) + data


def parse_publish(header, payload):
    """解析 PUBLISH 报文，返回 (topic, qos, packet_id, message)。"""
    qos = (header >> 1) & 0x03
    pos = 0

    topic, pos = read_string(payload, pos)

    packet_id = None
    if qos > 0:
        packet_id = payload[pos:pos + 2]
        pos += 2

    return topic, qos, packet_id, payload[pos:]


def publish_json(conn, topic, obj):
    """以 QoS 0 的 PUBLISH 报文发送 JSON 消息。"""
    body = json.dumps(obj, ensure_ascii=False)
    payload = encode_string(topic) + body.encode("utf-8")
    send_packet(conn, 0x30, payload)
    print(f"\n已回复消息，主题：{topic}")
    print(body)


def build_device_id(info):
    """按拼接规则生成 deviceId：manufacturerId + model + nodeId。"""
    return (
        str(info.get("manufacturerId", ""))
        + str(info.get("model", ""))
        + str(info.get("nodeId", ""))
    )


def handle_topo_add(conn, device_key, msg):
    """处理 /v1/devices/{id}/topo/add，回复第一个设备的 addResponse。"""
    device_infos = msg.get("deviceInfos")

    if not device_infos or not isinstance(device_infos, list):
        print("topo/add 消息中没有 deviceInfos，忽略")
        return

    info = device_infos[0]
    device_id = build_device_id(info)

    global LAST_DEVICE_ID
    LAST_DEVICE_ID = device_id

    response = {
        "statusDesc": "Success!",
        "data": [
            {
                "statusDesc": "success",
                "deviceInfo": {
                    "name": info.get("name", ""),
                    "manufacturerId": info.get("manufacturerId", ""),
                    "description": info.get("description", ""),
                    "model": info.get("model", ""),
                    "deviceId": device_id,
                    "nodeId": info.get("nodeId", ""),
                },
                "statusCode": 0,
            }
        ],
        "mid": str(msg.get("mid", "")),
        "statusCode": 0,
    }

    publish_json(
        conn,
        f"/v1/devices/{device_key}/topo/addResponse",
        response
    )
    print("继续等待消息……")


def now_event_time():
    """生成 eventTime，格式如 2026-10-16T10:32:29.331+0800。"""
    now = datetime.now(timezone(timedelta(hours=8)))
    return (
        now.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{now.microsecond // 1000:03d}+0800"
    )


def build_acq_files_delete(device_id):
    """构造档案删除命令。"""
    return {
        "msgType": "cloudReq",
        "mid": MID_ACQ_FILES_DELETE,
        "cmd": "acqFilesDelete",
        "serviceId": "command",
        "deviceId": device_id,
        "expire": 120,
        "eventTime": now_event_time(),
        "app": "SwitchCollect",
        "paras": {},
    }


def build_acq_files_add(device_id):
    """构造档案下发命令。"""
    meters = [
        ("RS485-1", "202108316022"),
        ("RS485-2", "110000000116"),
        ("RS485-3", "202108316038"),
        ("RS485-4", "110000000142"),
    ]

    acq_infos = [
        {
            "portInfo": {
                "channelType": "COM",
                "port": port,
                "baud": 9600,
                "check": "even",
                "databit": 8,
                "stopbit": 1,
            },
            "devInfo": [
                {
                    "address": address,
                    "protocol": "DLT645",
                }
            ],
        }
        for port, address in meters
    ]

    return {
        "msgType": "cloudReq",
        "mid": MID_ACQ_FILES_ADD,
        "cmd": "acqFilesAdd",
        "serviceId": "command",
        "deviceId": device_id,
        "expire": 120,
        "eventTime": now_event_time(),
        "app": "SwitchCollect",
        "paras": {
            "acqInfos": acq_infos,
        },
    }


def wait_for_command_response(conn, expect_mid, label):
    """等待终端在 /commandResponse 上回复指定 mid 的响应。"""
    deadline = time.monotonic() + COMMAND_WAIT_TIMEOUT

    while True:
        try:
            header, payload = recv_packet(conn)
        except socket.timeout:
            if time.monotonic() >= deadline:
                print(f"等待{label}响应超时（{COMMAND_WAIT_TIMEOUT} 秒）")
                return False
            continue

        packet_type = header >> 4

        if packet_type == 12:  # PINGREQ
            send_packet(conn, 0xD0, b"")
            continue

        if packet_type == 6:  # PUBREL
            send_packet(conn, 0x70, payload[:2])  # PUBCOMP
            continue

        if packet_type == 14:  # DISCONNECT
            print("客户端已断开，未收到响应")
            return False

        if packet_type != 3:  # 不是 PUBLISH
            continue

        topic, qos, pub_id, message = parse_publish(header, payload)

        if qos == 1 and pub_id is not None:
            send_packet(conn, 0x40, pub_id)  # PUBACK
        elif qos == 2 and pub_id is not None:
            send_packet(conn, 0x50, pub_id)  # PUBREC

        print(f"\n收到消息，主题：{topic}")

        try:
            text = message.decode("utf-8")
            print(text)
        except UnicodeDecodeError:
            continue

        if not topic.endswith("/commandResponse"):
            continue

        try:
            msg = json.loads(text)
        except json.JSONDecodeError:
            continue

        if msg.get("mid") == expect_mid:
            print(f"已确认收到{label}响应（mid={expect_mid}）")
            return True

        print(f"响应 mid 不匹配（期望 {expect_mid}），继续等待……")


def run_command_flow(conn, device_key, device_id):
    """发送档案删除、档案下发命令，并分别等待响应。"""
    command_topic = f"/v1/devices/{device_key}/command"

    print("\n---------- 档案删除 ----------")
    publish_json(conn, command_topic, build_acq_files_delete(device_id))
    wait_for_command_response(conn, MID_ACQ_FILES_DELETE, "档案删除")

    print("\n---------- 档案下发 ----------")
    publish_json(conn, command_topic, build_acq_files_add(device_id))
    wait_for_command_response(conn, MID_ACQ_FILES_ADD, "档案下发")


def handle_topo_update(conn, device_key, msg):
    """处理 /v1/devices/{id}/topo/update，回复 updateResponse，
    然后下发档案删除、档案下发命令，完成后退出程序。"""
    device_id = LAST_DEVICE_ID

    devices = msg.get("devices")
    if (
        isinstance(devices, list)
        and devices
        and isinstance(devices[0], dict)
        and devices[0].get("deviceId")
    ):
        device_id = devices[0]["deviceId"]

    response = {
        "mid": "4000",
        "statusDesc": "Success!",
        "statusCode": 0,
        "data": [
            {
                "statusDesc": "success",
                "deviceId": device_id,
                "statusCode": 0,
            }
        ],
    }

    publish_json(
        conn,
        f"/v1/devices/{device_key}/topo/updateResponse",
        response
    )

    # 发送档案删除、档案下发命令并等待响应
    run_command_flow(conn, device_key, device_id)

    raise BrokerShutdown("命令流程已完成，程序退出")


def handle_publish(conn, topic, message):
    """根据主题分发收到的 PUBLISH 消息。"""
    print(f"\n收到消息，主题：{topic}")

    try:
        text = message.decode("utf-8")
        print(text)
        msg = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"消息不是合法的 JSON，忽略：{exc}")
        return

    # 主题格式：/v1/devices/{deviceKey}/topo/{action}
    parts = topic.strip("/").split("/")

    if (
        len(parts) < 5
        or parts[0] != "v1"
        or parts[1] != "devices"
        or parts[3] != "topo"
    ):
        return

    device_key = parts[2]
    action = parts[4]

    if action == "add":
        handle_topo_add(conn, device_key, msg)
    elif action == "update":
        handle_topo_update(conn, device_key, msg)


def print_subscriptions(client_id, subscriptions):
    """打印终端的订阅信息。"""
    print("\n========== 终端订阅信息 ==========")
    print(f"Client ID：{client_id}")
    print(f"用户名：{USERNAME}")
    print("订阅主题：")

    for index, topic in enumerate(
        dict.fromkeys(subscriptions), 1
    ):
        print(f"  {index}. {topic}")

    print("==================================")


def handle_client(conn, addr):
    client_id = None
    subscriptions = []
    subscribed = False
    subscriptions_printed = False
    idle_timeouts = 0

    try:
        conn.settimeout(POLL_TIMEOUT)

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
                idle_timeouts = 0
            except socket.timeout:
                # 首次订阅后等待 SUBSCRIBE_WAIT 秒，
                # 没有新订阅就打印订阅列表，然后继续等待消息
                if subscribed and not subscriptions_printed:
                    idle_timeouts += 1

                    if idle_timeouts * POLL_TIMEOUT >= SUBSCRIBE_WAIT:
                        print_subscriptions(client_id, subscriptions)
                        subscriptions_printed = True
                        print("等待终端消息……（Ctrl+C 退出）")

                continue

            packet_type = header >> 4

            if packet_type == 3:  # PUBLISH
                topic, qos, pub_id, message = parse_publish(
                    header, payload
                )

                if qos == 1 and pub_id is not None:
                    send_packet(conn, 0x40, pub_id)  # PUBACK
                elif qos == 2 and pub_id is not None:
                    send_packet(conn, 0x50, pub_id)  # PUBREC

                handle_publish(conn, topic, message)

            elif packet_type == 6:  # PUBREL
                pub_id = payload[:2]
                send_packet(conn, 0x70, pub_id)  # PUBCOMP

            elif packet_type == 8:  # SUBSCRIBE
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

                # 收到新订阅后重新计时，等待可能到来的其他订阅
                idle_timeouts = 0
                subscriptions_printed = False

            elif packet_type == 12:  # PINGREQ
                send_packet(conn, 0xD0, b"")

            elif packet_type == 14:  # DISCONNECT
                break

        if subscribed and not subscriptions_printed:
            print_subscriptions(client_id, subscriptions)
        elif not subscribed:
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

                try:
                    handle_client(conn, addr)
                except BrokerShutdown as exc:
                    # 已回复 topo/updateResponse，退出程序
                    print(f"\n{exc}")
                    print("监测结束，程序退出")
                    break

    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，正在关闭监听……")
        print("程序已安全退出")


if __name__ == "__main__":
    main()
