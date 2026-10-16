
import socket
import time
from datetime import datetime


# ==================== 基本配置 ====================
HOST = "192.168.14.101"
PORT = 2404
TIMEOUT = 15
BUFFER_SIZE = 4096

# IEC 60870-5-104 风格的控制序号，原始字段每次增加 2
tx_next = 0
rx_next = 0
rx_i_count = 0

sock = None
buffer = bytearray()


def log(msg):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{now}] {msg}", flush=True)


def hx(data):
    return data.hex(" ").upper()


def parse_hex(s):
    return bytes.fromhex(s)


def send_raw(data, desc):
    """发送原始报文并打印"""
    log(f"发送（{desc}）：{hx(data)}")
    sock.sendall(data)


def send_i_frame(template, desc):
    """
    发送 I 格式报文。
    动态填充发送序号和接收确认序号，避免沿用固定序号。
    """
    global tx_next

    frame = bytearray(template)
    frame[2:4] = tx_next.to_bytes(2, "little")
    frame[4:6] = rx_next.to_bytes(2, "little")

    current_ns = tx_next
    tx_next = (tx_next + 2) & 0xFFFF

    send_raw(bytes(frame), f"{desc}，发送序号={current_ns // 2}")
    return bytes(frame)


def send_s_ack():
    """发送 S 格式确认，确认已接收的 I 格式报文"""
    frame = bytes([
        0x68, 0x04, 0x01, 0x00,
        rx_next & 0xFF, (rx_next >> 8) & 0xFF
    ])
    send_raw(frame, f"接收序号确认 N(R)={rx_next // 2}")


def extract_frame():
    """按照 68 + 长度 + 2 字节的格式从 TCP 字节流提取完整帧"""
    while buffer:
        if buffer[0] != 0x68:
            try:
                pos = buffer.index(0x68)
                log(f"丢弃帧前无效数据：{hx(buffer[:pos])}")
                del buffer[:pos]
            except ValueError:
                log(f"丢弃无效数据：{hx(buffer)}")
                buffer.clear()
                return None

        if len(buffer) < 2:
            return None

        total_len = buffer[1] + 2
        if len(buffer) < total_len:
            return None

        frame = bytes(buffer[:total_len])
        del buffer[:total_len]
        return frame

    return None


def recv_frame(deadline):
    """接收一帧完整报文，支持 TCP 粘包、拆包"""
    while True:
        frame = extract_frame()
        if frame is not None:
            log(f"接收：{hx(frame)}")
            return frame

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("等待报文超时")

        sock.settimeout(remaining)
        data = sock.recv(BUFFER_SIZE)

        if not data:
            raise ConnectionError("对端关闭 TCP 连接")

        log(f"TCP 收到 {len(data)} 字节")
        buffer.extend(data)


def handle_frame(frame):
    """
    处理公共通信机制：
    1. 收到测试激活帧 43，回复测试确认帧 83。
    2. 更新收到的 I 格式报文序号。
    3. 每累计 8 帧 I 格式报文发送 S 格式确认。
    """
    global rx_next, rx_i_count

    # IEC 104 风格的 TESTFR act -> TESTFR con
    if frame == parse_hex("68 04 43 00 00 00"):
        send_raw(
            parse_hex("68 04 83 00 00 00"),
            "测试激活确认 TESTFR con"
        )
        return False

    # I 格式：控制域第一个字节最低位为 0
    if len(frame) >= 6 and (frame[2] & 0x01) == 0:
        ns = int.from_bytes(frame[2:4], "little")
        rx_next = (ns + 2) & 0xFFFF
        rx_i_count += 1

        if rx_i_count >= 8:
            send_s_ack()
            rx_i_count = 0

    return True


def wait_for(predicate, desc, timeout=TIMEOUT):
    """
    持续收帧，自动处理周期性测试帧及 I 帧确认。
    只有满足当前步骤条件才返回。
    """
    deadline = time.monotonic() + timeout
    log(f"等待：{desc}")

    while True:
        frame = recv_frame(deadline)
        handle_frame(frame)

        if predicate(frame):
            log(f"匹配成功：{desc}")
            return frame

        log(f"当前报文不属于目标应答，继续等待：{desc}")


def exact(hex_string):
    expected = parse_hex(hex_string)
    return lambda frame: frame == expected


def i_frame_type_cot(type_id, cot):
    """匹配 I 帧的类型标识、传送原因及公共地址"""
    def match(frame):
        return (
            len(frame) >= 12
            and frame[0] == 0x68
            and frame[6] == type_id
            and frame[8:10] == bytes([cot, 0x00])
            and frame[10:12] == b"\x01\x00"
        )
    return match


def make_clock_sync():
    """构造当前电脑本地时间的 CP56Time2a 时钟同步报文"""
    now = datetime.now()

    ms_in_minute = (
        now.second * 1000 + now.microsecond // 1000
    )

    # CP56Time2a：毫秒、分钟、小时、日期+星期、月份、年份
    cp56 = bytes([
        ms_in_minute & 0xFF,
        (ms_in_minute >> 8) & 0xFF,
        now.minute,
        now.hour,
        now.day | (now.isoweekday() << 5),
        now.month,
        now.year % 100
    ])

    # I 帧控制域由 send_i_frame 动态填写
    return parse_hex(
        "68 14 00 00 00 00 "
        "67 01 06 00 01 00 00 00 00"
    ) + cp56


def match_payload(expected_hex):
    """
    比较报文长度字段及控制域之后的业务内容。
    允许应答的收发序号与示例日志不同。
    """
    expected = parse_hex(expected_hex)

    def match(frame):
        return (
            len(frame) == len(expected)
            and frame[0:2] == expected[0:2]
            and frame[6:] == expected[6:]
        )

    return match


def main():
    global sock, tx_next, rx_next, rx_i_count

    # 每次程序启动，序号从本次新建连接的初始状态开始
    tx_next = 0
    rx_next = 0
    rx_i_count = 0

    try:
        log("=" * 60)
        log("开始执行：初始化 -> 总召唤 -> 时钟同步 -> 写定值 -> 固化")
        log(f"连接 {HOST}:{PORT}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((HOST, PORT))
        log("TCP 连接成功")

        # ------------------------------------------------
        # 1. 初始化
        # ------------------------------------------------
        log("步骤 1/5：初始化")

        send_raw(
            parse_hex("68 04 07 00 00 00"),
            "初始化请求"
        )

        wait_for(
            exact("68 04 0B 00 00 00"),
            "初始化应答 1"
        )

        wait_for(
            exact("68 0E 00 00 00 00 46 01 04 00 01 00 00 00 00 02"),
            "初始化应答 2"
        )

        log(f"初始化完成，当前接收确认序号={rx_next // 2}")

        # ------------------------------------------------
        # 2. 总召唤
        # ------------------------------------------------
        log("步骤 2/5：发送总召唤")

        total_call = parse_hex(
            "68 0E 00 00 02 00 "
            "64 01 06 00 01 00 00 00 00 14"
        )
        send_i_frame(total_call, "总召唤请求")

        # 激活确认：类型 64，传送原因 07
        wait_for(
            i_frame_type_cot(0x64, 0x07),
            "总召唤激活确认"
        )

        # 总召唤期间持续接收遥信、遥测等数据，
        # 直到收到类型 64、传送原因 0A 的激活终止帧。
        wait_for(
            i_frame_type_cot(0x64, 0x0A),
            "总召唤激活终止"
        )

        log("总召唤完成")

        # ------------------------------------------------
        # 3. 时钟同步
        # ------------------------------------------------
        log("步骤 3/5：时钟同步")

        clock_frame = make_clock_sync()
        clock_payload = clock_frame[15:]
        send_i_frame(clock_frame, "时钟同步请求")

        def clock_ack(frame):
            return (
                len(frame) == len(clock_frame)
                and frame[0:2] == clock_frame[0:2]
                and frame[6:12] == bytes([
                    0x67, 0x01, 0x07, 0x00, 0x01, 0x00
                ])
                and frame[15:] == clock_payload
            )

        wait_for(clock_ack, "时钟同步确认")
        log("时钟同步完成")

        # ------------------------------------------------
        # 4. 写定值
        # ------------------------------------------------
        log("步骤 4/5：写定值")

        write_frame = parse_hex(
            "68 43 04 00 86 00 CB 07 06 00 01 00 00 00 80 "
            "2C 88 00 01 01 01 2E 88 00 26 04 00 00 80 3F "
            "2F 88 00 01 01 01 31 88 00 26 04 00 00 80 3F "
            "32 88 00 26 04 00 00 80 3F 33 88 00 26 04 00 "
            "00 80 3F 3B 88 00 01 01 01"
        )

        send_i_frame(write_frame, "写定值请求")

        write_ack = (
            "68 43 86 00 06 00 CB 07 07 00 01 00 00 00 80 "
            "2C 88 00 01 01 01 2E 88 00 26 04 00 00 80 3F "
            "2F 88 00 01 01 01 31 88 00 26 04 00 00 80 3F "
            "32 88 00 26 04 00 00 80 3F 33 88 00 26 04 00 "
            "00 80 3F 3B 88 00 01 01 01"
        )

        wait_for(
            match_payload(write_ack),
            "写定值完成应答"
        )
        log("定值写入成功")

        # ------------------------------------------------
        # 5. 固化定值
        # ------------------------------------------------
        log("步骤 5/5：固化定值")

        save_frame = parse_hex(
            "68 0D 06 00 88 00 CB 00 06 00 01 00 00 00 00"
        )
        send_i_frame(save_frame, "固化定值请求")

        save_ack = (
            "68 0D 88 00 08 00 CB 00 07 00 01 00 00 00 00"
        )

        wait_for(
            match_payload(save_ack),
            "固化定值完成应答"
        )

        log("=" * 60)
        log("全部流程成功：初始化、总召唤、时钟同步、写定值、固化")

    except socket.timeout:
        log("Socket 接收超时，流程终止，不自动重发业务报文")

    except TimeoutError as exc:
        log(f"等待超时：{exc}，流程终止")

    except ConnectionError as exc:
        log(f"连接异常：{exc}，流程终止")

    except OSError as exc:
        log(f"Socket 异常：{exc}")

    except Exception as exc:
        log(f"程序异常：{type(exc).__name__}: {exc}")

    finally:
        if sock is not None:
            try:
                sock.close()
                log("TCP 连接已关闭")
            except OSError:
                pass

        log("程序结束")


if __name__ == "__main__":
    main()
