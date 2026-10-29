# -*- coding: utf-8 -*-
"""
TCP Server: 监听 192.168.127.127:9027
时序: 终端(client, 192.168.127.244) 主动连接
      -> 终端先发"预连接请求"
      -> 本程序打印请求内容, 并回复应答帧
      -> 等待 1 秒后发送命令帧
      -> 接收并打印终端的返回
      -> 收到响应后自动安全退出程序
      -> 若终端 10 秒未响应命令帧, 关闭连接并安全退出
"""

import socket
import binascii
import time
from datetime import datetime

from fcs import calc_fcs

# ===== 配置 =====
SERVER_IP = "192.168.127.127"      # 本机(server)IP
SERVER_PORT = 9027                 # 监听端口
CLIENT_IP = "192.168.127.244"      # 终端(client)IP, 仅用于校验显示
RECV_BUF_SIZE = 4096               # 接收缓冲区大小
RECV_TIMEOUT = 30                  # 等待终端数据的超时时间(秒)
COMMAND_RESPONSE_TIMEOUT = 10      # 等待终端响应命令帧的超时时间(秒), 超时则关闭连接并退出
RESPONSE_GRACE_TIMEOUT = 2.0       # 已收到响应但帧不完整时, 等待后续数据的宽限时间(秒)

# 收到终端的预连接请求后, 回复的应答基础帧 (hex)
# 发送前会由 build_frame() 按实际终端地址修改地址域(第6字节起6字节),
# 并重算HCS(第13、14字节)和FCS(倒数第2、3字节)
RESPONSE_HEX = ("68 30 00 01 05 17 00 00 00 00 00 00 56 34 81 00 "
                "80 07 EA 0A 0F 04 09 29 29 00 00 07 EA 0A 0F 04 "
                "09 29 39 00 12 07 EA 0A 0F 04 09 29 39 00 12 "
                "FA 72 16")

# 回复应答帧后, 等待 COMMAND_DELAY 秒再发送的命令帧 (hex)
COMMAND_HEX = ("68 47 02 43 05 17 00 00 00 00 00 09 6C 72 07 01 22 60 00 80 00 01 09 02 04 12 00 02 02 0A 55 07 05 00 00 09 41 09 02 16 03 16 02 51 F2 09 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 03 02 0A 55 07 05 00 00 09 41 05 99 16 03 16 02 51 F2 01 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 06 02 0A 55 07 05 34 34 48 00 03 22 16 03 16 02 51 F2 01 02 02 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 07 02 0A 55 07 05 00 00 09 41 06 28 16 03 16 02 51 F2 01 02 03 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 08 02 0A 55 07 05 16 01 04 46 18 41 16 03 16 02 51 F2 01 02 04 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 09 02 0A 55 07 05 34 34 48 00 00 61 16 03 16 02 51 F2 09 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 0A 02 0A 55 07 05 34 34 48 00 01 18 16 03 16 02 51 F2 09 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 0C 02 0A 55 07 05 16 01 04 46 19 40 16 03 16 02 51 F2 09 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 02 04 12 00 0D 02 0A 55 07 05 34 34 53 00 01 77 16 03 16 02 51 F2 09 02 01 09 01 00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 01 01 00 00 E8 6E 16")

COMMAND_DELAY = 1.0                # 回复应答帧后到发送命令帧的等待时间(秒)


def now() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def hex_str(data: bytes) -> str:
    """把 bytes 转成空格分隔的大写十六进制字符串, 方便打印"""
    return " ".join(f"{b:02X}" for b in data)


def build_frame(base_frame: bytes, terminal_addr: bytes) -> bytes:
    """根据终端地址修改基础帧: 只改终端地址、HCS和FCS三部分。

    - 终端地址: 帧的第6字节开始, 共6字节(小端), 直接填入 terminal_addr;
    - HCS: 帧的第13、14字节(frame[12:14]), 算法与FCS相同,
      对第2个字节开始的11字节帧头(frame[1:12])计算;
    - FCS: 倒数第2、3字节, 用 fcs.calc_fcs 对 frame[1:-3]
      (除起始符68、FCS本身、结束符16外的所有字节) 重新计算。
    """
    frame = bytearray(base_frame)
    frame[5:11] = terminal_addr
    frame[12:14] = calc_fcs(bytes(frame[1:12]))   # HCS: 帧头11字节
    frame[-3:-1] = calc_fcs(bytes(frame[1:-3]))   # FCS: 整帧(除68/FCS/16)
    return bytes(frame)


def is_frame_complete(buf: bytes) -> bool:
    """判断缓冲区开头是否为一个完整帧: 0x68 起始, 帧总长 = 第2字节 + 2, 结束符 0x16"""
    if len(buf) < 3 or buf[0] != 0x68:
        return False
    total = buf[1] + 2
    return len(buf) >= total and buf[total - 1] == 0x16


def wait_for_response(conn):
    """等待终端对命令帧的响应, 并尽量收完整。

    返回值:
      bytes -- 收到的响应数据(完整帧, 或宽限超时前收到的数据)
      None  -- 终端一直没有响应(超时或直接断开)
    """
    buf = b""
    conn.settimeout(COMMAND_RESPONSE_TIMEOUT)
    while True:
        try:
            data = conn.recv(RECV_BUF_SIZE)
        except socket.timeout:
            if buf:
                print(f"[{now()}] [WARN] {RESPONSE_GRACE_TIMEOUT} 秒内无新数据, "
                      f"以已收到的 {len(buf)} 字节为准退出。")
                return buf
            print(f"[{now()}] [ERROR] {COMMAND_RESPONSE_TIMEOUT} 秒内未收到终端响应。")
            return None
        if not data:
            if buf:
                print(f"[{now()}] [INFO] 终端关闭了连接, 响应已收完。")
                return buf
            print(f"[{now()}] [INFO] 终端未响应即关闭连接。")
            return None
        buf += data
        print(f"[{now()}] [RECV] 响应 ({len(data)} 字节): {hex_str(data)}")
        if is_frame_complete(buf):
            print(f"[{now()}] [INFO] 收到完整响应帧 (共 {len(buf)} 字节)。")
            return buf
        # 帧还不完整(或非 68...16 格式), 用短超时等待剩余部分
        conn.settimeout(RESPONSE_GRACE_TIMEOUT)


def handle_client(conn, addr, response_base, command_base):
    """处理一次终端连接。收到命令帧的响应返回 True(程序应退出), 否则返回 False。"""
    print(f"[{now()}] [INFO] 终端已连接: {addr[0]}:{addr[1]}")
    if addr[0] != CLIENT_IP:
        print(f"[{now()}] [WARN] 连接的IP不是预期的 {CLIENT_IP}, 仍然继续处理。")

    conn.settimeout(RECV_TIMEOUT)
    try:
        # ---- 步骤1: 等待终端发来预连接请求 ----
        try:
            request = conn.recv(RECV_BUF_SIZE)
        except socket.timeout:
            print(f"[{now()}] [ERROR] 等待预连接请求超时 ({RECV_TIMEOUT} 秒)。")
            return False
        if not request:
            print(f"[{now()}] [INFO] 终端未发数据即关闭连接。")
            return False
        print(f"[{now()}] [RECV] 预连接请求 ({len(request)} 字节): {hex_str(request)}")

        # 提取终端地址: 帧的第6个字节开始, 共6字节(小端)
        terminal_addr = request[5:11]
        print(f"[{now()}] [INFO] 终端地址(小端): {hex_str(terminal_addr)} -> 正常序: {hex_str(terminal_addr[::-1])}")

        # 根据终端地址修改基础帧(仅终端地址 + FCS 两部分)
        response_data = build_frame(response_base, terminal_addr)
        command_data = build_frame(command_base, terminal_addr)

        # ---- 步骤2: 回复预连接应答帧 ----
        conn.sendall(response_data)
        print(f"[{now()}] [SEND] 预连接应答 ({len(response_data)} 字节): {hex_str(response_data)}")

        # ---- 步骤3: 等待1秒后发送命令帧 ----
        time.sleep(COMMAND_DELAY)
        conn.sendall(command_data)
        print(f"[{now()}] [SEND] 命令帧 ({len(command_data)} 字节): {hex_str(command_data)}")

        # ---- 步骤4: 等待终端响应, 收到后退出程序;
        #      10秒未响应也关闭连接并退出程序 ----
        if wait_for_response(conn) is None:
            print(f"[{now()}] [WARN] 终端 {COMMAND_RESPONSE_TIMEOUT} 秒未响应命令帧, "
                  f"关闭连接并退出程序。")
        return True
    except ConnectionResetError:
        print(f"[{now()}] [ERROR] 连接被终端重置。")
        return False
    except OSError as e:
        print(f"[{now()}] [ERROR] 网络错误: {e}")
        return False
    finally:
        conn.close()
        print(f"[{now()}] [INFO] 本次连接已关闭。")


def main():
    response_base = binascii.unhexlify(RESPONSE_HEX.replace(" ", ""))
    command_base = binascii.unhexlify(COMMAND_HEX.replace(" ", ""))
    # print(f"[INFO] 预连接应答帧 ({len(response_data)} 字节): {hex_str(response_data)}")
    # print(f"[INFO] 命令帧 ({len(command_data)} 字节): {hex_str(command_data)}")

    # 创建 TCP socket 并绑定监听
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((SERVER_IP, SERVER_PORT))
    except OSError as e:
        print(f"[ERROR] 绑定 {SERVER_IP}:{SERVER_PORT} 失败: {e}")
        print("        请确认本机网卡已配置该IP地址。")
        server.close()
        return

    server.listen(1)
    print(f"[INFO] 服务器已启动, 监听 {SERVER_IP}:{SERVER_PORT}, 等待终端 {CLIENT_IP} 连接...")
    print(f"[INFO] 时序: 终端连接 -> 终端发预连接请求 -> 回复应答帧"
          f" -> 等{COMMAND_DELAY:g}秒 -> 发命令帧 -> 收到响应(或{COMMAND_RESPONSE_TIMEOUT}秒未响应)"
          f" -> 自动退出\n")

    try:
        while True:
            conn, addr = server.accept()
            if handle_client(conn, addr, response_base, command_base):
                print(f"[{now()}] [INFO] 本次交互结束(收到响应或终端超时未响应), "
                      f"任务完成, 程序自动退出。")
                break
            print(f"[{now()}] [INFO] 继续等待下一次连接...\n")
    except KeyboardInterrupt:
        print("\n[INFO] 用户中断, 服务器退出。")
    finally:
        server.close()
        print(f"[{now()}] [INFO] 监听套接字已关闭, 再见。")


if __name__ == "__main__":
    main()
