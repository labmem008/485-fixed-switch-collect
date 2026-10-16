# -*- coding: utf-8 -*-
"""
TCP Server: 监听 192.168.127.127:9027
时序: 终端(client, 192.168.127.244) 主动连接
      -> 终端先发"预连接请求"
      -> 本程序打印请求内容, 并回复应答帧
      -> 等待 1 秒后发送命令帧
      -> 接收并打印终端的返回
"""

import socket
import binascii
import time
from datetime import datetime

# ===== 配置 =====
SERVER_IP = "192.168.127.127"      # 本机(server)IP
SERVER_PORT = 9027                 # 监听端口
CLIENT_IP = "192.168.127.244"      # 终端(client)IP, 仅用于校验显示
RECV_BUF_SIZE = 4096               # 接收缓冲区大小
RECV_TIMEOUT = 30                  # 等待终端数据的超时时间(秒)

# 收到终端的预连接请求后, 回复的应答帧 (hex)
RESPONSE_HEX = ("68 30 00 01 05 17 00 00 00 00 00 00 56 34 81 00 "
                "80 07 EA 0A 0F 04 09 29 29 00 00 07 EA 0A 0F 04 "
                "09 29 39 00 12 07 EA 0A 0F 04 09 29 39 00 12 "
                "FA 72 16")

# 回复应答帧后, 等待 COMMAND_DELAY 秒再发送的命令帧 (hex)
COMMAND_HEX = ("68 55 00 43 05 17 00 00 00 00 00 09 45 F0 07 01 "
               "0E 60 00 7F 00 02 04 12 00 02 02 0A 55 07 05 00 "
               "00 09 41 09 02 16 03 16 02 51 F2 09 02 01 09 01 "
               "00 11 04 11 01 16 01 12 08 98 12 00 32 02 04 55 "
               "07 05 00 00 00 00 00 00 09 01 00 12 00 01 12 00 "
               "01 01 00 00 0D 7C 16")

COMMAND_DELAY = 1.0                # 回复应答帧后到发送命令帧的等待时间(秒)


def now() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def hex_str(data: bytes) -> str:
    """把 bytes 转成空格分隔的大写十六进制字符串, 方便打印"""
    return " ".join(f"{b:02X}" for b in data)


def recv_and_print(conn, label=""):
    """循环接收并打印数据, 直到超时或连接关闭"""
    while True:
        try:
            data = conn.recv(RECV_BUF_SIZE)
        except socket.timeout:
            print(f"[{now()}] [INFO] {RECV_TIMEOUT} 秒内无数据, 接收结束。")
            return False
        if not data:
            print(f"[{now()}] [INFO] 终端关闭了连接。")
            return False
        print(f"[{now()}] [RECV]{label} ({len(data)} 字节): {hex_str(data)}")


def handle_client(conn, addr, response_data, command_data):
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
            return
        if not request:
            print(f"[{now()}] [INFO] 终端未发数据即关闭连接。")
            return
        print(f"[{now()}] [RECV] 预连接请求 ({len(request)} 字节): {hex_str(request)}")

        # ---- 步骤2: 回复预连接应答帧 ----
        conn.sendall(response_data)
        print(f"[{now()}] [SEND] 预连接应答 ({len(response_data)} 字节): {hex_str(response_data)}")

        # ---- 步骤3: 等待1秒后发送命令帧 ----
        time.sleep(COMMAND_DELAY)
        conn.sendall(command_data)
        print(f"[{now()}] [SEND] 命令帧 ({len(command_data)} 字节): {hex_str(command_data)}")

        # ---- 步骤4: 接收并打印终端的返回 ----
        recv_and_print(conn, " 返回")
    except ConnectionResetError:
        print(f"[{now()}] [ERROR] 连接被终端重置。")
    finally:
        conn.close()
        print(f"[{now()}] [INFO] 连接已关闭, 继续等待下一次连接...\n")


def main():
    response_data = binascii.unhexlify(RESPONSE_HEX.replace(" ", ""))
    command_data = binascii.unhexlify(COMMAND_HEX.replace(" ", ""))
    print(f"[INFO] 预连接应答帧 ({len(response_data)} 字节): {hex_str(response_data)}")
    print(f"[INFO] 命令帧 ({len(command_data)} 字节): {hex_str(command_data)}")

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
          f" -> 等{COMMAND_DELAY:g}秒 -> 发命令帧 -> 接收返回\n")

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn, addr, response_data, command_data)
    except KeyboardInterrupt:
        print("\n[INFO] 用户中断, 服务器退出。")
    finally:
        server.close()


if __name__ == "__main__":
    main()
