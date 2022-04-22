import socket
import time
import json
import struct
import digital_wallet
import requests as req

my_address = "3EuJcabTdjEiMpdtxPtDUeVt6RUdqVGTzB"
now = time.time()


def make_debug_shit_bytes_fixed(stri):
    starr = stri[2:-1].split(r"\x")
    byti = "0x"
    for i in starr:
        lengthi = len(i)
        if lengthi == 1:
            byti += str(hex(ord(i)))[2:]
        elif lengthi == 2:
            byti += i
        elif lengthi > 2:
            byti += i[:2]
            for j in i[2:]:
                byti += str(hex(ord(j)))[2:]

    length = (len(byti)-2)/2
    return int(byti, 16).to_bytes(int(length), 'big')


if __name__ == '__main__':
    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            print(digital_wallet.version_handshake(conn, digital_wallet.convert_ip_address(HOST), 65432))
            print("done")

