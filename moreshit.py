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
    for i in range(10):
        print("https://www.blockchain.com/btc/block/00000000000000000001f218ce346b2a7105de260632ea5af171604cc9f2dd69?" + str(i))


