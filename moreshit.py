import socket
import time
import json
import struct
import digital_wallet
import requests as req

my_address = "3EuJcabTdjEiMpdtxPtDUeVt6RUdqVGTzB"
now = time.time()

mercaz = ["mfgkdsgkjhfg", 14, b'ARFJNLKJH', 'l', 68]

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


def only_int_is_gud(lst):
    new_lst = []
    for i in lst:
        if type(i) == int:
            new_lst.append(i)
    return new_lst


def get_diff(num):
    num = str(hex(num))
    return int("0x" + num[4:], 16) * 2 ** (8 * (int(num[:4], 16) - 3))


def rec(n):
    if n==1:
        return 1
    return n*rec(n-1)

if __name__ == '__main__':
    print(rec(4))
