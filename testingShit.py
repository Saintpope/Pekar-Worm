
import socket
import time
import json
import struct
import digital_wallet

if __name__ == '__main__':
    genesis_block = digital_wallet.make_debug_shit_bytes("01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 3B A3 ED FD  7A 7B 12 B2 7A C7 2C 3E 67 76 8F 61 7F C8 1B C3  88 8A 51 32 3A 9F B8 AA", 64)
    genesis_block += digital_wallet.make_debug_shit_bytes('4B 1E 5E 4A 29 AB 5F 49  FF FF 00 1D 1D AC 2B 7C 01 01 00 00 00 01 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF  FF FF 4D 04 FF FF 00 1D', 64)
    genesis_block += digital_wallet.make_debug_shit_bytes('01 04 45 54 68 65 20 54  69 6D 65 73 20 30 33 2F 4A 61 6E 2F 32 30 30 39  20 43 68 61 6E 63 65 6C 6C 6F 72 20 6F 6E 20 62  72 69 6E 6B 20 6F 66 20 73 65 63 6F 6E 64 20 62  61 69 6C 6F 75 74 20 66', 64)
    genesis_block += digital_wallet.make_debug_shit_bytes('6F 72 20 62 61 6E 6B 73  FF FF FF FF 01 00 F2 05 2A 01 00 00 00 43 41 04  67 8A FD B0 FE 55 48 27 19 67 F1 A6 71 30 B7 10  5C D6 A8 28 E0 39 09 A6 79 62 E0 EA 1F 61 DE B6  49 F6 BC 3F 4C EF 38 C4', 64)
    genesis_block += digital_wallet.make_debug_shit_bytes('F3 55 04 E5 1E C1 12 DE  5C 38 4D F7 BA 0B 8D 57 8A 4C 70 2B 6B F1 1D 5F  AC 00 00 00 00', 29)
    new_block = digital_wallet.parse_block_msg(genesis_block)
    print(new_block)






