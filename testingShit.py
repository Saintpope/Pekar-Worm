import bitcoin
import socket

import digital_wallet

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 18333))
    s.listen(1)
    print("server up")
    test_s, client_address = s.accept()
    print("connected, trying handshake")
    ipv6_test = 0x00000000000000000000FFFF0A000001
    ipv6_test = ipv6_test.to_bytes(16, 'little')
    print(digital_wallet.version_handshake(test_s, ipv6_test, 6789))


