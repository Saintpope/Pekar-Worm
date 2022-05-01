import struct
import hashlib
from typing import List
import socket
import random
import time
from collections import namedtuple
import json
import bitcoin

Tx = namedtuple("Tx", "Txins Txouts witnessData locktime is_valid hash")
Txin = namedtuple("Txin", "hash index sig sequence")
Txout = namedtuple("Txout", "value pk_script is_spent")

Block = namedtuple("Block", "version prev_block_hash merkle_root timestamp bits nonce Txs hash")

Addr = namedtuple("Addr", "services ipv6 port")  # ipv6 saved as int

Branch = namedtuple("Branch", "Block children")

block_tree = Branch(Block(0, 0, 0, 0, 0, 0, [], 1), [])
is_block_tree_used = False

blockchain_path = r"D:\eilon\works\bitcoinShit\blockchain.txt"
is_blockchain_used = False

transactions_path = r"D:\eilon\works\bitcoinShit\tx.txt"
is_transactions_used = False

addresses_path = r"D:\eilon\works\bitcoinShit\addresses.txt"

is_addresses_used = False

safe_length = 4
my_port = ("node", 18333)
net = "testnet"
my_version = 70001
services = 1
my_ipv6 = 0x210abd796c9816b.to_bytes(16, 'big')
mining_reward = 50

magic_val = {"main": 0xD9B4BEF9, "testnet": 0xDAB5BFFA, "signet": 0x40CF030A, "namecoin": 0xFEB4BEF9}
my_magic_val = 0xD9B4BEF9
command_lst = ["version", "verack", "addr", "inv", "getdata", "notfound", "getblocks", "getheaders", "tx", "block", ""]


def get_blocks():  # listen and return broadcasted blocks
    pass


def is_valid(previous, proof_of_work):  # gets previous block and check if the block is valid
    # check if hash is the same
    # validate proof of work
    # check signatures
    # check overspending
    pass


def is_sig_valid(msg, pubkey, sign):
    if msg == "bruh":
        return False
    return True


def blockchain_engine(block):  # add blocks to block chain
    pass


class Transaction:
    def __init__(self, to, sender, amount, sign, transactions):
        self.to = to
        self.sender = sender
        self.amount = amount
        self.sign = sign
        self.transactions = transactions
        self.valid = self.is_valid()

    def is_valid(self):
        sumo = 0
        if not is_sig_valid(self.to_string(), self.sender, self.sign):
            return False
        for i in self.transactions:
            if not i.is_valid():
                return False
            if i.to == self.sender:
                sumo += i.amount
        if sumo < self.amount:
            return False

    def to_string(self):
        return str(self.to) + str(self.sender) + str(self.amount)


class BlockChain:
    def __init__(self, header, transactions, proof_of_work):
        self.header = header
        self.transactions = transactions
        self.proof_of_work = proof_of_work
        self.children = []
        self.is_valid = False

    def len_longest_chain(self):
        if len(self.children) == 0:
            return None, 1
        maxi = 0
        maxi_block = None
        for i in self.children:
            length = 1 + i.len_longest_chain()[1]
            if length > maxi:
                maxi = length
                maxi_block = i
        return maxi_block, maxi

    def is_valid(self):
        for i in self.transactions:
            if not i.is_valid():
                return False
        if True:
            pass


def byte_arr_to_str(arr):
    this_string = ""
    for i in arr:
        this_string += str(i)
    return this_string


# --------------------------------------------------------parses------------------------------------------------------ #


def parse_msg(soc):
    try:
        msg = soc.recv(24)
        print(msg)
        magic_num = struct.unpack("<L", msg[:4])[0]
        command = struct.unpack("<12s", msg[4:16])[0]
        length = struct.unpack("<L", msg[16:20])[0]
        checksum = struct.unpack("<4s", msg[20:24])[0]
        payload_bytes = soc.recv(length)
        while len(payload_bytes) < length:
            payload_bytes += soc.recv(length-len(payload_bytes))
        return magic_num, command, length, checksum, payload_bytes
    except Exception as e:
        print(e)
        return ()


def parse_net_addr(payload, is_version, version_net):  # payload is sequence of bytes
    time_net = ""
    total_offset = 0
    if (not is_version) and version_net >= 31402:
        time_net = struct.unpack("<L", payload[:4])[0]
        total_offset = 4
    services_net = struct.unpack("<Q", payload[total_offset:total_offset + 8])[0]
    total_offset += 8
    ipaddr = struct.unpack(">16s", payload[total_offset:total_offset + 16])[0]
    total_offset += 16
    port = struct.unpack(">H", payload[total_offset:total_offset + 2])[0]
    return time_net, services_net, ipaddr, port


def parse_var_len_int(payload):  # return length of field
    if payload[0] < 253:
        return payload[0], 1
    print("length messuring contest")
    if payload[0] == 253:
        print("shit no.1")
        return struct.unpack("<H", payload[1:3])[0], 3
    if payload[0] == 254:
        print("shit no.2")
        return struct.unpack("<L", payload[1:5])[0], 5
    if payload[0] == 255:
        print("shit no.3")
        return struct.unpack("<Q", payload[1:9])[0], 9


def parse_var_len_str(payload):
    length, length_of_len = parse_var_len_int(payload)
    return struct.unpack(create_struct_ord(length), payload[length_of_len:length + length_of_len])[
               0], length + length_of_len


def parse_version_msg(payload):  # payload is sequence of bytes
    version_ver = struct.unpack("<l", payload[:4])[0]
    print(version_ver)
    used_version = min(version_ver, my_version)  # check later
    services_ver = struct.unpack("<Q", payload[4:12])[0]
    print(services_ver)
    timestamp = struct.unpack("<Q", payload[12:20])[0]
    print(timestamp)
    net_addr_recv = parse_net_addr(payload[20:46], True, version_ver)
    print(net_addr_recv)
    net_addr_sender = []
    nonce = ""
    user_agent = ""
    start_height = ""
    relay = False
    if version_ver >= 106:
        net_addr_sender = parse_net_addr(payload[46:72], True, version_ver)
        print(net_addr_sender)
        nonce = struct.unpack("<Q", payload[72:80])[0]
        print(nonce)
        user_agent, temp_len = parse_var_len_str(payload[80:])
        print(temp_len)
        start_height = struct.unpack("<L", payload[80 + temp_len:84 + temp_len])[0]
        print(start_height)
        if version_ver >= 70001:
            relay = struct.unpack("<?", payload[84 + temp_len:])[0]
    return version_ver, services_ver, timestamp, net_addr_recv, net_addr_sender, nonce, user_agent, start_height, relay


def parse_addr_msg(payload):
    length, length_of_len = parse_var_len_int(payload)
    if length > 1000:
        return None
    addr_lst = []
    for i in range(length):
        addr_lst.append(parse_net_addr(payload[i * 30 + length_of_len:], False, 31402))
    return addr_lst


def parse_inventory_vector(payload):
    typ = struct.unpack("<L", payload[:4])[0]
    hsh = struct.unpack("<32s", payload[4:36])[0]
    return typ, hsh


def parse_inv_getdata_notfound_msg(payload):
    length, length_of_len = parse_var_len_int(payload)
    print("got length")
    if length > 50000:
        return None
    inv_lst = []
    print(length)
    for i in range(length):
        print("229 in loop")
        print(i)
        inv_lst.append(parse_inventory_vector(payload[i * 36 + length_of_len:]))
    return inv_lst


# def parse_getblocksheaders_msg(payload): for now, no need to parse that kind of msg
#     version_getblk = struct.unpack("<L", payload[:4])[0]
#     length, length_of_len = parse_var_len_int(payload[4:])
#     block_locator_hashes = []
#     for i in range(length):
#         block_locator_hashes.append(struct.unpack("<p", payload[4+length_of_len+i*32:4+length_of_len+(i+1)*32])[0])
#     hash_stop = struct.unpack("<p", payload[4+length_of_len+length*32:36+length_of_len+length*32])[0]
#     return version_getblk, block_locator_hashes, hash_stop


def parse_outpoint_msg(payload):
    hasho = struct.unpack("<32s", payload[:32])[0]
    index = struct.unpack("<L", payload[32:36])[0]
    print("outpoint")
    print((hasho, index))
    return hasho, index


def parse_txin_msg(payload):
    previous_output = parse_outpoint_msg(payload[:36])[0]
    script_len, script_len_offset = parse_var_len_int(payload[36:])
    sig = \
    struct.unpack(create_struct_ord(script_len), payload[36 + script_len_offset:36 + script_len + script_len_offset])[0]
    sequence = struct.unpack("<L", payload[36 + script_len + script_len_offset:40 + script_len + script_len_offset])[0]
    return previous_output, sig, sequence, 40 + script_len + script_len_offset


def parse_txout_msg(payload):
    value = struct.unpack("<Q", payload[:8])[0]
    pk_script_len, pk_script_len_offset = parse_var_len_int(payload[8:])
    pk_script = struct.unpack(create_struct_ord(pk_script_len),
                              payload[8 + pk_script_len_offset:8 + pk_script_len_offset + pk_script_len])[0]
    return value, pk_script, 8 + pk_script_len_offset + pk_script_len


def parse_witnessdata_msg(payload):
    total_offset = 0
    wd_len, wd_len_offset = parse_var_len_int(payload)
    total_offset += wd_len_offset
    wd = []
    for i in range(wd_len):
        wd_len_temp, wd_len_offset_temp = parse_var_len_int(payload[total_offset:])
        total_offset += wd_len_offset_temp
        wd.append(struct.unpack(create_struct_ord(wd_len_temp), payload[total_offset:total_offset + wd_len_temp])[0])
        total_offset += wd_len_temp
    return wd, total_offset


def parse_tx_msg(payload):
    print("tx")
    version_tx = struct.unpack("<L", payload[:4])[0]
    print(version_tx)
    flag = struct.unpack(">H", payload[4:6])[0]
    print(payload[4:6])
    offset_flag = 0
    if flag == 1:
        offset_flag = 2
    txin_len, txin_len_offset = parse_var_len_int(payload[4 + offset_flag:])
    print("****")
    print(txin_len)
    sum_txin_offset = 0
    txin = []
    for i in range(txin_len):
        a_txin = parse_txin_msg(payload[4 + offset_flag + txin_len_offset + sum_txin_offset:])
        txin.append(a_txin[:3])
        sum_txin_offset += a_txin[3]
    txout_len, txout_len_offset = parse_var_len_int(payload[4 + offset_flag + txin_len_offset + sum_txin_offset:])
    total_offset = 4 + offset_flag + txin_len_offset + sum_txin_offset + txout_len_offset
    txout = []
    print(txout_len)
    for i in range(txout_len):
        print(i)
        a_txout = parse_txout_msg(payload[total_offset:])
        print(a_txout)
        txout.append(a_txout[:2])
        total_offset += a_txout[2]
    wd_offset = 0
    wd = ''
    if flag == 1:
        wd, wd_offset = parse_witnessdata_msg(payload[total_offset:])
    total_offset += wd_offset
    print(payload[total_offset:])
    lock_time = struct.unpack("<L", payload[total_offset:total_offset+4])[0]
    hsh = ''
    hsh = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return txin, txout, lock_time, hsh, total_offset + 4


def parse_block_msg(payload):
    version_blk = struct.unpack("<L", payload[:4])[0]
    print(version_blk)
    prev_block = struct.unpack("<32s", payload[4:36])[0]
    print(prev_block)
    merkle_root = struct.unpack("<32s", payload[36:68])[0]
    print(merkle_root)
    timestamp = struct.unpack("<L", payload[68:72])[0]
    print(timestamp)
    bits = struct.unpack("<L", payload[72:76])[0]
    print(bits)
    nonce = struct.unpack("<L", payload[76:80])[0]
    print(nonce)
    tx_count, total_offset = parse_var_len_int(payload[80:])
    print(tx_count)
    tx: List[tuple] = []
    for i in range(tx_count):
        a_tx = parse_tx_msg(payload[80 + total_offset:])
        print(a_tx)
        tx.append(a_tx[:4])
        total_offset += a_tx[4]
    hsh = hashlib.sha256(hashlib.sha256(payload[:80]).digest()).digest()
    print("block")
    return version_blk, prev_block, merkle_root, timestamp, bits, nonce, hsh, tx


def parse_reject_msg(payload):
    total_offset = 0
    msg_typ, total_offset = parse_var_len_str(payload)
    ccode = struct.unpack("B", payload[total_offset:total_offset + 1])[0]
    total_offset += 1
    reason, temp_offset = parse_var_len_str(payload[total_offset:])
    total_offset += temp_offset
    hsh = struct.unpack("<32s", payload[total_offset:])[0]
    return msg_typ, ccode, reason, hsh


# --------------------------------------------------------parses------------------------------------------------------ #
# ------------------------------------------------------msg_create---------------------------------------------------- #


def create_net_addr(is_for_version, serv, ipvsix, porto):
    print("net_addr")
    if is_for_version:
        return struct.pack('<Q16sH', serv, ipvsix, porto)
    return struct.pack('<LQ16sH', int(time.time()), serv, ipvsix, porto)


def create_version_msg(serv, ipvsix, porto, needed_version, user_agent, start_height):
    if needed_version < 106:
        return struct.pack("<LQQ", my_version, services, int(time.time())) + create_net_addr(True, serv, ipvsix, porto)
    if needed_version >= 106 and needed_version < 70001:
        return struct.pack("<LQQ", my_version, services, int(time.time())) + create_net_addr(True, serv, ipvsix,
                                                                                             porto) + create_net_addr(
            True, services, my_ipv6, my_port[1]) + struct.pack("<Q", random.randint(0, 42069)) + create_var_str(
            user_agent) + struct.pack("<L", start_height)
    if needed_version >= 70001:
        return struct.pack("<LQQ", my_version, services, int(time.time())) + create_net_addr(True, serv, ipvsix,
                                                                                             porto) + create_net_addr(
            True,
            services,
            my_ipv6,
            my_port[
                1]) + struct.pack(
            "<Q", random.randint(0, 42069)) + create_var_str(user_agent) + struct.pack("<L", start_height) + struct.pack("?", False)


def create_var_int(info):  # info can be an array or string
    leni = len(info)
    if leni < 253:
        return struct.pack("<B", leni)
    if leni < 65535:
        return struct.pack("<BH", 253, leni)
    if leni < 4294967295:
        return struct.pack("<BL", 254, leni)
    return struct.pack("<BQ", 255, leni)


def create_var_str(stri):
    return create_var_int(stri) + struct.pack(create_struct_ord(len(stri)), stri.encode())


def create_inventory_vector(typ, hsh):
    return struct.pack("<L", typ) + struct.pack("<32s", hsh)


def create_getdata_msg(inv_vecs):  # gets an array of inv_vec [[typ1,hsh1], .....]
    output = create_var_int(inv_vecs)
    print("line 405")
    for i in range(len(inv_vecs)):
        output += create_inventory_vector(inv_vecs[i][0], inv_vecs[i][1])
        print("line 408")
    print("409")
    return output


def create_command(command):
    order = "<" + str(len(command)) + "s"
    output = struct.pack(order, command.encode())
    while len(output) < 12:
        output += struct.pack("x")
    return output


def create_msg(payload, command):
    return struct.pack("<L", my_magic_val) + create_command(command) + struct.pack("<L", len(payload)) + struct.pack(
        "<L", int.from_bytes(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4], 'little')) + payload


def create_getblocks(agreed_version, block_locator_hashes, hash_stop):
    output = struct.pack("<L", agreed_version) + create_var_int(block_locator_hashes)
    for i in range(len(block_locator_hashes)):
        output += struct.pack("<32s", block_locator_hashes[i])
    output += struct.pack("<32s", hash_stop)
    return output


def create_reject_msg(typ, ccode, ccode_str, hsh_rjct_obj):
    return create_var_str(typ) + struct.pack("B", ccode) + create_var_str(ccode_str) + struct.pack("<32s", hsh_rjct_obj)


# ------------------------------------------------------msg_create---------------------------------------------------- #
# -----------------------------------------------------msg_validate--------------------------------------------------- #


def extract_comm(com):
    stri = ""
    for i in com.decode("utf-8"):
        if i in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                 'u', 'v', 'w', 'x', 'y', 'z']:
            stri += i
    return stri


def validate_msg(msg_tuple):
    if msg_tuple[0] != my_magic_val:
        print(0)
        return False
    if extract_comm(msg_tuple[1]) not in ["inv", "block", "ping", "pong", "version", "verack", "tx", "addr", "getheaders", "alert"]:  # check later
        print(1)
        print(extract_comm(msg_tuple[1]))
        return False
    if msg_tuple[2] != len(msg_tuple[4]):
        print(2)
        print(msg_tuple[2])
        print(len(msg_tuple[4]))
        print(msg_tuple[4])
        return False
    if msg_tuple[3] != hashlib.sha256(hashlib.sha256(msg_tuple[4]).digest()).digest()[:4]:
        print("validate msg")
        print(msg_tuple[3])
        print(hashlib.sha256(hashlib.sha256(msg_tuple[4]).digest()).digest()[:4])
        print(3)
        return False
    return True


def validate_tx(tx_tuple):  # not coinbase txs, create seperate func for them. validation require whole block
    sum_output = 0
    for i in tx_tuple[2]:
        sum_output += i[0]

    sum_input = 0
    spent_tx = []
    for i in tx_tuple[1]:
        itx = search_tx_by_hash_in_blockchain(i[0][0])
        if itx is None:
            return False
        if not itx.is_valid:
            return False
        if itx.Txouts[i[0][0][1]].is_spent:
            return False
        if not bitcoin.ecdsa_verify(itx.hash, i[1], itx.Txouts[i[0][1]].pk_script):
            return False
        sum_input += itx.Txouts[i[0][1]][0]
        spent_tx.append((itx, i[0][1]))

    if sum_input < sum_output:
        return False

    # for i in spent_tx: put in block generator
    #     i[0].Txouts[i[1]].is_spent = True
    #     transsactions_handle_update(i[0])
    return True


def validate_block(blk_tuple):  # "Block", "version prev_block_hash merkle_root timestamp bits nonce hash Txs"
    hsh_arr = [blk_tuple[7][0][3]]
    fee_sum = 0
    for i in range(len(blk_tuple[7]) - 1):  # validate all txs in block
        if not validate_tx(blk_tuple[7][i + 1]):
            return False
        hsh_arr.append(blk_tuple[7][i + 1][4])
        txin_sum = 0
        for j in blk_tuple[7][1]:
            itx = search_tx_by_hash(j[0][0])
            txin_sum += itx.Txouts[j[0][1]][0]
        txout_sum = 0
        for j in blk_tuple[7][2]:
            txout_sum += j[0]
        fee_sum += txin_sum - txout_sum

    if blk_tuple[7][0][1][0][0] * 0.00000001 != fee_sum + mining_reward:
        print("miining fee")
        print(blk_tuple[7][0][2][0][0])
        print(fee_sum + mining_reward)
        return False

    if blk_tuple[2] != calc_merkle_root(hsh_arr):
        print("merkle root")
        return False

    blk_hash_int = int.from_bytes(blk_tuple[6], 'little')
    if blk_hash_int > blk_tuple[4] * 2**(8*(0x1b - 3)):
        print("proof of work")
        print(blk_hash_int)
        print(blk_tuple[6])
        print(blk_tuple[4] * 2**(8*(0x1b - 3)))
        return False
    return True


# -----------------------------------------------------msg_validate--------------------------------------------------- #
# -----------------------------------------------------file_handle---------------------------------------------------- #


def blockchain_handle_write(info):  # info = Block object arr
    global is_blockchain_used
    while is_blockchain_used:
        time.sleep(0.01)
    is_blockchain_used = True
    f = open(blockchain_path, 'w')
    print("*** writing in blockchain")
    print(info)
    print(make_json_ser(info))
    f.write(json.dumps(make_json_ser(info)))
    f.close()
    is_blockchain_used = False


def blockchain_handle_read():
    global is_blockchain_used
    while is_blockchain_used:
        time.sleep(0.01)
    is_blockchain_used = True
    f = open(blockchain_path, 'r')
    f_txt = json.loads(f.read())
    f.close()
    is_blockchain_used = False
    print("*** reading blockchain")
    print(un_ser_shit(f_txt))
    return un_ser_shit(f_txt)


def addresses_handle_write(info):  # info = address object arr ip is int
    global is_addresses_used
    while is_addresses_used:
        time.sleep(0.01)
    is_addresses_used = True
    f = open(addresses_path, 'w')
    f.write(json.dumps(info))
    f.close()
    is_addresses_used = False


def addresses_handle_read():
    global is_addresses_used
    while is_addresses_used:
        time.sleep(0.01)
    is_addresses_used = True
    print("584")
    f = open(addresses_path, 'r')
    print("586")
    f_txt = json.loads(f.read())
    print("588")
    f.close()
    is_addresses_used = False
    return f_txt


def transsactions_handle_write(info):
    global is_transactions_used
    while not is_transactions_used:
        time.sleep(0.01)
    is_transactions_used = True
    f = open(transactions_path, 'w')
    f.write(json.dumps(info))
    f.close()
    is_transactions_used = False


def make_json_ser(heretic_list):
    print("hey i called make json ser")
    new_list = []
    for i in heretic_list:
        if type(i) == bytes or type(i) == int:
            print(type('%s' % i))
            new_list.append('%s' % i)

        elif (type(i) == list or type(i) == tuple) and type(i) != bytes:
            new_list.append(make_json_ser(i))

        elif type(i) != list and type(i) != tuple and type(i) != bytes:
            new_list.append(i)

    return new_list


def un_ser_shit(heretic_list):
    new_list = []
    for i in heretic_list:
        if type(i) == list or type(i) == tuple:
            new_list.append(un_ser_shit(i))
        if type(i) == str and i[0] == 'b':
            print("line 634 :%s" % i)
            new_list.append(make_debug_shit_bytes_fixed(i))
        if type(i) == str and i.isdigit():
            new_list.append(int(i))
    return new_list


def transsactions_handle_read():
    global is_transactions_used
    while is_transactions_used:
        time.sleep(0.01)
    is_transactions_used = True
    f = open(transactions_path, 'r')
    f_txt = json.loads(f.read())
    f.close()
    is_transactions_used = False
    return f_txt


def transsactions_handle_update(new_tx):
    info = transsactions_handle_read()
    for i in info:
        if i.hash == new_tx.hash:
            i = new_tx
    transsactions_handle_write(info)


def tx_update_in_blockchain(new_tx):
    blockchain = blockchain_handle_read()
    for i in blockchain:
        for j in i[6]:
            old_tx = j
            if new_tx[5] == j[5]:  # check if work
                old_tx = new_tx
            j = old_tx
    blockchain_handle_write(blockchain)


def make_tx_seralizable(tx_lst):
    pass

# -----------------------------------------------------file_handle---------------------------------------------------- #
# -----------------------------------------------------random_shit---------------------------------------------------- #


def search_tx_by_hash(hsh):
    txs = transsactions_handle_read()
    for i in txs:
        if i.hash == hsh:
            return i
    return None


def search_block_by_hash(hsh):
    pass


def calc_merkle_root(hsh_arr):
    length = len(hsh_arr)
    if length == 1:
        return hsh_arr[0]
    if length % 2 != 0:
        hsh_arr.append(hsh_arr[length - 1])
        length += 1
    new_hsh_arr = []
    for i in range(int(length / 2)):
        new_hsh_arr.append(hashlib.sha256(hashlib.sha256(hsh_arr[2 * i] + hsh_arr[2 * i + 1]).digest()).digest())
    return calc_merkle_root(new_hsh_arr)


def create_struct_ord(length):
    return "<" + str(length) + "s"


def version_handshake(s, ipvsix, porto):
    try:
        version_msg = create_version_msg(services, ipvsix, porto, my_version, "", 0)  # R --> L version msg
        print("created version msg")
        the_msg = create_msg(version_msg, "version")
        print("created msg")
        s.sendall(the_msg)
    except Exception as e:
        print(e)
        print("went wrong in line 614")
        return -1
    msg_tuple = parse_msg(s)  # L --> R version msg
    print("got msg")
    if len(msg_tuple) == 0:
        print("line 627")
        return 0
    print(validate_msg(msg_tuple))
    print(msg_tuple[1])
    if (not validate_msg(msg_tuple)) or extract_comm(msg_tuple[1]) != "version":
        print("line 630")
        return 0
    try:
        print("line 633")
        version_tuple = parse_version_msg(msg_tuple[4])
    except Exception as e:
        print(e)
        return 0
    pref_version = min(my_version, version_tuple[0])
    print("line 639")

    try:
        print("line 649")
        s.sendall(create_msg(struct.pack("x"), "verack"))  # R --> L verack msg
    except Exception as e:
        print(e)
        return -2

    verac_tuple = parse_msg(s)  # L --> R verack msg
    print("line 641")
    if len(verac_tuple) == 0:
        print("line 643")
        return 0
    if (not validate_msg(verac_tuple)) or extract_comm(verac_tuple[1]) != "verack":
        print(validate_msg(verac_tuple))
        print(extract_comm(verac_tuple[1]))
        print("line 646")
        return 0
    # addresses = addresses_handle_read()
    # print("737")
    # print(version_tuple[1])
    # addresses.append(Addr(version_tuple[1], '%s' % ipvsix, porto))
    # print("739")
    # addresses_handle_write(addresses)
    # print("741")
    return pref_version


def create_block_locator_hash():
    block_chain = blockchain_handle_read()
    print(block_chain)
    blk_loc_hsh = []
    print("block locator hash &&&&&&&&&&&&&&&")
    print(block_chain)

    len_block_chain = len(block_chain)
    if len_block_chain == 0:
        return []
    print(len(block_chain[0]))
    for i in range(len_block_chain):  # change values later
        if i % 10 == 0:
            print(i)
            blk_loc_hsh.append(block_chain[-i][7])
    if not block_chain[0][7] in blk_loc_hsh:
        blk_loc_hsh.append(block_chain[0][7])
    return blk_loc_hsh


def divide_tuple_inv(inv_tuple):
    output = []
    i = 0
    while 128 * (i + 1) < len(inv_tuple):
        output.append(inv_tuple[128 * i:128 * (i + 1)])
        i += 1
    output.append(inv_tuple[128 * i:])
    return output


def init_block_download(s, agreed_version):
    flag = True
    while flag:
        s.sendall(create_msg(create_getblocks(agreed_version, create_block_locator_hash(), 0x0.to_bytes(32, 'big')), "getblocks"))
        print("sent getblocks msg")
        msg_tuple = parse_msg(s)
        if len(msg_tuple) == 0:
            print("744")
            print(msg_tuple)
            return False
        print("807")
        while extract_comm(msg_tuple[1]) != "inv":
            print("809")
            waiting_for_inv(s, msg_tuple)
            msg_tuple = parse_msg(s)
        print("812")
        if (not validate_msg(msg_tuple)) or extract_comm(msg_tuple[1]) != "inv":
            print("747")
            return False
        print("825")
        try:
            inv_tuple = parse_inv_getdata_notfound_msg(msg_tuple[4])
            print("got inv")
        except Exception as e:
            print("752")
            print(e)
            return False
        if len(inv_tuple) == 0:
            break
        print("764")
        for i in divide_tuple_inv(inv_tuple):
            print(i)
            print("sent getdata msgs")
            s.sendall(create_msg(create_getdata_msg(i), "getdata"))
            for j in range(len(i)):
                print("got a blockmsg")
                print(j)
                msg_tuple = parse_msg(s)
                if len(msg_tuple) == 0:
                    print("762")
                    return False
                if (not validate_msg(msg_tuple)) or extract_comm(msg_tuple[1]) != "block":
                    print("765")
                    return False
                try:
                    block_tuple = parse_block_msg(msg_tuple[4])
                except Exception as e:
                    print("770")
                    print(e)
                    return False
                if validate_block(block_tuple):
                    print("saving block")
                    b1 = Block(block_tuple[0], block_tuple[1], block_tuple[2], block_tuple[3], block_tuple[4],
                               block_tuple[5], block_tuple[7], block_tuple[6])
                    block_chain = blockchain_handle_read()
                    block_chain.append(make_json_ser(b1))
                    blockchain_handle_write(block_chain)
    print("finished")
    return True


def add_block_to_tree(block_tuple):
    if not validate_block(block_tuple):
        return False
    cur_b = Branch(Block(block_tuple[0], block_tuple[1], block_tuple[2], block_tuple[3], block_tuple[4], block_tuple[5],
                         block_tuple[7], block_tuple[6]), [])
    global is_block_tree_used
    while is_block_tree_used:
        time.sleep(0.01)
    is_block_tree_used = True
    father = find_father(block_tree, cur_b.Block.prev_block_hash)
    if father is None:
        is_block_tree_used = False
        return False
    print(father)
    for i in father.children:
        if i.Block.hash == cur_b.Block.hash:
            print("dup")
            is_block_tree_used = False
            return False
    father.children.append(cur_b)
    is_block_tree_used = False
    return True


def find_father(branch, hsh):  # only use when tree isn't used unless in add_block_to_tree
    if branch is None:
        return None
    if branch.Block.hash == hsh:
        return branch
    for i in branch.children:
        req = find_father(i, hsh)
        if not (req is None):
            return req
    return None


def add_to_blockchain():
    global block_tree
    global is_block_tree_used
    while is_block_tree_used:
        time.sleep(0.01)
    is_block_tree_used = True
    maxi = [0, None]
    for i in block_tree.children:
        if get_longest_branch(i) > maxi[0]:
            maxi[0] = get_longest_branch(i)
            maxi[1] = i

    if maxi[0] >= safe_length:
        for i in maxi[0][0][6]:
            for j in i[0]:
                tx = search_tx_by_hash_in_blockchain(j[0])
                tx[1][1][2] = False
                tx_update_in_blockchain(tx)
        blockchain = blockchain_handle_read()
        blockchain.append(maxi[1].Block)
        blockchain_handle_write(blockchain)
        block_tree = maxi[1]
        is_block_tree_used = False
        return True

    is_block_tree_used = False
    return False


def get_longest_branch(tree):
    if len(tree.children) == 0:
        return 1
    maxi = 0
    for i in tree.children:
        if get_longest_branch(i) > maxi:
            maxi = get_longest_branch(i)
    return maxi + 1


def search_tx_by_hash_in_blockchain(hsh):
    blockchain = blockchain_handle_read()
    for i in blockchain:
        for j in i[6]:
            if j[5] == hsh:
                return j
    return None


def socket_handler(s, ipvsix, porto):
    agreed_version = version_handshake(s, ipvsix, porto)
    if agreed_version < 1:  # fix later
        return
    init_block_download(s, agreed_version)
    while True:
        try:
            msg_tuple = parse_msg(s)
            if not validate_msg(msg_tuple):
                s.sendall(create_msg(create_reject_msg(msg_tuple[1], 0x10, "REJECT_INVALID", ""), "reject"))
            if extract_comm(msg_tuple[1]) == "ping":
                s.sendall(create_msg(msg_tuple[4], "pong"))
            if extract_comm(msg_tuple[1]) == "inv":
                inv_list = parse_inv_getdata_notfound_msg(msg_tuple[4])
                req_lst = []
                for i in inv_list:
                    if i[0] == 2:
                        req_lst.append(i)
                s.sendall(create_msg(create_getdata_msg(req_lst), "getdata"))
                for i in req_lst:
                    msg_tuple = parse_msg(s)
                    if (not validate_msg(msg_tuple)) or extract_comm(msg_tuple[1]) == "block":
                        s.sendall(create_msg(create_reject_msg(msg_tuple[1], 0x10, "REJECT_INVALID", ""), "reject"))
                    block_tuple = parse_block_msg(msg_tuple[4])
                    if not add_block_to_tree(block_tuple):
                        s.sendall(create_msg(create_reject_msg(msg_tuple[1], 0x10, "REJECT_INVALID", ""), "reject"))
                    add_to_blockchain()
        except Exception as e:
            print(e)
            break


def make_debug_shit_bytes(stri, num_of_bytes):
    byti = "0x"
    for i in stri:
        if i in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']:
            byti += i
        elif not i in ['b', 'x', '\\', ' ']:
            print(str(hex(ord(i)))[:2])
            byti += str(hex(ord(i)))[2:]
    length = (len(byti)-2)/2
    # print("converting this int %s to bytes in line 966" % int(byti, 16))
    print("his length is %s" % length)
    print(byti)
    return int(byti, 16).to_bytes(int(length), 'big')


def make_debug_shit_bytes_fixed(stri):
    print("------------------------")
    print(stri)
    print("------------------------")
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


def convert_ip_address(ip_address):
    ip_lst = ip_address.split(".")
    return struct.pack("xxxxxxxxxxxx") + struct.pack("B", int(ip_lst[0])) + struct.pack("B", int(ip_lst[1])) + struct.pack("B", int(ip_lst[2])) + struct.pack("B", int(ip_lst[3]))


def waiting_for_inv(s, msg_tuple):
    try:
        if not validate_msg(msg_tuple):
            s.sendall(create_msg(create_reject_msg(extract_comm(msg_tuple[1]), 0x10, "REJECT_INVALID", ""), "reject"))
        elif extract_comm(msg_tuple[1]) == "ping":
            s.sendall(create_msg(msg_tuple[4], "pong"))
        else:
            s.sendall(create_msg(create_reject_msg(extract_comm(msg_tuple[1]), 0x40, "REJECT_NONSTANDARD", ""), "reject"))
    except Exception as e:
        print(e)
        print("1018")

# -----------------------------------------------------random_shit---------------------------------------------------- #
# inferkit


if __name__ == '__main__':
    # genesis_block = make_debug_shit_bytes("01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 3B A3 ED FD  7A 7B 12 B2 7A C7 2C 3E 67 76 8F 61 7F C8 1B C3  88 8A 51 32 3A 9F B8 AA", 64)
    # genesis_block += make_debug_shit_bytes('4B 1E 5E 4A 29 AB 5F 49  FF FF 00 1D 1D AC 2B 7C 01 01 00 00 00 01 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF  FF FF 4D 04 FF FF 00 1D', 64)
    # genesis_block += make_debug_shit_bytes('01 04 45 54 68 65 20 54  69 6D 65 73 20 30 33 2F 4A 61 6E 2F 32 30 30 39  20 43 68 61 6E 63 65 6C 6C 6F 72 20 6F 6E 20 62  72 69 6E 6B 20 6F 66 20 73 65 63 6F 6E 64 20 62  61 69 6C 6F 75 74 20 66', 64)
    # genesis_block += make_debug_shit_bytes('6F 72 20 62 61 6E 6B 73  FF FF FF FF 01 00 F2 05 2A 01 00 00 00 43 41 04  67 8A FD B0 FE 55 48 27 19 67 F1 A6 71 30 B7 10  5C D6 A8 28 E0 39 09 A6 79 62 E0 EA 1F 61 DE B6  49 F6 BC 3F 4C EF 38 C4', 64)
    # genesis_block += make_debug_shit_bytes('F3 55 04 E5 1E C1 12 DE  5C 38 4D F7 BA 0B 8D 57 8A 4C 70 2B 6B F1 1D 5F  AC 00 00 00 00', 29)
    #
    # print(add_block_to_tree((0, 1, 0, 0, 0, 0, 2, [])))
    # print(add_to_blockchain())
    # print(add_block_to_tree((0, 2, 0, 0, 0, 0, 3, [])))
    # print(add_to_blockchain())
    # print(add_block_to_tree((0, 3, 0, 0, 0, 0, 4, [])))
    # print(add_to_blockchain())
    # print(add_block_to_tree((0, 4, 0, 0, 0, 0, 5, [])))
    # print(add_to_blockchain())
    # print(add_block_to_tree((0, 5, 0, 0, 0, 0, 6, [])))
    # print(add_to_blockchain())
    # print(add_block_to_tree((0, 1, 0, 0, 0, 0, 21, [])))
    # print(add_to_blockchain())
    disired_address = "89.138.132.18"

    blockchain_handle_write([])
    print(convert_ip_address(disired_address))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((disired_address, 8333))
        socket_handler(sock, convert_ip_address(disired_address), 8333)

