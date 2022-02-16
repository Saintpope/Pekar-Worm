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

Addr = namedtuple("Addr", "services ipv6 port")

Branch = namedtuple("Branch", "Block children")

block_tree = Branch(None, [])
is_block_tree_used = False

blockchain_path = r"D:\eilon\works\bitcoinShit\blockchain.txt"
is_blockchain_used = False

transactions_path = r"D:\eilon\works\bitcoinShit\tx.txt"
is_transactions_used = False

addresses_path = r"D:\eilon\works\bitcoinShit\addresses.txt"
is_addresses_used = False

safe_length = 6
my_port = ("node", 18333)
net = "testnet"
my_version = 70001
services = 1
my_ipv6 = 0x00000000000000000000FFFF0A000001.to_bytes(16, 'big')
mining_reward = 6.25

magic_val = {"main": 0xD9B4BEF9, "testnet": 0xDAB5BFFA, "signet": 0x40CF030A, "namecoin": 0xFEB4BEF9}
my_magic_val = 0xDAB5BFFA
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
        magic_num = struct.unpack("<L", msg[:4])[0]
        command = struct.unpack("<12s", msg[4:16])[0]
        length = struct.unpack("<L", msg[16:20])[0]
        checksum = struct.unpack("<4s", msg[20:24])[0]
        payload_bytes = soc.recv(length)
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
    if int(struct.unpack("B", payload[0])[0]) == 253:
        return struct.unpack("<H", payload[1:3])[0], 3
    if int(struct.unpack("B", payload[0])[0]) == 254:
        return struct.unpack("<L", payload[1:5])[0], 5
    if int(struct.unpack("B", payload[0])[0]) == 255:
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
    typ = struct.unpack("<L", payload[:4])
    hsh = struct.unpack("<32s", payload[4:36])
    return typ, hsh


def parse_inv_getdata_notfound_msg(payload):
    length, length_of_len = parse_var_len_int(payload)
    if length > 50000:
        return None
    inv_lst = []
    for i in range(length):
        inv_lst.append(parse_inventory_vector(payload[i * 36 + length_of_len]))
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
    version_tx = struct.unpack("<L", payload[:4])[0]
    flag = struct.unpack("<H", payload[4:6])[0]
    offset_flag = 0
    if flag == 1:
        offset_flag = 2
    txin_len, txin_len_offset = parse_var_len_int(payload[4 + offset_flag:])
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
    lock_time = struct.unpack("<L", payload[total_offset:])[0]
    hsh = ''
    hsh = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return version_tx, txin, txout, lock_time, hsh, total_offset + 4


def parse_block_msg(payload):
    version_blk = struct.unpack("<L", payload[:4])[0]
    prev_block = struct.unpack("<32s", payload[4:36])[0]
    merkle_root = struct.unpack("<32s", payload[36:68])[0]
    timestamp = struct.unpack("<L", payload[68:72])[0]
    bits = struct.unpack("<L", payload[72:76])[0]
    nonce = struct.unpack("<L", payload[76:80])[0]
    tx_count, total_offset = parse_var_len_int(payload[80:])
    tx: List[tuple] = []
    for i in range(tx_count):
        a_tx = parse_tx_msg(payload[80 + total_offset:])
        tx.append(a_tx[:5])
        total_offset += a_tx[5]
    hsh = hashlib.sha256(hashlib.sha256(payload[:80]).digest()).digest()
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
    for i in range(len(inv_vecs)):
        output += create_inventory_vector(inv_vecs[i][0], inv_vecs[i][1])
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
    if extract_comm(msg_tuple[1]) not in ["inv", "blocks", "ping", "pong", "version", "verac", "tx"]:  # check later
        print(1)
        print(extract_comm(msg_tuple[1]))
        return False
    if msg_tuple[2] != len(msg_tuple[4]):
        print(2)
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


def validate_block(blk_tuple):
    hsh_arr = [blk_tuple[7][0][4]]
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

    if blk_tuple[7][0][2][0] != fee_sum + mining_reward:
        return False

    if blk_tuple[2] != calc_merkle_root(hsh_arr):
        return False

    if int(blk_tuple[6]) > blk_tuple[4]:
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
    f.write(json.dumps(info))
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
    return f_txt


def addresses_handle_write(info):  # info = address object arr
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
    f = open(addresses_path, 'r')
    f_txt = json.loads(f.read())
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
        version_msg = create_version_msg(services, ipvsix, porto, my_version, "", 0)
        print("created version msg")
        the_msg = create_msg(version_msg, "version")
        print("created msg")
        s.sendall(the_msg)
    except Exception as e:
        print(e)
        print("went wrong in line 614")
        return -1
    msg_tuple = parse_msg(s)
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
    verac_tuple = parse_msg(s)
    print("line 641")
    if len(verac_tuple) == 0:
        print("line 643")
        return 0
    if (not validate_msg(verac_tuple)) or verac_tuple[1] != "verack":
        print("line 646")
        return 0
    try:
        print("line 649")
        s.sendall(create_msg(struct.pack("x"), "verack"))
    except Exception as e:
        print(e)
        return -2
    addresses = addresses_handle_read()
    addresses.append(Addr(version_tuple[1], ipvsix, porto))
    addresses_handle_write(addresses)
    return pref_version


def create_block_locator_hash():
    block_chain = blockchain_handle_read()
    blk_loc_hsh = []
    for i in range(int(len(block_chain) / 10)):
        blk_loc_hsh.append(block_chain[-10 * i - 1:-(10 * i)].hash)
    if blk_loc_hsh[len(blk_loc_hsh) - 1] != block_chain[0].hash:
        blk_loc_hsh.append(block_chain[0].hash)
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
        s.sendall(create_msg(create_getblocks(agreed_version, create_block_locator_hash(), 0), "getblocks"))
        msg_tuple = parse_msg(s)
        if len(msg_tuple) == 0:
            return False
        if (not validate_msg(msg_tuple)) or msg_tuple[1] != "inv":
            return False
        try:
            inv_tuple = parse_inv_getdata_notfound_msg(msg_tuple[4])
        except Exception as e:
            print(e)
            return False
        if len(inv_tuple) == 0:
            break
        for i in divide_tuple_inv(inv_tuple):
            s.sendall(create_msg(create_getdata_msg(i), "getdata"))
            for j in range(len(i)):
                msg_tuple = parse_msg(s)
                if len(msg_tuple) == 0:
                    return False
                if (not validate_msg(msg_tuple)) or msg_tuple[1] != "block":
                    return False
                try:
                    block_tuple = parse_block_msg(msg_tuple[4])
                except Exception as e:
                    print(e)
                    return False
                if validate_block(block_tuple):
                    b1 = Block(block_tuple[0], block_tuple[1], block_tuple[2], block_tuple[3], block_tuple[4],
                               block_tuple[5], block_tuple[7], block_tuple[6])
                    block_chain = blockchain_handle_read()
                    block_chain.append(b1)
                    blockchain_handle_write(block_chain)
    return True


def add_block_to_tree(block_tuple):
    if not validate_block(block_tuple):
        return False
    cur_b = Branch(Block(block_tuple[0], block_tuple[1], block_tuple[2], block_tuple[3], block_tuple[4], block_tuple[5],
                         block_tuple[7], block_tuple[6]), None)
    global is_block_tree_used
    while is_block_tree_used:
        time.sleep(0.01)
    is_block_tree_used = True
    father = find_father(block_tree, cur_b.Block.prev_block_hash)
    for i in father.children:
        if i.Block.hash == cur_b.Block.hash:
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
            if msg_tuple[1] == "ping":
                s.sendall(create_msg("", "pong"))
            if msg_tuple[1] == "inv":
                inv_list = parse_inv_getdata_notfound_msg(msg_tuple[4])
                req_lst = []
                for i in inv_list:
                    if i[0] == 2:
                        req_lst.append(i)
                s.sendall(create_msg(create_getdata_msg(req_lst), "getdata"))
                for i in req_lst:
                    msg_tuple = parse_msg(s)
                    if (not validate_msg(msg_tuple)) or msg_tuple[1] == "block":
                        s.sendall(create_msg(create_reject_msg(msg_tuple[1], 0x10, "REJECT_INVALID", ""), "reject"))
                    block_tuple = parse_block_msg(msg_tuple[4])
                    if not add_block_to_tree(block_tuple):
                        s.sendall(create_msg(create_reject_msg(msg_tuple[1], 0x10, "REJECT_INVALID", ""), "reject"))
                    add_to_blockchain()
        except Exception as e:
            print(e)
            break


# -----------------------------------------------------random_shit---------------------------------------------------- #
# inferkit


if __name__ == '__main__':
    # msg1 = 0xF9BEB4D974780000000000000000000002010000E293CDBE01000000016DBDDB085B1D8AF75184F0BC01FAD58D1266E9B63B50881990E4B40D6AEE3629000000
    # msg1 = msg1.to_bytes(64, 'big')
    # print(msg1)
    #
    # msg2 = 0x008B483045022100F3581E1972AE8AC7C7367A7A253BC1135223ADB9A468BB3A59233F45BC578380022059AF01CA17D00E41837A1D58E97AA31BAE584EDEC28D
    # msg2 = msg2.to_bytes(64, 'big')
    # print(msg2)
    #
    # msg3 = 0x35BD96923690913BAE9A0141049C02BFC97EF236CE6D8FE5D94013C721E915982ACD2B12B65D9B7D59E20A842005F8FC4E02532E873D37B96F09D6D4511ADA8F
    # msg3 = msg3.to_bytes(64, 'big')
    # print(msg3)
    #
    # msg4 = 0x14042F46614A4C70C0F14BEFF5FFFFFFFF02404B4C00000000001976A9141AA0CD1CBEA6E7458A7ABAD512A9D9EA1AFB225E88AC80FAE9C7000000001976A914
    # msg4 = msg4.to_bytes(64, 'big')
    # print(msg4)
    #
    # msg5 = 0x0EAB5BEA436A0484CFAB12485EFDA0B78B4ECC5288AC00000000
    # msg5 = msg5.to_bytes(26, 'big')
    # print(msg5)
    #
    # msg = msg1 + msg2 + msg3 + msg4 + msg5
    # print(msg)
    # magic_num = my_magic_val
    # command = struct.unpack("<12s", msg[4:16])[0]
    # length = struct.unpack("<L", msg[16:20])[0]
    # checksum = struct.unpack("<4s", msg[20:24])[0]
    # payload_bytes = msg[24:]
    #
    # print(validate_msg((magic_num, command, length, checksum, payload_bytes)))
    # print(parse_tx_msg(msg[24:]))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 18333))
    print("beginning handshake")
    ipv6_test = 0x00000000000000000000FFFF0A000001
    ipv6_test = ipv6_test.to_bytes(16, 'little')
    print(type(ipv6_test))
    print(version_handshake(s, ipv6_test, 18333))
