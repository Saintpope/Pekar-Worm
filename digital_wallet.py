
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

blockchain_path = ""
is_blockchain_used = False

transactions_path = ""
is_transactions_used = False

addresses_path = ""
is_addresses_used = False

safe_length = 6
my_port = ("node", 18333)
net = "testnet"
my_version = 70001
services = 1
my_ipv6 = 0
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
    if (not is_version) and version_net >= 31402:
        time_net = struct.unpack("<L", payload[:4])[0]
    services_net = struct.unpack("<Q", payload[4:12])[0]
    ipaddr = struct.unpack(">16s", payload[12:28])[0]
    port = struct.unpack(">H", payload[28:30])[0]
    return time_net, services_net, ipaddr, port


def parse_var_len_int(payload):  # return length of field
    if struct.unpack("B", payload[0])[0] < 253:
        return struct.unpack("B", payload[0])[0], 1
    if struct.unpack("B", payload[0])[0] == 253:
        return struct.unpack("<H", payload[1:3])[0], 3
    if struct.unpack("B", payload[0])[0] == 254:
        return struct.unpack("<L", payload[1:5])[0], 5
    if struct.unpack("B", payload[0])[0] == 255:
        return struct.unpack("<Q", payload[1:9])[0], 9


def parse_var_len_str(payload):
    length, length_of_len = parse_var_len_int(payload)
    return struct.unpack(create_struct_ord(length), payload[length_of_len:length+length_of_len])[0], length+length_of_len


def parse_version_msg(payload):  # payload is sequence of bytes
    version_ver = struct.unpack("<L", payload[:4])[0]
    used_version = min(version_ver, my_version)  # check later
    services_ver = struct.unpack("<Q", payload[4:12])[0]
    timestamp = struct.unpack("<Q", payload[12:20])[0]
    net_addr_recv = parse_net_addr(payload[20:46], True, version_ver)
    net_addr_sender = ""
    nonce = ""
    user_agent = ""
    start_height = ""
    relay = False
    if version_ver >= 106:
        net_addr_sender = parse_net_addr(payload[46:72], True, version_ver)
        nonce = struct.unpack("<Q", payload[72:80])[0]
        user_agent, temp_len = parse_var_len_str(payload[80:])
        start_height = struct.unpack("<L", payload[80+temp_len:84+temp_len])[0]
        if version_ver >= 70001:
            relay = struct.unpack("?", payload[84+temp_len:85+temp_len])[0]
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
        inv_lst.append(parse_inventory_vector(payload[i*36+length_of_len]))
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
    sig = struct.unpack(create_struct_ord(script_len), payload[36+script_len_offset:36+script_len+script_len_offset])[0]
    sequence = struct.unpack("<L", payload[36+script_len+script_len_offset:40+script_len+script_len_offset])[0]
    return previous_output, sig, sequence, 40+script_len+script_len_offset


def parse_txout_msg(payload):
    value = struct.unpack("<Q", payload[:8])[0]
    pk_script_len, pk_script_len_offset = parse_var_len_int(payload[8:])
    pk_script = struct.unpack(create_struct_ord(pk_script_len), payload[8+pk_script_len_offset:8+pk_script_len_offset+pk_script_len])[0]
    return value, pk_script, 8+pk_script_len_offset+pk_script_len


def parse_witnessdata_msg(payload):
    total_offset = 0
    wd_len, wd_len_offset = parse_var_len_int(payload)
    total_offset += wd_len_offset
    wd = []
    for i in range(wd_len):
        wd_len_temp, wd_len_offset_temp = parse_var_len_int(payload[total_offset:])
        total_offset += wd_len_offset_temp
        wd.append(struct.unpack(create_struct_ord(wd_len_temp), payload[total_offset:total_offset+wd_len_temp])[0])
        total_offset += wd_len_temp
    return wd, total_offset


def parse_tx_msg(payload):
    version_tx = struct.unpack("<L", payload[:4])[0]
    flag = struct.unpack("<H", payload[4:6])[0]
    offset_flag = 0
    if flag == 1:
        offset_flag = 2
    txin_len, txin_len_offset = parse_var_len_int(payload[4+offset_flag:])
    sum_txin_offset = 0
    txin = []
    for i in range(txin_len):
        a_txin = parse_txin_msg(payload[4+offset_flag+txin_len_offset+sum_txin_offset:])
        txin.append(a_txin[:3])
        sum_txin_offset += a_txin[3]
    txout_len, txout_len_offset = parse_var_len_int(payload[4+offset_flag+txin_len_offset+sum_txin_offset:])
    total_offset = 4+offset_flag+txin_len_offset+sum_txin_offset+txout_len_offset
    txout = []
    for i in range(txout_len):
        a_txout = parse_txout_msg(payload[total_offset:])
        txout.append(a_txout[:3])
        total_offset += a_txout[3]
    wd, wd_offset = parse_witnessdata_msg(payload[total_offset:])
    total_offset += wd_offset
    lock_time = struct.unpack("<L", payload[:-4])
    hsh = hashlib.sha256(hashlib.sha256(payload))
    return version_tx, txin, txout, lock_time, hsh, total_offset+4


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
        a_tx = parse_tx_msg(payload[80+total_offset:])
        tx.append(a_tx[:5])
        total_offset += a_tx[5]
    hsh = hashlib.sha256(hashlib.sha256(payload[:80]))
    return version_blk, prev_block, merkle_root, timestamp, bits, nonce, hsh, tx


def parse_reject_msg(payload):
    total_offset = 0
    msg_typ, total_offset = parse_var_len_str(payload)
    ccode = struct.unpack("B", payload[total_offset:total_offset+1])[0]
    total_offset += 1
    reason, temp_offset = parse_var_len_str(payload[total_offset:])
    total_offset += temp_offset
    hsh = struct.unpack("<32s", payload[total_offset:])[0]
    return msg_typ, ccode, reason, hsh


# --------------------------------------------------------parses------------------------------------------------------ #
# ------------------------------------------------------msg_create---------------------------------------------------- #


def create_net_addr(is_for_version, serv, ipvsix, porto):
    if is_for_version:
        return struct.pack('<QpH', serv, ipvsix, porto)
    return struct.pack('<LQpH', time.time(), serv, ipvsix, porto)


def create_version_msg(serv, ipvsix, porto, needed_version, user_agent, start_height):
    if needed_version < 106:
        return struct.pack("<LQQ", my_version, services, time.time()) + create_net_addr(True, serv, ipvsix, porto)
    if needed_version >= 106:
        return struct.pack("<LQQ", my_version, services, time.time()) + create_net_addr(True, serv, ipvsix, porto) + create_net_addr(True, services, my_ipv6, my_port[1]) + struct.pack("<Q", random.randint(0, 42069)) + create_var_str(user_agent) + struct.pack("<L", start_height)
    if needed_version >= 70001:
        return struct.pack("<LQQ", my_version, services, time.time()) + create_net_addr(True, serv, ipvsix,
                                                                                        porto) + create_net_addr(True,
                                                                                                              services,
                                                                                                              my_ipv6,
                                                                                                              my_port[
                                                                                                                  1]) + struct.pack(
            "<Q", random.randint(0, 42069)) + create_var_str(user_agent) + struct.pack("<L?", start_height, False)


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
    return create_var_int(stri) + struct.pack(create_struct_ord(len(stri)), stri)


def create_inventory_vector(typ, hsh):
    return struct.pack("<L", typ) + struct.pack("<32s", hsh)


def create_getdata_msg(inv_vecs):  # gets an array of inv_vec [[typ1,hsh1], .....]
    output = create_var_int(inv_vecs)
    for i in range(len(inv_vecs)):
        output += create_inventory_vector(inv_vecs[i][0], inv_vecs[i][1])
    return output


def create_command(command):
    order = "<" + str(len(command)) + "s"
    output = struct.pack(order, command)
    while len(output) < 12:
        output += struct.pack("x")
    return output


def create_msg(payload, command):
    return struct.pack("<L", my_magic_val) + create_command(command) + struct.pack("<L", len(payload)) + struct.pack("<32s", hashlib.sha256(hashlib.sha256(payload[:32]))) + payload


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


def validate_msg(msg_tuple):
    if msg_tuple[0] != my_magic_val:
        return False
    if msg_tuple[1] not in ["inv", "blocks", "ping", "pong", "version", "verac"]:  # check later
        return False
    if msg_tuple[2] != len(msg_tuple[4])/8:
        return False
    if msg_tuple[3] != hashlib.sha256(hashlib.sha256(msg_tuple[4][:32])):
        return False
    return True


def validate_tx(tx_tuple):  # not coinbase txs, create seperate func for them. validation require whole block
    sum_output = 0
    for i in tx_tuple[2]:
        sum_output += i[0]

    sum_input = 0
    spent_tx = []
    for i in tx_tuple[1]:
        itx = search_tx_by_hash(i[0][0])
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
    for i in range(len(blk_tuple[7])-1):  # validate all txs in block
        if not validate_tx(blk_tuple[7][i+1]):
            return False
        hsh_arr.append(blk_tuple[7][i+1][4])
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
    while not is_blockchain_used:
        time.sleep(0.01)
    is_blockchain_used = True
    f = open(blockchain_path, 'w')
    f.write(json.dumps(info))
    f.close()
    is_blockchain_used = False


def blockchain_handle_read():
    global is_blockchain_used
    while not is_blockchain_used:
        time.sleep(0.01)
    is_blockchain_used = True
    f = open(blockchain_path, 'r')
    f_txt = json.loads(f.read())
    f.close()
    is_blockchain_used = False
    return f_txt


def addresses_handle_write(info):  # info = address object arr
    global is_addresses_used
    while not is_addresses_used:
        time.sleep(0.01)
    is_addresses_used = True
    f = open(addresses_path, 'w')
    f.write(json.dumps(info))
    f.close()
    is_addresses_used = False


def addresses_handle_read():
    global is_addresses_used
    while not is_addresses_used:
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
    while not is_transactions_used:
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
        hsh_arr.append(hsh_arr[length-1])
        length += 1
    new_hsh_arr = []
    for i in range(int(length/2)):
        new_hsh_arr.append(hashlib.sha256(hashlib.sha256(hsh_arr[2*i]+hsh_arr[2*i+1])))
    return calc_merkle_root(new_hsh_arr)


def create_struct_ord(length):
    return "<" + str(length) + "s"


def version_handshake(s, ipvsix, porto):
    try:
        s.sendall(create_msg(create_version_msg(services, ipvsix, porto, my_version, "", 0), "version"))
    except Exception as e:
        print(e)
        return -1
    msg_tuple = parse_msg(s)
    if len(msg_tuple) == 0:
        return 0
    if (not validate_msg(msg_tuple)) or msg_tuple[1] != "version":
        return 0
    try:
        version_tuple = parse_version_msg(msg_tuple[4])
    except Exception as e:
        print(e)
        return 0
    pref_version = min(my_version, version_tuple[0])
    verac_tuple = parse_msg(s)
    if len(verac_tuple) == 0:
        return 0
    if (not validate_msg(verac_tuple)) or verac_tuple[1] != "verack":
        return 0
    try:
        s.sendall(create_msg(struct.pack("x"), "verack"))
    except Exception as e:
        print(e)
        return -2
    return pref_version


def create_block_locator_hash():
    block_chain = blockchain_handle_read()
    blk_loc_hsh = []
    for i in range(int(len(block_chain)/10)):
        blk_loc_hsh.append(block_chain[-10*i-1:-(10*i)].hash)
    if blk_loc_hsh[len(blk_loc_hsh)-1] != block_chain[0].hash:
        blk_loc_hsh.append(block_chain[0].hash)
    return blk_loc_hsh


def divide_tuple_inv(inv_tuple):
    output = []
    i = 0
    while 128*(i+1) < len(inv_tuple):
        output.append(inv_tuple[128*i:128*(i+1)])
        i += 1
    output.append(inv_tuple[128*i:])
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
                    b1 = Block(block_tuple[0], block_tuple[1], block_tuple[2], block_tuple[3], block_tuple[4], block_tuple[5], block_tuple[7], block_tuple[6])
                    block_chain = blockchain_handle_read()
                    block_chain.append(b1)
                    blockchain_handle_write(block_chain)
    return True


def block_chain_gen(block_tuple):
    pass



# -----------------------------------------------------random_shit---------------------------------------------------- #
#inferkit

if __name__ == '__main__':
   pass


