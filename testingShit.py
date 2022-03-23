import time

import requests
from bs4 import BeautifulSoup as bs

url_tx = "https://www.blockchain.com/btc/tx/936b1b51ba83f1fffce58c010f1591f208a610cda70d2a7cc26cad396202130c"

key = ['@', '&', '#', '$', '%', '!', '^', '*', '-', '+', '_', '=', '`', '~', '[', '.', ']', '{', '}', '>', '<', '?', ',', ';', '/', '|']


def get_first_block():
    req = requests.get("https://www.blockchain.com/btc/blocks?page=1")
    soup = bs(req.text, 'html.parser')
    first_block = soup.find(name="a", attrs={'class', 'sc-1r996ns-0 fLwyDF sc-1tbyx6t-1 kCGMTY iklhnl-0 eEewhk'})
    return "https://www.blockchain.com" + first_block.attrs.get('href')
    # print([a.text for a in amount_of_btc if "sc-1ryi78w-0 cILyoi sc-16b9dsl-1 ZwupP u3ufsr-0 eQTRKC" in str(a)])
    # print([amount.text for amount in amount_of_btc])
    # amount = [amount for amount in amount_of_btc if amount.text == "Value"][0]
    # print(amount.find(name="div"))
    # print(type(amount))
    # print(amount.parent.find_all(attrs={"opacity", 1}))
    # print(amount)


def get_tx_hashes(url):
    addr_arr = []
    try:
        i = 1
        while True:
            req = requests.get(url)
            soup = bs(req.text, 'html.parser')
            tx_in_blk = soup.find_all(name="a",
                                      attrs={'class', 'sc-1r996ns-0 fLwyDF sc-1tbyx6t-1 kCGMTY iklhnl-0 eEewhk'})
            tx_in_blk = [tx.text for tx in tx_in_blk if len(tx.text) == 64]
            if len(tx_in_blk) == 0:
                break
            print(tx_in_blk)
            for j in tx_in_blk:
                addr_arr.append("https://www.blockchain.com/btc/tx/" + j)
            i += 1
            print(i)

    except Exception as e:
        print(e)
    return addr_arr
    # req = requests.get(url_blk)
    # soup = bs(req.text, 'html.parser')
    # tx_in_blk = soup.find_all(name="a", attrs={'class', 'sc-1r996ns-0 fLwyDF sc-1tbyx6t-1 kCGMTY iklhnl-0 eEewhk'})
    # tx_in_blk = [tx.text for tx in tx_in_blk if len(tx.text) == 64]
    # print(tx_in_blk)


def check_single_tx(my_pk, victim_pk, amount, url):
    req = requests.get(url)
    soup = bs(req.text, 'html.parser')
    input_addr = soup.find_all(name="div", attrs={'class', 'sc-1tbyx6t-0'})
    input_addr = [addr.text for addr in input_addr]
    print(input_addr)
    if (len(input_addr) != 2) or (my_pk not in input_addr) or (victim_pk not in input_addr):
        return False
    output = soup.find_all(name="span", attrs={'class', 'sc-1ryi78w-0 cILyoi sc-16b9dsl-1 ZwupP u3ufsr-0 eQTRKC'})
    output = [out.text for out in output if "BTC" in out.text]
    print(output)
    if float(output[1][:-5])-float(output[0][:-5]) < amount:
        return False
    return True


def check_if_paid(my_pk, victim_pk, amount):
    tx_hsh = get_tx_hashes(get_first_block())
    print(tx_hsh)
    for i in tx_hsh:
        if check_single_tx(my_pk, victim_pk, amount, i):
            return True
    return False


if __name__ == '__main__':
    flag = False
    while not flag:
        try:
            flag = check_if_paid(0, 0, 0)
        except Exception as e:
            print(e)
        time.sleep(600)

