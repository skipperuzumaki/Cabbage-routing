from Cryptographic_encryption import *
from collections import OrderedDict
import secrets
import random

# message ids
# 00 request public key
# 01 decrypt and pass on message
# 10 decrypt and read for yourself
# 11 request address

def find_active_peers():
    pass

def request_public_key(address):
    pass

def choose_path(active_peers,reciever_address):
    npeers=3+secrets.randbelow(3)
    r=random.SystomRandom()
    r.shuffle(active_peers)
    using_peers=[]
    nreciever=secrets.randbelow(npeers)
    for i in range(npeers+1):
        using_peers.append(active_peers[i])
        if i==nreciever:
            using_peers.append(reciever_address)
        else:
            using_peers.append(active_peers[i])
    return using_peers

def ready_keys(using_peers):
    public_keys=OrderedDict()
    for i in using_peers:
        public_keys[i]=request_public_key(i)
    return public_keys

def ready_message(message,public_keys,reciever_address):
    signature=sign(message,private_key)
    message+=signature
    message+=my_address.encode('utf8')
    base=encrypt_asymmetrically(message,public_keys[reciever_address])
    base = bytes(2).encode('utf8') + base # decrypt and read
    for i in public_keys:
        if i!=reciever_address:
            base = bytes(1).encode('utf8') + base #decrypt and pass on
            base=encrypt_asymmetrically(base,public_keys[i])
            base+=public_keys[i].encode('utf8')
    return base

def extract_details(message):
    message = message.decode('utf8')
    message_id = message[0:2]
    address = message[2:address_lenght+2]
    data = message[address_lenght+2:len(message)]
    return [message_id,data,address]

def send_message(messgae,address):
    pass
