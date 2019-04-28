from Cryptographic_encryption import *
from collections import OrderedDict
import secrets
import random

# message ids
# a request public key
# b decrypt and pass on message
# c decrypt and read for yourself
# d request address


private_key,public_key=generate_key_pair()#temporarily
my_address='192.168.000.013'

def raw_to_normal_address(raw_address):
    k=raw_address.split('.')
    address=''
    for i in k:
        q=int(i)
        address+=str(q)
        address+='.'
    return address[0:len(address)-1]

eg_signature=b'\xc9D\xa2\x0e1\xbdw!q\xba\xb7\xb9\xb6\xd4D\xae\xf7\xaeD1%7\x95\xce\xd1+z\xd1\x0bZ\x07\xf3\xf4\x86VH\t\xef\x16\x87v\xc4\xab\x145\x8c\x19p=L\xcd*~1\xb7 \xf2}?q}\xed\x13\xd3\xc6\x8f?\x19\xfe\x12\xe6u\xfc\xc9\xd7U\xbf|\xc8\xc0\'\xe6,\x06W\xde\x80U\x93\xee\xddJ\x80B\xb4\xfe\xee~\xd5\xa3Q\x108}\xfc\xaddu\xec\xb6r\x94\xd4\xb2\xd9\x05\xd4\x19\xd1\xfef\xea\xc7\xf4\x9e\x8b\x8c\xcc\x1c. \x91aU\x8aK\xc0gE +\xfb\x99\x06P\xbe\xaec\xa2\t"a<b)\x05\xa6\xd85\x138Hhq,\x86\xd8\xbd\n(\x81\x10\xd1w3\x96\xc5\xea&\xe7cnc\xaf\xa0RQ(\xec\xf4\x85\x93~\x9b\x97\x89\x81@\x08\x80\xa0`\xad\xd7&\xc8\x1eF\x17K\xcf\xf6\x86?\x82\xc6\xc8R\x10\x9a\xb4\x81\x0b`\xfb\x0b\xa1\x03[0\xaf\xd8\x8av\\\x17\x1e\xf2k\x01\x90m\xf0\xea\xea\x14\x1d]\x14\x98\xcc\xbb\xee\x02\x93\xe0 \xb1\x0b\x1a\x8e3\x0c]s{\xc3\xca\xc0i\xf0\xc4b\xb8\xad\xbe\x0c\xee\xe3D\xe9\xa9\xd6\x84H\xa0\x0f\x1cM\xc8\xbe\x8b2)^\xf3\xc1\x05u1\x13%\x8fD7\xb1\xd7*\x05_"\xc8Y\xbf\x9f\x9e\xaf\x89x\x1f\xcc\xa2\xfa\x8e\xed\xf2J\xd3.\x1el\x9eC6cK\xd6%\xd7=hz@\x87\xae.\xccO\x84\x82oo\xdf\xeb\x1f)\x82Q\xd7\x9c\xee\xb7\xd7\xda[H\xe6\xbb4\xae\xeb\xe7*e;\xdf\xea\xdfr\xc0\x1e\xef\xf3>\xf1\x08\xbd\xfc\xd9N\xccEOv\xcc\xe4\x83u\x16\xe0\xa2\x1a<\xc1\xec?Z\xd9\x1a!8$_rD.\xcc1A~\xa6\xff\x05y#\xa9J\xc6\xbdy\x02\xaf\x99=(\xf6*\xb8\x80\xda\x14\xaf\x9b\xbe\x16\xd9(\x88\x00\x9bx\xc1\xa0\xe2\nO\x93\x02\xbb\x00\x96\xdd\xad\x7f\x04\xae\xac\x85\xee\xb8\'\xf2\xb0<\xea\xa5\xe3e\x0f#\xdd\x85?6^\x9fiT#\xf6\xa1\x19\x1bLOZ\xa9c\xecnw)\xd27\xf0T\x87m\x98\x84\xe1\x9f'#temporarily

def request_public_key(address):
    return public_key

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
    message=message.encode('utf8') #decrypt and read
    signature=sign_b(message,private_key)
    message = bytes('c'.encode('utf8')) + message
    message+=signature
    message+=my_address.encode('utf8')
    base=encrypt_b(message,public_keys[reciever_address])
    for i in public_keys:
        if i!=reciever_address:
            base = bytes('b'.encode('utf8')) + base #decrypt and pass on
            base+=str(i).encode('utf8')
            base=encrypt_b(base,public_keys[i])
    return base

def extract_details(message,key):
    d_cmd_msg=decrypt_b(message,key)
    if d_cmd_msg[0:1]==b'a':
        pass
    elif d_cmd_msg[0:1]==b'b':
        cmd=d_cmd_msg[0:1]
        msg=d_cmd_msg[1:len(d_cmd_msg)-len(my_address)]
        address=d_cmd_msg[len(d_cmd_msg)-len(my_address):len(d_cmd_msg)]
        return [cmd,msg,address]
    elif d_cmd_msg[0:1]==b'c':
        cmd=d_cmd_msg[0:1]
        msg=d_cmd_msg[1:len(d_cmd_msg)-(len(eg_signature)+len(my_address))]
        sign=d_cmd_msg[len(d_cmd_msg)-(len(eg_signature)+len(my_address)):len(d_cmd_msg)-len(my_address)]
        address_sender=d_cmd_msg[len(d_cmd_msg)-len(my_address):len(d_cmd_msg)]
        if verify_signature_b(sign,msg,request_public_key(address_sender)):
            return [msg,address_sender]
        else:
            return 'Falsified message recieved'
    elif d_cmd_msg[2:3]==b'd':
        pass
    else:
        return 'invalid message'
    return 'Error check code'

#test code
k1=encryption_key()
k2=encryption_key()
kr=encryption_key()
d=dict()
d['r']=kr
d[1]=k1
d[2]=k2
