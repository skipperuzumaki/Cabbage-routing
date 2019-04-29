from Cryptographic_encryption import *
from collections import OrderedDict
import secrets
import random
import socket

#plz find a better soln

class Client:
    def __init__(self,address):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((address,10000))

    def SendMsg(self,message):
        self.sock.send(message)

    def RecMsg(self):
        data = self.sock.recv(1024)
        return data

#for this

# message ids
# a request public key
# b decrypt and pass on message
# c decrypt and read for yourself
# d public key sending
# e get 15 active peer addresses with seperation charecter |

tracker='000.000.000.000'#clearly temporary

def raw_to_normal_address(raw_address):
    k=raw_address.split('.')
    address=''
    for i in k:
        q=int(i)
        address+=str(q)
        address+='.'
    return address[0:len(address)-1]

def normal_to_raw_address(address):
    k=address.split('.')
    raw_address=''
    for i in k:
        if len(i)==1:
            i='00'+i
        elif len(i)==2:
            i='0'+i
        elif len(i)==3:
            pass
        else:
            return'inv.ali.d a.res'
        address+=i
    return address

def request_public_key(address):
    tclient = Client(tracker)
    tclient.SendMsg(b'a'+address.encode('utf8'))
    publickey_b = tclient.RecMsg()
    tclient.sock.close()
    return Bytes_ToPublicKey(publickey_b)

def active_peers():
    tclient = Client(tracker)
    tclient.SendMsg(b'e')
    data_b = tclient.RecMsg()
    tclient.sock.close()
    data=data_b.decode('utf8')
    activepeers=data.split('|')
    return activepeers

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
        msg=d_cmd_msg[1:len(d_cmd_msg)-15]
        address=d_cmd_msg[len(d_cmd_msg)-15:len(d_cmd_msg)]
        return [cmd,msg,address]
    elif d_cmd_msg[0:1]==b'c':
        cmd=d_cmd_msg[0:1]
        msg=d_cmd_msg[1:len(d_cmd_msg)-(512+15)]
        sign=d_cmd_msg[len(d_cmd_msg)-(512+15):len(d_cmd_msg)-15]
        address_sender=d_cmd_msg[len(d_cmd_msg)-15:len(d_cmd_msg)]
        if verify_signature_b(sign,msg,request_public_key(address_sender)):
            return [cmd,msg,address_sender]
        else:
            return 'Falsified message recieved'
    elif d_cmd_msg[2:3]==b'd':
        pass
    else:
        return 'invalid message'
    return 'Error check code'
