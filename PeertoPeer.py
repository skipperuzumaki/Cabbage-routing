import socket
import threading
from data_handler import *
import os
from requests import get
import portforwardlib as pf
import netifaces

def router_ip():
    gws=netifaces.gateways()
    return gws['default'][2][0]

def serverhost():
    s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    s.connect( ( "www.google.com", 80 ) )
    serverhost = s.getsockname()[0]
    s.close()
    return serverhost

def check_ip():
    ip = get('https://api.ipify.org').text
    return ip

pf.forwardPort(5005,5005,router_ip(),serverhost(),False,'UDP',0,'cabbage routing',True)

class friendlist:
    def __init__(self):
        self.publickeylist=dict()
    def add_friend(self,address):
        self.publickeylist[address]=get_public_key(address)
    def getpublickey(self,address):
        if address in self.publickeylist:
            return self.publickeylist[address]
        else:
            self.addfriend(address)
            return self.publickeylist[address]

class Peer:
    def __init__(self):
        self.serverhost=serverhost()
        self.sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.reciever = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        address = (self.serverhost,5004)
        print(check_ip())
        self.sender.bind(address)#we get a socket with ip address and port 5004
        address = (self.serverhost,5005)
        self.reciever.bind(address)#we get a socket with ip address and port 5005
    def start_rec_server(self,buffersize):
        try:
            while True:
                data,addr=self.reciever.recvfrom(buffersize)
                print(data)
        except:
            print('Some exception occured')
        finally:
            print('No Longer Recieving Data')
    def send_data(self,data,address):
        self.sender.sendto(data,(address,5005))
    def __self_message_verify(message,address):
        pass
    def __pass_on_data(extracted):
        if extracted[0]==bytes(2).encode('utf8'):
            if __self_message_verify(extracted[1],extracted[2]):
                print(str(extracted[2])+'sent you:')
                print(str(decrypt_asymmetrically(extracted[1],friendlist.getpublickey(extracted[2]))))
        elif extracted[0]==bytes(0).encode('utf8'):
            self.send_data(base64.urlsafe_b64encode(public_key),extracted[2])
        elif extracted[0]==bytes(1).encode('utf8'):
            data=decrypt_asymmetrically(extracted[1],friendlist.getpublickey(extracted[2]))
            self.send_data(data,extracted[2])
    def mainloop(self,buffersize):
        t=threading.Thread(target=self.start_rec_server,args=(buffersize,))
        t.start()
        while True:
            print('enter [address to send to]~[message]\n')
            val=input()
            splitval=val.split('~')
            self.send_data(splitval[1],base64.b64decode(splitval[0]))

    
    
p=Peer()
try:
    p.mainloop(1024)
except KeyboardInterrupt:
    pf.forwardPort(5005,5005,router_ip(),serverhost(),True,'UDP',0,'cabbage routing',True)


