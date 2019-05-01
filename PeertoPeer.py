import socket
import threading
from data_handler import *
import os
import sys
from requests import get
import portforwardlib as pf
import netifaces
import pickle

MyAddress='000.000.000.000'

class _Friends:
    def init(self):
        try:
            fr=open('Friends.bin','br')
            self.__friends=pickle.load(fr)
            fr.close()
        except:
            self.__friends=dict()
        
    def AddFriend(self,friend,address):
        try:
            if len(address) != len('000.000.000.000'):
                raise IOError
            k= address.split('.')
            if len(k) != 4:
                raise IOError
            for i in k:
                int(i)
                if len(i) != 3:
                    raise IOError
        except:
            return 'invalid address use raw form ipv4 address [eg :> 102.168.000.001 not 192.168.0.0]'

        if friend in self.__friends:
            if self.__friends[friend]==address:
                return 'friend already present'
            else:
                return 'friend present with different address use UpdateFriend to chnage address'
        else:
            self.__friends[friend]=address
            self.save()
            return 'added friend '+friend+' at '+address

    def UpdateFriend(self,friend,updated_address):
        try:
            if len(updated_address) != len('000.000.000.000'):
                raise IOError
            k= updated_address.split('.')
            if len(k) != 4:
                raise IOError
            for i in k:
                int(i)
                if len(i) != 3:
                    raise IOError
        except:
            return 'invalid address use raw form ipv4 address [eg :> 102.168.000.001 not 192.168.0.0]'

        if friend not in self.__friends:
            return 'friend not saved use AddFriend to add a new friend'
        else:
            k = self.__friends[friend]
            self.__friends[friend]=updated_address
            self.save()
            return 'updated '+friend+' form '+k+' to '+updated_address

    def DeleteFriend(self,friend):
        del self.__friends[friend]
        self.save()
        return 'deleted friend '+friend+' if he existed'

    def ShowFriends(self):
        return self.__friends

    def GetAddress(self,friend):
        if friend in self.__friends:
            return self.__friends[friend]
        else:
            return 'friend not saved'

    def save(self):
        fw=open('Friends.bin','bw')
        pickle.dump(self,fw)
        fw.close()


class _DecryptionKeys:
    def __init__(self):
        self.__keys=dict()
        self.__RSAkeys=generate_key_pair()

    def AddKey(self,encryptedkey,address):
        encryptionkey_b=decrypt_asymmetrically(encryptedkey,self.__RSAkeys[0])
        encryptionkey=encryptionkey_b.decode('utf8')
        self.__keys[address]=encryptionkey

    def GetKey(self,address):
        key=self.__keys[address]
        self.__keys[address]=0
        del self.__keys[address]

    def PublicKey(self):
        return self.__RSAkeys[1]

DecryptionKey=_DecryptionKeys()


class PortForward:
    def __init__(self):
        self.router_ip=self.router_ip()
        self.serverhost=self.serverhost()
        self.ip=self.check_ip()
        self.protocol = 'TCP'

    def EnablePortForward(self):
        pf.forwardPort(10000,10000,self.router_ip,self.serverhost,False,self.protocol,0,'cabbage routing',True)

    def DisablePortForward(self):
        pf.forwardPort(10000,10000,self.router_ip,self.serverhost,True,self.protocol,0,'cabbage routing',True)
    
    def router_ip(self):
        gws=netifaces.gateways()
        return gws['default'][2][0]

    def serverhost(self):
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        s.connect( ( "www.google.com", 80 ) )
        serverhost = s.getsockname()[0]
        s.close()
        return serverhost

    def check_ip(self):
        ip = get('https://api.ipify.org').text
        return ip


class Server:
    def init(self):
        p=PortForward()
        print('router_ip '+p.router_ip)
        print('serverhost '+p.serverhost)
        print('ip '+p.ip)
        global MyAddress
        MyAddress=p.ip
        p.EnablePortForward()
        self.connections=[]
        self.peers=[]
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.bind((p.serverhost,10000))
        self.sock.listen(1)

    def run_server(self):
        print('started')
        while True:
            print('running')
            c,a=self.sock.accept()
            self.peers.append(a)
            cThread=threading.Thread(target=self.handler,args=(c,a))
            cThread.deamon=True
            cThread.start()
            self.connections.append(c)
            print(str(a[0])+':'+str(a[1])+'connected')

    def handler(self,c,a):
        try:
            while True:
                data=c.recv(4096)
                for conn in self.connections:
                    if data:
                        details=extract_details(data,self.DecryptionKey.GetKey(a))
                        if details[0]==b'b':
                            client = Client(details[2])
                            client.SendMsg(details[1])
                        elif details[0]==b'c':
                            print('message');print(details[1]);print('recieved from');print(details[2]);
                        self.disconnect(c,a)
        except:
            self.disconnect(c,a)

    def disconnect(self,c,a):
        self.connections.remove(c)
        self.peers.remove(a)
        c.close()

    
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


class Peer:
    def init(self):
        self.Friends=_Friends()
        self.Friends.init()
        self.server=Server()
        self.server.init()
        sThread=threading.Thread(target=self.server.run_server)
        sThread.daemon=True
        sThread.start()
        kThread=threading.Thread(target=self.SearchKeys)
        kThread.daemon=True
        kThread.start()

    def SendData(self,friend,data):
        retval=self.Friends.GetAddress(friend)
        if retval not in ['friend not saved',None]:
            self.SendDataNonFriend(retval,data)
        else:
            print(retval)
            print('use SendDataNonFriend')

    def SendDataNonFriend(self,_address,data):
        address=raw_to_normal_address(_address)
        using_peers,last=choose_path(active_peers(),address)
        public_keys,encryption_keys=ready_keys(using_peers)
        self.SendEncryptionKey(encryption_keys,public_keys)
        message=ready_message(data,public_keys,address,last)
        self.SendDataNonAnonymous(last,message)

    def SendDataNonAnonymous(self,address,data):
        client = Client(address)
        client.SendMsg(data)

    def SendEncryptionKey(self,encryption_keys,public_keys):
        zclient=Client(tracker)
        for i in encryption_keys:
            msg=encrypt_asymmetrically(encryption_keys[i],public_keys[i])
            msg+=i.encode('utf8')
            zclient.SendMsg(msg)

    def SearchKeys(self):
        kclient=Client(tracker)
        tclient.SendMsg(b'd' + PublicKey_ToBytes(DecryptionKey.PublicKey()) + MyAddress.encode('utf8'))
        while True:
            data_b = kclient.RecMsg()
            key=data_b[0:684]
            address=data_b[684:len(data)]
            DecryptionKey.addkey(key,address)