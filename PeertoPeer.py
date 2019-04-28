import socket
import threading
from data_handler import *
import os
import sys
from requests import get
import portforwardlib as pf
import netifaces
import pickle


class Friends:
    def __init__(self):
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
    def __init__(self):
        p=PortForward()
        print('router_ip '+p.router_ip)
        print('serverhost '+p.serverhost)
        print('ip '+p.ip)
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
                        print(data)
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
        print(data)


class Peer:
    def init(self):
        server=Server()
        sThread=threading.Thread(target=server.run_server)
        sThread.daemon=True
        sThread.start()

    def SendData(self,address,data):
        client = Client(address)
        client.SendMsg(data)
