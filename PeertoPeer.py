import socket
import threading
from data_handler import *

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
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        s.connect( ( "www.google.com", 80 ) )
        serverhost = s.getsockname()[0]
        s.close()
        self.recieving=False
        self.sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.reciever = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        address = (serverhost,5004)
        print(address)
        self.sender.bind(address)#we get a socket with ip address and port 5004
        address = (serverhost,5005)
        self.reciever.bind(address)#we get a socket with ip address and port 5005
        print(address)
    def start_rec_server(self,buffersize):
        try:
            if (self.recieving):
                raise EOFError#just raised a random error will like to change later
            self.recieving=True
            while True:
                data,addr=reciever.recvfrom(buffersize)
                extracted=extract_details(data)
                t1=threading.Thread(target=self.__pass_on_data,args=(extracted))
                t1.run()
                del t1
        except:
            self.recieveing=False
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
        t=threading.Thread(target=self.start_rec_server,args=(buffersize))
        t.start()
        try:
            while True:
                print('enter [address to send to]~[message]\n')
                val=input()
                splitval=val.split('~')
                self.send_data(splitval[1],splitval[0])
        except:
            print('Some error occured')
    
    
