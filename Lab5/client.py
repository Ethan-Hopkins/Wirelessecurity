import socket, time
from crypto import KeyManager, cryptoM
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    asServer = Client('localhost', 9997)
    tgsServer = Client('localhost', 9996)
    service = Client('localhost', 9999)
    Kc = KeyManager.read_key("Kc.txt")
    AD_c = asServer.s.getpeername()[0].encode()
    IDC = 'CIS3319USERID'.encode()
    IDV = "CIS3319SERVERID".encode()
    IDTGS = 'CIS3319TGSID'.encode()
    now = (int( time.time() ))

    asServer.send(cryptoM.assemble2bytes(IDC,IDTGS,now))
    rec = asServer.recv()
    print(rec)

    #msg3

    E_c = AES.new(Kc, AES.MODE_ECB)
    msg2D = E_c.decrypt(rec)
    KCTgs, IDTGS, T2, lifetime2,Ticket_tgs_recved = cryptoM.disassemble2bytes(msg2D)
    print("msg2 Kctgs, Idtgs,ts2,lifetime2,tickettgs\n",KCTgs.hex(),"\n",IDTGS.decode(),"\n",T2.decode(),"\n",lifetime2.decode(),"\n",Ticket_tgs_recved.hex(),"\n")
    time.sleep(1) 
    TS3 = int(time.time())
    authenticator_content = cryptoM.assemble2bytes(IDC, AD_c, TS3)
    E_c_tgs = AES.new(KCTgs, AES.MODE_ECB)
    Authenticator = E_c_tgs.encrypt(pad(authenticator_content,16))
    msg3 = cryptoM.assemble2bytes(IDV, Ticket_tgs_recved, Authenticator)
    tgsServer.send(msg3)


    rec = tgsServer.recv()
    msg4D = E_c_tgs.decrypt(rec)
    #print(cryptoM.disassemble2bytes(msg4D)[0].decode())
    #print(cryptoM.disassemble2bytes(msg4D)[0].hex())
    KCV, IDV, TS4, lifetime4, ticketV = cryptoM.disassemble2bytes(msg4D)
    print("msg4 KCV, IDV,TS4,lifetime4,ticketV\n",KCV.hex(),"\n",IDV.decode(),"\n",TS4.decode(),"\n",lifetime4.decode(),"\n",ticketV.hex(),"\n")
    
    time.sleep(1)
    TS5 = int(time.time())
    AuthenticatorC = cryptoM.assemble2bytes(IDC,AD_c,TS5)
    ECV = AES.new(KCV, AES.MODE_ECB)
    Authenticator = ECV.encrypt(pad(AuthenticatorC,16))
    msg5 = cryptoM.assemble2bytes(ticketV,Authenticator)
    service.send(msg5)

    rec = service.recv()
    msg6Desc = ECV.decrypt(rec)
    TS51 = cryptoM.disassemble2bytes(msg6Desc)[0].decode()
    print(TS51)
    print("Timestamps", TS5,"\t", TS51)
    if TS51==TS5+1:
        print("Authenticated")
    else:
        print("Authentication failed")
        exit(1)

    

    print(rec)
    