import socket
import time
from crypto import KeyManager, cryptoM
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    Ktgs = KeyManager.read_key("Ktgs.txt")
    IDV = 'CIS3319SERVERID'
    Kv = KeyManager.read_key("Kv.txt")
    server = Server('localhost', 9999)
    AD_C = server.conn.getsockname()[0].encode()

    EV = AES.new(Kv, AES.MODE_ECB)
    rec = server.recv()
    ticketV, Authenticator, = cryptoM.disassemble2bytes(rec)
    dec = EV.decrypt(ticketV)
    KCV, IDC, AD1, IDV, TS4, lifetime4 = cryptoM.disassemble2bytes(dec)
    print("ms5 KCV, IDC, AD1, IDV, TS4, lifetime4, authenticator\n", KCV.hex(),"\n",IDC.decode(),"\n",AD1.decode(),"\n",IDV.decode(),"\n",TS4.decode(),"\n",lifetime4.decode(),"\n",Authenticator.hex(),"\n\n")
    ECV = AES.new(KCV, AES.MODE_ECB)
    Authenticatordec = ECV.decrypt(Authenticator)
    IDC, AD2, TS5 = cryptoM.disassemble2bytes(Authenticatordec)

    ctime = time.time()
    if int(ctime)-(int(TS5.decode())) <= int(lifetime4.decode()) and AD1==AD2:
        print("ticket valid\n")
    else:
        print("ticket expired\n")
        exit(1)

    msg6 = ECV.encrypt(pad(cryptoM.assemble2bytes(int(TS5.decode()) + 1),16))
    server.send(msg6)

    server.close()
