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
    Kv = KeyManager.read_key("Kv.txt")
    KCTGS = KeyManager.read_key("KCTGS.txt")
    IDC = 'CIS3319USERID'.encode()
    IDTGS = 'CIS3319TGSID' .encode()
    IDV = 'CIS3319SERVERID'.encode()
    server = Server('localhost', 9996)
    AD_c = server.conn.getsockname()[0].encode()
    display = 0 

    rec = server.recv()
    IDV, Tickettgs, Authenticator = cryptoM.disassemble2bytes(rec)

    print("ms3 IDV, TicketTGS,Authenticator\n", IDV.decode(),"\n",Tickettgs.hex(),"\n",Authenticator.hex(),"\n\n")

    E_tgs = AES.new(Ktgs, AES.MODE_ECB)
    Tickettgs_d =  E_tgs.decrypt(Tickettgs)
    Tickettgs_cont = cryptoM.disassemble2bytes(Tickettgs_d)
    TS2 = int(Tickettgs_cont[4].decode())
    lifetime2 = int(Tickettgs_cont[5].decode())

    ctime = time.time()
    if ctime-TS2 <= lifetime2:
        print("ticket valid\n")
    else:
        print("ticket expired\n")
        exit(1)

    time.sleep(1)
    TS4 = int(time.time())
    lifetime4 = 84600
    KCV = get_random_bytes(16)
    TicketCV= cryptoM.assemble2bytes(KCV,IDC,AD_c,IDV,TS4,lifetime4)

    EV = AES.new(Kv, AES.MODE_ECB)
    TicketV = EV.encrypt(pad(TicketCV,16))
    ms4C = cryptoM.assemble2bytes(KCV,IDV,TS4,lifetime4,TicketV)

    ECTGS = AES.new(KCTGS, AES.MODE_ECB)
    msg4 = ECTGS.encrypt(pad(ms4C,16))

    server.send(msg4)
    server.close()
