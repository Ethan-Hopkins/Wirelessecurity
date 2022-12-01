import socket, random, secrets,time
from des import DesKey
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
    KeyManager.save_key("Kc.txt",KeyManager.generate_key(KeyManager,128))
    KeyManager.save_key("Ktgs.txt",KeyManager.generate_key(KeyManager,128))
    KeyManager.save_key("Kv.txt",KeyManager.generate_key(KeyManager,128))
    Kc = KeyManager.read_key("Kc.txt")
    Ktgs = KeyManager.read_key("Ktgs.txt")
    
    Lifetime2 = 60

    BLOCK_SIZE = 16
    Kctgs = KeyManager.generate_key(KeyManager,128)
    KeyManager.save_key("KCTGS.txt",Kctgs)
    server = Server('localhost', 9997)
    AD_c = server.conn.getsockname()[0].encode()

    
    rec = server.recv()
    IDC, IDTGS, TS1 = cryptoM.disassemble2bytes(rec)
    print("idc, idtgs, ts1\n",IDC.decode(),"\n",IDTGS.decode(),"\n",TS1.decode(),"\n\n")
    time.sleep(1)
    ts2 = int( time.time() )

    ticketC = cryptoM.assemble2bytes(Kctgs,IDC,AD_c, IDTGS,ts2,Lifetime2)
    E_tgs = AES.new(Ktgs, AES.MODE_ECB)
    Ticket_tgs = E_tgs.encrypt(pad(ticketC,BLOCK_SIZE))
   
    msg2_content = cryptoM.assemble2bytes(Kctgs, IDTGS, ts2, Lifetime2, Ticket_tgs)
    E_c = AES.new(Kc, AES.MODE_ECB)
    msg2 = E_c.encrypt(pad(msg2_content,BLOCK_SIZE))
    
    server.send(msg2)
    
    server.close()
