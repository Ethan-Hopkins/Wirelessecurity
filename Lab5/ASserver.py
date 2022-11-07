import socket, random, secrets,time
from des import DesKey
from crypto import KeyManager
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
    KeyManager.save_key("Kc.txt",KeyManager.generate_key(KeyManager,64))
    KeyManager.save_key("Ktgs.txt",KeyManager.generate_key(KeyManager,64))
    KeyManager.save_key("Kv.txt",KeyManager.generate_key(KeyManager,64))
    Kc = KeyManager.read_key("Kc.txt")
    Ktgs = KeyManager.read_key("Ktgs.txt")

    IDC = 'CIS3319USERID'
    IDTGS = 'CIS3319TGSID'
    Lifetime2 = '60'

    Kctgs = KeyManager.generate_key(KeyManager,64)
    
    server = Server('localhost', 9997)

    
    rec = server.recv().decode()
    print(rec)

    ts2 = str(int( time.time() ))
    ticket = DesKey(Ktgs).encrypt(Kctgs+(IDC+"127.0.0.1:9997"+IDTGS+ts2+Lifetime2).encode(),padding=True)
    ret =  DesKey(Kc).encrypt(Kctgs+(IDTGS+ts2+Lifetime2).encode()+ticket,padding = True)
    server.send(ret)
    server.close()
