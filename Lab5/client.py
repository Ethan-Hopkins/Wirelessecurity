import socket, time
from crypto import KeyManager

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
    tgsServer = Client('localhost', 9998)
    service = Client('localhost', 9999)
    Kc = KeyManager.read_key("Kc.txt")

    IDC = 'CIS3319USERID'
    IDTGS = 'CIS3319TGSID' 
    now = str(int( time.time() ))

    asServer.send((IDC+IDTGS+now).encode())
    rec = asServer.recv()
    print(rec)
    
    tgsServer.send("hi!".encode())
    rec = tgsServer.recv().decode()
    print(rec)

    service.send("hi!".encode())
    rec = service.recv().decode()
    print(rec)
    