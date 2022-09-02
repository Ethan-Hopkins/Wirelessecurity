
import socket
from crypto import KeyManager, DES


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
    client = Client('localhost', 9998)
    key = KeyManager().read_key('key.txt')
    des = DES(key)

    while True:
        msg = input('> ')
        while len(msg)%8!=0:
            msg+=" "
        if msg == 'exit':
            break
        else:
            
            client.send(des.encrypt(msg))
        saved = client.recv()
        print(des.decrypt(saved))
        print(saved)
        # TODO: your code here
        
    client.close()
