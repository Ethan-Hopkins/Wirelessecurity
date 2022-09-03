
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
    display = 0
    while True:
        
        msg = input('> ')
        if msg == 'plain':
            display = 0
            msg = input('> ')
        elif msg == 'cypher':
            display = 1
            msg = input('> ')
        if msg == 'exit':
            break
        
        else:
            while len(msg)%8!=0:
                msg+=" "
            client.send(des.encrypt(msg))
        saved = client.recv()
        if display == 0:
            print(des.decrypt(saved))
        else:
            print(saved.hex())
        # TODO: your code here
        
    client.close()
