
import socket

from crypto import KeyManager, DES

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
    KeyManager.save_key('key.txt', KeyManager.generate_key(KeyManager,256))
    server = Server('localhost', 9998)
    display = 0
    key = KeyManager.read_key('key.txt')
    des = DES(key)

    while True:
        #recieve message
        saved = server.recv()
        #check if method should be displayed as cyphertext or plaintext
        if display == 0:
            print(des.decrypt(saved))
        else:
            print(saved.hex())
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
            server.send(des.encrypt(msg))
            
        # TODO: your code here

    server.close()
