
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
    KeyManager.save_key('deskey.txt', KeyManager.generate_key(KeyManager,256))
    KeyManager.save_key('hmackey.txt', KeyManager.generate_key(KeyManager,256))
    server = Server('localhost', 9998)
    display = 0 
    key = KeyManager.read_key('deskey.txt')
    hmackey = KeyManager.read_key('hmackey.txt')
    print("deskey:",key.hex())
    print("hmackey:",hmackey.hex())
    des = DES(key,hmackey)

    while True:
        cipher_text = server.recv()
        msg = des.decrypt(cipher_text)
        # print(msg)
        # print("MAC: ", mac)

        msg = input('> ')
        if msg == 'exit':
            break
        cipher_text, mac = des.encrypt(msg)
        server.send(cipher_text)
        print(mac.hex())

    server.close()
