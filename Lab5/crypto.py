import random, secrets, base64
class KeyManager:
    @staticmethod
    def read_key(key_file: str) -> bytes:
        with open(key_file, 'rb') as f:
            return f.read()
    
    @staticmethod
    def save_key(key_file: str, key: bytes):
        with open(key_file, 'wb') as f:
            f.write(key)

    def __init__(self, seed=None):
        self.random = random.Random(seed)
    
    def generate_key(self, key_len=256) -> bytes:
        return secrets.token_bytes(key_len//8)

class cryptoM:
    def assemble2bytes(*args) -> bytes:
        if len(args) == 0:
            return b""
        buffer = b""
        for arg in args:
            if isinstance(arg, str):
                elem = base64.encodebytes(arg.encode())
            elif isinstance(arg, bytes):
                elem = base64.encodebytes(arg)
            else:
                elem = base64.encodebytes(str(arg).encode())
            
            buffer += elem + b" "
        
        buffer = buffer[:-1]
        return buffer

    def disassemble2bytes(buffer: bytes) -> 'list[bytes]':
        elems = buffer.split(b" ")
        elems = [ base64.decodebytes(elem) for elem in elems ]
        return elems