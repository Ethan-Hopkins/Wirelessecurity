
from copy import deepcopy
from itertools import zip_longest
import random
from re import I
import secrets
from typing import Iterable


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
        """"
        Generate a random key of length key_len (bit length).
        return: random bytes of length (key_len // 8)
        """
        return secrets.token_bytes(key_len//8)


def bitize(byts: bytes) -> 'list[int]':
    """
    bitize bytes
    """
    # each number of the original setup is hex and decides what 4 of the final bits will be f = 1111 2 = 0010
    bits = list()
    byts = bytes.hex(byts)
    for byte in byts:
        #converteach
        temp = bin(int(byte,16))[2:].zfill(4)
        for bit in temp: bits.append(int(bit))

    return bits

def debitize(bits: Iterable[int]) -> bytes:
    """
    debbitize a list of bits
    """
    if len(bits) % 8 != 0:
        raise ValueError('bits length is not a multiple of 8')

    byts = []
    chunk_size = 4
    list_chunked = [bits[i:i + chunk_size] for i in range(0, len(bits), chunk_size)]
    #print(list_chunked)
    for list in list_chunked:
        count = 0
        count+= list[0]*8+list[1]*4+list[2]*2+list[3]
        byts.append(hex(count)[2:])
    return bytes.fromhex(''.join(str(bit) for bit in byts))
        

def bit2hex(bits: Iterable[int]) -> str:
    """
    convert bits to hex string
    """
    return debitize(bits).hex()

def hex2bit(hex_str: str) -> list:
    """
    convert hex string to bits
    """
    return bitize(bytes.fromhex(hex_str))

def permute(raw_seq: Iterable, table: Iterable[int]) -> list:
    """
    permute bits with a table
    """
    result = list()
    for i in table:
        result.append(raw_seq[i])
    #if index in table is 40 and the value is 3, the 40th index in raw_seq goes to the new third index
    return result # just a placeholder

def xor(bits1: Iterable[int], bits2: Iterable[int]) -> 'list[int]':
    """
    xor two bits
    """
    result = list()
    for b1,b2 in zip_longest(bits1,bits2, fillvalue= 0):
        result.append( 1 if b1!=b2 else 0)
    
    return result 

class DES:

    # initial permutation
    IP = [
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    # final permutation
    FP = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    # parity-bit drop table for key schedule
    KEY_DROP = [
        56, 48, 40, 32, 24, 16, 8, 0,
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 60, 52, 44, 36,
        28, 20, 12, 4, 27, 19, 11, 3
    ]

    BIT_SHIFT = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # key compression permutation
    KEY_COMPRESSION = [
        13, 16, 10, 23, 0, 4, 2, 27,
        14, 5, 20, 9, 22, 18, 11, 3,
        25, 7, 15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54, 29, 39,
        50, 44, 32, 47, 43, 48, 38, 55,
        33, 52, 45, 41, 49, 35, 28, 31
    ]
    
    # D box, key expansion permutation
    D_EXPANSION = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16, 
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 
        27, 28, 29, 30, 31, 0
    ]
    
    # S boxes
    S1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]

    S2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ]

    S3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ]

    S4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ]

    S5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ]

    S6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ]

    S7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ]

    S8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    
    # S-box substitution
    S = [S1, S2, S3, S4, S5, S6, S7, S8]
    
    # D box, straight permutation
    D_STRAIGHT = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]

    @staticmethod
    def key_generation(key: 'list[int]') -> 'list[list[int]]':
        """
        raw_key: 64 bits
        return: 16 * (48bits key)
        """
        # had to change this
        keys= list()
        # TODO: your code here
        #drop parity bits looks like its working
        parityDropped = permute(key,DES.KEY_DROP)
        #split left right
        leftkey = list()
        rightkey = list()
        for split in range(56):
            if split<=27: leftkey.append(parityDropped[split])
            else: rightkey.append(parityDropped[split])
        #print(len(leftkey),len(rightkey))
        # 16 round for loop shift keys
        # combine thats a  key
        #repeat
        for loop in range(16):
            #shiftleft
            DES.shiftLeft(leftkey,DES.BIT_SHIFT[loop])
            #shift right
            DES.shiftLeft(rightkey,DES.BIT_SHIFT[loop])
            #combine
            newkey = list()
            for combine in range(56):
                if combine<=27: newkey.append(leftkey[combine])
                else: newkey.append(rightkey[combine-28])
            #print(len(newkey),"huh")
            # permute to make 48 bits
            keys.append(permute(newkey,DES.KEY_COMPRESSION))
            #append to keys
        return keys

    @staticmethod
    def shiftLeft(key: 'list[int]',numShifts: 'int') -> 'list[int]':
        for shifts in range(numShifts):
            Storagebit = key[0]
            for restBits in range(1,28):
                key[restBits-1] = key[restBits]
            key[27] = Storagebit
        return key
    
    @staticmethod
    def f(R: 'list[int]', key: 'list[int]') -> 'list[int]':
        """
        f function
        R: 32 bits
        key: 48 bits
        return: 32 bits
        """
        # TODO: your code here
        #permute R expantion table to expand to 48 bits
        expanded = permute(R,DES.D_EXPANSION)
        #xor expanded r and key
        whitener = xor(expanded,key)
        # sboxes?
        chunks = list()
        for chunk in range(8):
            chunks.append(list())
            for bit in range(6):
                chunks[chunk].append(whitener[(chunk*6)+bit])
        #print(chunks[0][1])
        post_sbox= list()
        outbyte=0
        for chunk in range(8):
            row = chunks[chunk][0]*2 +chunks[chunk][5]
            column = chunks[chunk][1]*8 +chunks[chunk][2]*4+chunks[chunk][3]*2+chunks[chunk][4]  
            outbyte = bin(DES.S[chunk][row][column])[2:].zfill(4)
            for bit in range(4):
                #keep ur eye on this it might be wrong
                post_sbox.append(int(outbyte[bit]))
        #straight dboxes?
        output = permute(post_sbox,DES.D_STRAIGHT)

        return output 

    @staticmethod  
    def mixer(L: 'list[int]', R: 'list[int]', sub_key: 'list[int]') -> 'tuple[list[int]]':
        """
        right_half: 32 bits
        sub_key: 48 bits
        return: 32 bits
        """
        # TODO: your code here
        # tips: finish f and xor first, then use them here
        return (xor(L,DES.f(R,sub_key)),R)
        return (L, R) # just a placeholder
    
    @staticmethod
    def swapper(L: 'list[int]', R: 'list[int]') -> 'tuple[list[int]]':
        """
        A free function for you, LMAO ^O^
        """
        return R, L

    def __init__(self, raw_key: bytes) -> None:
        # for encryption use
        self.keys = DES.key_generation(bitize(raw_key))
        
        # for decryption use
        self.reverse_keys = deepcopy(self.keys)
        self.reverse_keys.reverse()

    def enc_block(self, block: 'list[int]') -> 'list[int]':
        """
        Encrypt a block of 64 bits (8 bytes).
        block: 64 bits.
        return: 64 bits.
        """
        testing = 0
        # TODO: your code here
        #intial permutation
        initial = permute(block,self.IP)
        if testing==1 :
            print("start enc_block test")
            assert bit2hex(initial) =="14a7d67818ca18ad"
            print("IP PASSED")

        #splitblock
        leftBlock = list()
        rightBlock = list()
        for split in range(64):
            if split<=31: leftBlock.append(initial[split])
            else: rightBlock.append(initial[split])
        if testing==1 :
            assert bit2hex(leftBlock) =="14a7d678"
            assert bit2hex(rightBlock)=="18ca18ad"
            print("SPLITTING PASSED")
            
            assert bit2hex(xor(leftBlock,self.f(rightBlock,self.keys[0])))=="5a78e394"
            print("FUNCTION PASSED")
        #repeat 15 times
        for loop in range(16):
            leftBlock = self.mixer(leftBlock,rightBlock,self.keys[loop])[0]
            
            if(loop!=15): 
                swapped = self.swapper(leftBlock,rightBlock)
                leftBlock=swapped[0]
                rightBlock=swapped[1]
            #print(loop,bit2hex(leftBlock),bit2hex(rightBlock))
            
            #leftblock = xor(leftblock,f(rightblock,48bitkey))
            #swapper
        #leftblock = xor(leftblock,f(rightblock,48bitkey))
        output = list()
        for combine in range(64):
            if(combine<32): output.append(leftBlock[combine])
            else: output.append(rightBlock[combine-32])
        return permute(output,self.FP)
        #return finalpermutation

    def dec_block(self, block: 'list[int]') -> 'list[int]':
        """
        similar to enc_block
        block: 64 bits
        return: 64 bits
        """
        testing = 0
        # TODO: your code here
        #intial permutation
        initial = permute(block,self.IP)
        

        #splitblock
        leftBlock = list()
        rightBlock = list()
        for split in range(64):
            if split<=31: leftBlock.append(initial[split])
            else: rightBlock.append(initial[split])
        
        #repeat 15 times
        for loop in range(16):
            leftBlock = self.mixer(leftBlock,rightBlock,self.keys[15-loop])[0]
            
            if(loop!=15): 
                swapped = self.swapper(leftBlock,rightBlock)
                leftBlock=swapped[0]
                rightBlock=swapped[1]
            #print(loop,bit2hex(leftBlock),bit2hex(rightBlock))
            
            #leftblock = xor(leftblock,f(rightblock,48bitkey))
            #swapper
        #leftblock = xor(leftblock,f(rightblock,48bitkey))
        output = list()
        for combine in range(64):
            if(combine<32): output.append(leftBlock[combine])
            else: output.append(rightBlock[combine-32])
        return permute(output,self.FP)

    def encrypt(self, msg_str: str) -> bytes:
        """
        Encrypt the whole message.
        Handle block division here.
        *Inputs are guaranteed to have a length divisible by 8.
        """
        encrypted = list()
        counter = 0
        block = ""
        #print(bitize(msg_str))
        for char in msg_str:
            
            counter+=1
            block+=char
            if counter %8 == 0:
                block = block.encode()
                cipherblock = self.enc_block(bitize(block))
                for bit in cipherblock:
                    encrypted.append(bit)
                block = ""
        #print(debitize(encrypted))
        return debitize(encrypted) # just a placeholder
    
    def decrypt(self, msg_bytes: bytes) -> str:
        """
        Decrypt the whole message.
        Similar to encrypt.
        """
        decrypted = ""
        counter = 0
        block = ""
        msg = msg_bytes.hex()
        for byte in msg:
            block+=byte
            counter+=1
            if(counter%16==0):
                result= bit2hex(self.dec_block(bitize(bytes.fromhex(block))))
                #print((bit2hex(result)))
                block=""  
                for bit in result:
                    decrypted+=bit
            
        return (bytes.fromhex(decrypted).decode()) # just a placeholderSS