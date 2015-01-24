#internal libraries
import random, os, base64, math

#function from wikipedia
def xor_strings(s,t):
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

from collections import Counter

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

class LengthError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class EntropyError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

#WCR principal class
class WCR:
    def __init__(self, length):
        if length >= 1024 and length % 256 == 0:
            self.iv = os.urandom(length)
        else:
            raise LengthError("length must be a multiple of 256 and >= 1024")
        self.max = len(self.iv)
    def encrypt(self, message, passwd):
        '''Encrypt a piece of data with WCR'''
        if entropy(passwd) <= 2.2:
            raise EntropyError("password's entropy must be > 2.2")
        text = list(message)
        q = random.randint(0, len(passwd)-1)
        k = passwd[q]
        i = 0
        for c in text:
            new_character = chr((ord(self.iv[i]) * ord(k)) % 255)
            text[i] = xor_strings(text[i], new_character)
            i += 1
        return ''.join(text), q
    def decrypt(self, ciphertext, passwd, q):
        '''Decrypt a piece of data with WCR'''
        text = list(ciphertext)
        k = passwd[q]
        i = 0
        for c in text:
            new_character = chr(ord(self.iv[i]) * ord(k) % 255)
            text[i] = xor_strings(text[i], new_character)
            i += 1
        return ''.join(text)
    def export(self):
        '''export the key in base64 format'''
        return base64.b64encode(self.iv)
    def import_base64(self, new_iv):
        '''import a key in base64 format'''
        self.iv = base64.b64decode(new_iv)
        self.max = len(self.iv)
