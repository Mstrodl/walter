#internal libraries
import random
import os
import base64
import math

from collections import Counter
BLOCKSIZ = 16

def xor_strings(s,t):
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

'''
    q1w2e3r4
    q1w2e3r4q1w2e3r4q1w2e3r4q1w2e3r[4]
'''
def pad(passwd, l):
    plen = l - (len(passwd) % l)
    padding = chr(0) * plen
    return passwd + padding

class BException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class LengthError(BException):
    def __init__(self, value):
        BException.__init__(self, value)

class EntropyError(BException):
    def __init__(self, value):
        BException.__init__(self, value)

#WCR principal class
class WCR:
    def __init__(self, length):
        if length >= 1024 and length % 256 == 0:
            self.key = os.urandom(length)
        else:
            raise LengthError("length must be a multiple of 256 and >= 1024")
        self.length = len(self.key)
    def encrypt(self, message, passwd):
        '''Encrypt a piece of data with WCR'''
        if entropy(passwd) <= 2.2:
            raise EntropyError("password's entropy must be > 2.2")
        text = list(message)
        # q = random.SystemRandom().randint(0, len(passwd)-1)
        # k = passwd[q]
        i = 0
        pwdpadded = pad(passwd, self.length)
        for c in text:
            # n = ord(self.key[i]) * ord(k)
            # new_character = chr(n % 255)
            newchar = xor_strings(self.key[i], pwdpadded[i])
            text[i] = xor_strings(text[i], newchar)
            i += 1
        return ''.join(text)
    def decrypt(self, ciphertext, passwd):
        '''Decrypt a piece of data with WCR'''
        text = list(ciphertext)
        #k = passwd[q]
        i = 0
        pwdpadded = pad(passwd, self.length)
        for c in text:
            # n = ord(self.key[i]) * ord(k)
            # new_character = chr(n % 255)
            newchar = xor_strings(self.key[i], pwdpadded[i])
            text[i] = xor_strings(text[i], newchar)
            i += 1
        return ''.join(text)
    def export(self):
        '''export the key in base64 format'''
        return base64.b64encode(self.key)
    def import_base64(self, new_iv):
        '''import a key in base64 format'''
        self.key = base64.b64decode(new_iv)
        self.length = len(self.key)

