#python
# diffie.py
# implements Diffie-Hellman Key Exchange

import random
import os
import time

PRIME = 127

def get_rand(n):
    return int(os.urandom(n).encode('hex'), 16)

def g(gen, x, prime):
    return pow(gen, x, prime)

def setBit(int_type, offset):
    mask = 1 << offset
    return(int_type | mask)

_mrpt_num_trials = 5 # number of bases to test

def test_prime(n):
    assert n >= 2
    # special case 2
    if n == 2:
        return True
    # ensure n is odd
    if n % 2 == 0:
        return False
    # write n-1 as 2**s * d
    # repeatedly try to divide n-1 by 2
    s = 0
    d = n-1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2**s * d == n-1)
 
    # test the base a to see whether it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite
 
    for i in range(_mrpt_num_trials):
        a = random.randrange(2, n)
        if try_composite(a):
            return False
 
    return True # no base tested showed n as composite

def get_tprime(n):
    x = get_rand(n)
    setBit(x, 0)
    setBit(x, long(x).bit_length())
    return x

def test_tprime(x):
    b = long(x).bit_length()
    c1 = test_prime(x)
    c2 = pow(2, b-1) < x < pow(2, b)
    return c1 and c2

def get_prime(x):
    p = get_tprime(x)
    while not test_tprime(p):
        p = get_tprime(x)
    return p

def test():
    p = get_tprime(32)
    while not test_tprime(p):
        p = get_tprime(32)
    gn = get_rand(64) # base generator
    a = get_rand(8)
    b = get_rand(8)
    print p, gn, a, b
    PA = g(gn, a, p)
    PB = g(gn, b, p)
    print 'PA =', PA
    print 'PB =', PB
    SA = g(PB, a, p)
    SB = g(PA, b, p)
    print 'SA =', SA
    print 'SB =', SB
    print 'SA == SB ->', SA == SB

