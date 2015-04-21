# -*- coding: utf-8 -*-
# client.py - Walter Client
import socket
import time
import thread
import sys
import hashlib
import ast

import diffie as dh
import error

from wcr2 import WCR

VERSION = '0.2'
AUTHOR = 'Lukas Mendes'
PORT = 39
BUFSIZE = 4096

def passwordHash(x):
    return hashlib.sha256(x).hexdigest()

def printout(msg):
    sys.stdout.write(msg) ; sys.stdout.flush()

def socksend(sock, message):
    try:
        sock.send(message)
    except socket.error as e:
        error.err('SocketError', e.message)

def receber_msg(n, sock, crypt_obj, ep):
    while True:
        recieved = sock.recv(BUFSIZE)
        #r = ast.literal_eval(recieved)
        decrypted = crypt_obj.decrypt(recieved, ep)
        printout('\rmsg: %s\n' % decrypted)
        printout('%s:msg> ' % n)
    thread.exit()

def main():
    print "Walter Client v%s by %s" % (VERSION, AUTHOR)
    
    tcp = socket.socket()
    addr = raw_input('IP do Servidor: ')
    CONN = (addr, PORT)
    trypwd = raw_input('Senha do Servidor: ')
    nick = raw_input('Nick do Usuário: ')
    
    tcp.connect(CONN)
    socksend(tcp, passwordHash(trypwd))
    # handling diffie-hellman
    dh_recep = tcp.recv(BUFSIZE)
    
    # handling wrong passwords
    if dh_recep == "senha errada, seu merda.":
        print 'Wrong password!'
        print 'closing...'
        tcp.close()
        return 1
    
    if dh_recep.startswith('?DIFFIE'):
        D = dh_recep.split()
        prime = int(D[1])
        generator = int(D[2])
        socksend(tcp, '?YESDIFFIE')
        a = dh.get_rand(8)
        PA = dh.g(generator, a, prime)
        socksend(tcp, '?PUBLICA %d' % PA)
        _PB = tcp.recv(BUFSIZE)
        if not _PB.startswith('?PUBLICB'):
            error.err('DH_NValid_PB')
            return 1
        PB = long(_PB.split()[1])
        S = dh.g(PB, a, prime)
        epwd = S
    else:
        error.err('DH_NValid_DIFFIE')
        return 1
    
    # getting WCR key
    H = tcp.recv(BUFSIZE)
    h = H.split(';')
    print h[0]
    key = h[1]
    
    w = WCR(2048)
    w.import_base64(key)
    epwd = str(epwd)
    thread.start_new_thread(receber_msg, tuple([nick, tcp, w, epwd]))
    
    print 'Bem-vindo a um servidor do Walter, boas conversas!'
    
    while True:
        msg = raw_input()
        if msg == '/exit': # closing connection
            socksend(tcp, '1CLOSE')
            tcp.close()
            return 0
        r = w.encrypt('%s: %s' % (nick, msg), epwd)
        socksend(tcp, str(r))

if __name__ == '__main__':
    sys.exit(main())
