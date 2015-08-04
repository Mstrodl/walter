# -*- coding: utf-8 -*-
# client.py - Walter Client
import socket
import time
import thread
import sys
import hashlib
import ast
import platform

import diffie as dh
import error

from wcr2 import WCR

VERSION = '0.2.1.feelsgoodmate'
AUTHOR = 'Lukas Mendes'
PORT = 39
BUFSIZE = 4096
MSG_MAX = 1024

ping_lock = False
read_lock = False
used = False

def beep_message():
    if platform.os.name == 'posix':
        print '\a'
        time.sleep(0.2)
    elif platform.os.name == 'windows':
        winsound.Beep(200, 200)

def socksend(sock, message):
    try:
        sock.send(message)
    except socket.error as e:
        error.err('SocketError', e.strerror)

def passwordHash(x):
    return hashlib.sha256(x).hexdigest()

def printout(msg):
    sys.stdout.write(msg) ; sys.stdout.flush()

def read_message(socket):
    global used
    n = ''
    n += sys.stdin.read(1)
    while n[len(n)-1] != '\n':
        if not read_lock:
            try:
                n += sys.stdin.read(1)
            except KeyboardInterrupt:
                socksend(socket, "1CLOSE")
        else:
            if not used:
                used = True
                printout('%s\n' % n)
    return n

def receber_msg(n, sock, crypt_obj, ep):
    global ping_lock
    global read_lock
    global used
    while True:
        recieved = sock.recv(BUFSIZE)
        if recieved == 'RCVPING':
            ping_lock = True
        elif recieved == 'SVERR':
            sys.exit(1)
        elif recieved[:4] == "MTD^":
            print 'Server MOTD:', recieved.split('^')[1]
        elif recieved == '**SERVER**: client joined':
            printout('%s\n' % recieved)
        else:
            ping_lock = False
            read_lock = True
            #r = ast.literal_eval(recieved)
            decrypted = crypt_obj.decrypt(recieved, ep)
            beep_message()
            printout('\n\rmsg: %s\n' % decrypted)
            printout('%s:msg> ' % n)
            read_lock = False
            used = False
    thread.exit()

def main():
    global ping_lock
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
        secret = dh.g(PB, a, prime)
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
    thread.start_new_thread(receber_msg, tuple([nick, tcp, w, str(secret)]))
    
    print 'Welcome to a Walter server!'
    
    while True:
        msg = read_message(tcp).strip()
        if msg.startswith('/'):
            if msg == '/help':
                print '/exit - exits server'
                print '/ping - pings server'
            elif msg == '/exit': # closing connection
                socksend(tcp, '1CLOSE')
                tcp.close()
                return 0
            elif msg == '/ping': #pinging to server
                print 'ping cmd'
                t1 = 0
                t = time.time()
                socksend(tcp, 'STPING')
                time.sleep(1)
                if ping_lock:
                    t1 = time.time()
                    ping_lock = False
                else:
                    print 'ping: not lock'
                t2 = t1 - t
                print t2
                print '%3.2fms' % ((t2-1)*1000)
            elif msg[:11] == '/fixmessage':
                new_motd = msg[12:]
                print 'setting motd to %s' % new_motd
                socksend(tcp, 'MOTD^%s' % new_motd)
                print 'setted.'
            elif msg == '/message' or msg == '/motd':
                socksend(tcp, "GETMOTD")
        else:
            r = w.encrypt('%s: %s' % (nick, msg), str(secret))
            socksend(tcp, str(r))

if __name__ == '__main__':
    sys.exit(main())

