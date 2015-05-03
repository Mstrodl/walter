# -*- coding: utf-8 -*-
# server.py - Walter Server
import socket
import time
import thread
import sys
import hashlib
import ast

import diffie as dh
import error

from wcr2 import WCR

# coisa q tenho q faze
# log no servidor

VERSION = '0.2'
AUTHOR = 'Lukas Mendes'
BANNER = "Walter Server v%s by %s" % (VERSION, AUTHOR)
PORT = 39
BUFSIZE = 4096

sockets = []
secrets = {}
nicks = {}

def passwordHash(x):
    return hashlib.sha256(x).hexdigest()

def logMessage(msg):
    logfile = open('logging.log', 'a')
    logfile.write(time.ctime()+':'+msg+'\n')
    logfile.close()

def printout(msg):
    sys.stdout.write(msg); sys.stdout.flush()

def socksend(sock, message):
    try:
        sock.send(message)
    except socket.error as e:
        error.err('SocketError', e.strerror)

def broadcast_all(start_socket, message):
    for s in sockets:
        if s == start_socket:
            pass
        else:
            try:
                printout('\n broadcasting: %s\n' % repr(s))
                socksend(s, message)
            except:
                printout("\n error: %s\n" % repr(s))
                try: s.close()
                except: pass
                sockets.remove(s)

def broadcast_encryp(sock, m, crypt_obj):
    global secrets
    global sockets
    for s in sockets:
        if s == sock:
            continue
        ssecret = secrets[hash(s)]
        new_message = crypt_obj.encrypt(m, ssecret)
        socksend(s, str(new_message))

def handle_diffie(sock, client):
    '''Handles DHKE(Diffie-Hellman Key Exchange)'''
    gen = dh.get_rand(64)
    p = dh.get_prime(32)
    socksend(sock, '?DIFFIE %d %d' % (p, gen))
    resp = sock.recv(BUFSIZE)
    if resp == '?YESDIFFIE':
        b = dh.get_rand(8)
        PB = dh.g(gen, b, p)
        socksend(sock, '?PUBLICB %d' % PB)
        _PA = sock.recv(BUFSIZE)
        if not _PA.startswith('?PUBLICA'):
            error.err('DH_NValid_PA', client)
            return False
        PA = long(_PA.split()[1])
        S = dh.g(PA, b, p)
        return S
    else:
        error.err('DH_NValid_YD', client)
        return False

def conectado(sock, cli, spwd, skey, crypt_obj):
    global secrets
    global sockets
    global nicks
    cli = str(cli)
    print 'thread iniciado: %s' % cli
    sockets.append(sock)
    trypass = sock.recv(BUFSIZE)
    if trypass == passwordHash(spwd): #acertou
        print '@@@accept %s' % cli
        secret = handle_diffie(sock, cli[0])
        if not secret:
            print '##ERROR NOT SECRET %s' % cli
            sock.close()
            thread.exit()
        socksend(sock, "senha aceita;%s" % skey)
        secret = str(secret)
        secrets[hash(sock)] = secret
        socksend(sock, "**SERVER**: client joined")
        while True:
            recieved_message = sock.recv(BUFSIZE)
            if recieved_message == '1CLOSE':
                cls_msg = '**SERVER**: %s closed connection' % nicks[hash(sock)]
                broadcast_encryp(sock, cls_msg, crypt_obj)
                print 'closing: %s' % repr(sock)
                logMessage('Client closed : %s' % cli)
                break
            elif recieved_message == 'STPING':
                print 'STPING: %s' % cli
                socksend(sock, 'RCVPING')
            else:
                m = crypt_obj.decrypt(recieved_message, secret)
                print 'recv from %s: %s' % (cli, repr(recieved_message))
                print '\tMESSAGE: %s' % m
                nicks[hash(sock)] = m.split(':')[0]
                broadcast_encryp(sock, m, crypt_obj)
            # e = ast.literal_eval(recieved_message)
            # plz dont do this
            # e = eval(recieved_message, {'secrets': secrets})
        print '!!!fechado!!:', cli
        sockets.remove(sock)
        del secrets[hash(sock)]
        del nicks[hash(sock)]
        sock.close()
    else:
        sockets.remove(sock)
        print '###wrong_password: %s' % cli
        socksend(sock, "senha errada, seu merda.") # xinga fortemente o cara que errou a senha
        sock.close()
    print '###closing_thread: %s' % cli
    del sock
    thread.exit()

def main():
    print BANNER
    logMessage("Walter Server v%s started" % VERSION)
    argv = sys.argv
    default = False
    if len(argv) == 1 or argv[1] == 'deflt':
        default = True
        print 'running default arguments'
        print 'HOST -> localhost'
        print 'password -> 123'
        HOST, s_passwd = 'localhost', '123'
    if len(argv) != 3 and not default:
        print 'usage: [sudo] python %s HOST s_passwd' % argv[0]
        return 1
    if not default:
        HOST = argv[1]
        s_passwd = argv[2]
    logMessage('Running server at %s password %s' % (HOST, s_passwd))
    w = WCR(2048)
    s_key = w.export()
    tcp = socket.socket()
    tcp.bind((HOST, PORT))
    tcp.listen(15)
    print 'Waiting for clients in %s...' % HOST
    while True:
        con, cliente = tcp.accept()
        logMessage('New client : %s' % cliente[0])
        thread.start_new_thread(conectado, tuple([con, cliente, s_passwd, s_key, w]))

if __name__ == '__main__':
    sys.exit(main())
