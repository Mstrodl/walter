#coding: utf-8
import sys, socket, time, thread, hashlib

from wcr2 import *

VERSION = '0.0.1.2'
AUTHOR = 'Lukas Mendes'
PORT = 39
BUFSIZE = 4096

def printout(msg):
	sys.stdout.write(msg) #; sys.stdout.flush()

def receber_msg(n, sock, crypt_obj, ep):
	printout('Iniciado, mensagens aparecerao automaticamente aqui.\n')
	while True:
		recieved = sock.recv(BUFSIZE)
		r = eval(recieved)
		decrypted = crypt_obj.decrypt(r[0], ep, r[1])
		printout('\rmsg: %s\n' % decrypted)
		printout('\n'+n+': msg> ')

def main():
	tcp = socket.socket()
	print 'Walter Client v'+VERSION+' by '+AUTHOR
	addr = raw_input('Server address: ')
	CONN = (addr, PORT)
	trypwd = raw_input('Server password: ')
	nick = raw_input('User nick: ')
	tcp.connect(CONN)
	tcp.send(hashlib.md5(trypwd).hexdigest())
	H = tcp.recv(BUFSIZE)
	h = H.split(';')
	print h[0]
	key = h[1]
	epwd = h[2]
	w = WCR(2048)
	w.import_base64(key)
	thread.start_new_thread(receber_msg, tuple([nick, tcp, w, epwd]))
	while True:
		msg = raw_input()
		if msg == '/exit':
			tcp.send('1CLOSE')
			tcp.close()
		r = w.encrypt(nick+': '+msg, epwd)
		tcp.send(str(r))

main()
