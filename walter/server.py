#coding: utf-8
import socket, time, thread, sys, hashlib

from ast import literal_eval
from wcr2 import *

VERSION = '0.0.1'
AUTHOR = 'Lukas Mendes'
PORT = 39
BUFSIZE = 4096

sockets = []

def printout(msg):
	sys.stdout.write(msg); sys.stdout.flush()

def broadcast_all(start_socket, message):
    for s in sockets:
        if s == start_socket:
            pass
        else:
            printout('\n broadcasting: '+repr(s)+'\n')
            s.send(message)

def conectado(sock, cli, spwd, skey, epwd, crypt_obj):
	print 'thread iniciado:', cli, 'com socket:', repr(sock)
	sockets.append(sock)
	trypass = sock.recv(BUFSIZE)
	if trypass == hashlib.md5(spwd).hexdigest(): #acertou
		print '@@@esse pau no cu acertou', cli
		sock.send("acertou seu bosta")
		sock.send(skey)
		print '@@@chave enviada para', cli
		sock.send(epwd)
		#print '@@@senha de criptografia enviada para', cli
		while True:
			recieved_message = sock.recv(BUFSIZE)
			#print 'recebido:', recieved_message
			if recieved_message == '1CLOSE':
				print 'closing connection with', repr(sock)
				break
			e = literal_eval(recieved_message)
			print 'literal_eval:', e
			print '\t!!!message!!!:', crypt_obj.decrypt(e[0], epwd, e[1])
			broadcast_all(sock, recieved_message)
		print '!!!fechado!!:', cli
		sockets.remove(sock)
		sock.close()
	else:
		sockets.remove(sock)
		print 'ERR trolado pela senha', cli
		sock.send("vc errou seu pau no cu") #xinga fortemente o cara que errou a senha
		sock.close()
	print '###exiting of thread###:', cli
	thread.exit()

def mainloop():
	print 'Walter Server v'+VERSION+" by "+AUTHOR
	s_passwd = raw_input("Server Password: ")
	e_passwd = raw_input("Encryption Password: ")
	w = WCR(2048)
	s_key = w.export()
	tcp = socket.socket()
	tcp.bind((socket.gethostbyname('localhost'), PORT))
	tcp.listen(15)
	print 'Listening for Walter Clients in IP', socket.gethostbyname('localhost'), '...'
	while True:
		con, cliente = tcp.accept()
		thread.start_new_thread(conectado, tuple([con, cliente, s_passwd, s_key, e_passwd, w]))

mainloop()