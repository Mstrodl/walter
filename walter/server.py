#coding: utf-8
import socket, time, thread, sys, hashlib

from ast import literal_eval
from wcr2 import *

VERSION = '0.0.1.5'
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
			try:
				printout('\n broadcasting: '+repr(s)+'\n')
				s.send(message)
			except:
				printout("\n error: "+repr(s)+'\n')
				try: s.close()
				except: pass
				sockets.remove(s)

def conectado(sock, cli, spwd, skey, epwd, crypt_obj):
	print 'thread iniciado:', cli, 'com socket:', repr(sock)
	sockets.append(sock)
	trypass = sock.recv(BUFSIZE)
	if trypass == hashlib.md5(spwd).hexdigest(): #acertou
		print '@@@acertou', cli
		sock.send("senha aceita" + ';' + skey + ';' + epwd)
		print '@@@chave enviada:', cli
		#print '@@@senha de criptografia enviada para', cli
		while True:
			recieved_message = sock.recv(BUFSIZE)
			#print 'recebido:', recieved_message
			if recieved_message == '1CLOSE':
				print 'closing:', repr(sock)
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
		sock.send("senha errada, seu merda.") #xinga fortemente o cara que errou a senha
		sock.close()
	print '###exiting of thread###:', cli
	thread.exit()

def mainloop():
	print 'Walter Server v'+VERSION+" by "+AUTHOR
	argv = sys.argv
	if len(argv) != 4:
		print 'usage: [sudo] python server.py HOST s_passwd e_passwd'
		sys.exit(1)
	#HOST = raw_input("Server hosting IP: ")
	#s_passwd = raw_input("Server Password(without ; character): ")
	#e_passwd = raw_input("Encryption Password(without ; character): ")
	HOST = argv[1]
	s_passwd = argv[2]
	e_passwd = argv[3]
	w = WCR(2048)
	s_key = w.export()
	tcp = socket.socket()
	tcp.bind((HOST, PORT))
	tcp.listen(15)
	print 'Listening for Walter Clients in IP', HOST, '...'
	while True:
		con, cliente = tcp.accept()
		thread.start_new_thread(conectado, tuple([con, cliente, s_passwd, s_key, e_passwd, w]))

mainloop()