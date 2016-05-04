# Walter Protocol

When a client starts a connection with a server, the client sends their password and if that password matches with what the server has in it, they make a Diffie-Hellman Key Exchange and use that secret to be an password for a XOR cipher, else, the server closes the connection and sends a lovely message to the client.
IV => IV for XOR cipher
p, gen, pb, pa => prime number, generator, public number B, public number A
```
 A(client): --sends sha256(password)--
 B(server): senha aceita;IV
 B: ?DIFFIE p gen
 A: ?YESDIFFIE
 B: ?PUBLICB pb
 A: ?PUBLICA pa
 --A and B have the same secret now--
```

Client side after that: the client receives an IV from server and uses in the XOR cipher, and then the client enters an infinite loop waiting for input and receiving messages from server.

Server side after that: the server uses the secret in the key exchange and puts that in an table, relating each socket to each secret.
```
 secret = str(secret)
 secrets[hash(sock)] = secret
```

## Messages

When a client gets an input from user, it uses the XOR cipher and sends that chiphertext, when the server recieves that ciphertext, it applies the XOR cipher again and gets the text from the client, after that it broadcasts the encrypted message to all sockets and it uses the secret from each socket to send it only to that socket.
```
 A: --scrambled message--
 B: --descrambles it and broadcasts it, using broadcast_encryp()--
 C(another client): --descrambles it and shows that message to user--
```

### /exit
```
 A: 1CLOSE
 B: --closes connection and closes the thread related to that client, its that simple--
```

### /ping
```
 A: STPING
 B: RCVPING [A does not try to descramble this message, thanks to receber_msg()]
 A: --you know, t1 - t0 and bang! ping--
```
