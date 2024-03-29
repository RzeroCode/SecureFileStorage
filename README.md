# SecureFileStorage
This application is a cryptographically secure file sharing and storage application. With the loading of appropriate public and private keys of server and client and authentication will be done by server to the client based on client’s entered password if authentication is granted based on entered password. If password is entered correctly user will be able to decrypt it’s encrypted private key. If not, authentication fails and user is again asked for their password. Then a challenge-response protocol is run to authenticate the user. For each phase of the communication, messages are signed and verified. RSA algorithm is used for this purpose. If authentication protocol finishes successfully a session key is generated based on HMAC between client and the server. 
	 All authenticated clients can store and retrieve files from the server. All these processes are done securely using previously generated session key. All files are encrypted and their names are standardized based on client’s name. Only owner of the file can restore its original name and decrypt its contents. This is done using AES based private key cryptography. A client can also request another client’s file from the server. In this case, secure file relaying algorithm is run. Server requests permission of the file’s owner. If it is granted, owner sends private AES key to the server (Also file’s original name), server relays it to the requester. Then requester can receive the encrypted file, appropriate keys and original file name. Requester finally restores the file in its storage. Server can never know files contents and its original name. This is achieved using public key cryptography.

### File Relaying Algorithm:	 

Requesting Client: X, File Owner Client: Y, Server: S File: F

1. X -> S: download request for F using its name that was assigned by server (signed 
using X's RSA private key)
1. S -> Y: ask for permission to send F to the client X
1. Y -> S: F's AES key || IV || F's original filename sent (encrypted with RSA and 
authenticated with HMAC)
1. S -> X: relay message 3 and the encrypted file (all signed using RSA)
