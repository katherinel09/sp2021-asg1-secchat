- intiailize memory  correctly (use calloc for heap!)
- set pointers to null after deallocated
- check for buffer overflows through arithmatic!!

- Think about which inputs are permissible
- Choose types based on these ranges
- Verify whether each input is in range before converting
- Always compile with -Wall and -Werror

- test boundary cases 
- - login with no users
- - cases with no users
- - cases with max users
- - repeated username attempt

- Corner code => just above or below size limits and integer ranges
- Extreme values far outside expected ranges
- Generate random inputs


Compiling (to do)
- gcc -fporfile-arcs -ftest-coverage -o -parseint parseint.c
- gcc -fsanitize=address -o buffer-overflow buffer-overflow.c
- gcc -fsanitize=undefined -o buffer-overflow buffer-overflow.c
valgrind ./myprogram param1 param2
afl-gcc -o hello hello.c (afl-fuzz -i in -o out ./hello) (sudo apt install afl)
* remember to you need to multiplex the input
Ex: input consists of commands which specify both data and which socket to send it t

O DO from deadline 1a: 

#2 [0/1] Can exit program using /exit and CTRL+D (end-of-file)
[0/1] Exit the client and connect to the client again, is the old
 message shown?
#1 [0/1] Is the message correctly formatted, including a timestamp
 (see example in assignment). Sender needs not be included yet.
[1/1] Connect a second client and send a short public message.
 Is it shown immediately in the original client?
#3 [0/1] Type the bogus command /nonsense, do you get a sensible error
 message?
[1/2] README.md clearly documents the protocol between client and server,
 including all messages send and the way they are encoded on the
 socket.

--- feedback ---
Your documentation is very detailed, but unfortunately you did not (yet) document the protocol between client and server (further than that their communication happens via sockets), or describe the messages that are sent and their encoding or data layout.

#1 The chat messages are not formatted according to the assignment specification. Check the specification Section 5: Each message is shown together with a timestamp, the user who sent it, and for private messages also the recipient. The assignment specification also gives an example of what this can look like.
// Kat - matter of change the string, add the time stamp

#2 Both /exit and CTRL+D do not work. When typing /exit, it is recognized as an exitcommand, but the client freezes and does not exit.

#3 Bogus commands are simply sent as public messages.
// Kat - implement an error messahe

Deadline 1c TO DO :)))

Functional requirements: 

- The user can register a new account. To do so, they will have to supply a username and a password.
– You are allowed (but not required) to set a maximum length for the username and/or the password, as long as it is no less than 8 characters.
- The application prohibits registration of a user with a previously registered username.
- The user can login. It is only possible to login to an account if one knows the password supplied at registration time.
- The user can exit. This logs out from the server and terminates the client program.
- When the client starts, it displays all public messages previously sent by anyone, and all private messages received and sent by the current user, in chronological order from old to new.
- The user can send a public message to all users.
- The user can send a private message to a specific user.
- You are allowed (but not required) to set a maximum length for messages, as long as it is no less than 140 characters.
- Each message is shown together with a timestamp, the user who sent it, and for private messages also the recipient.
- The clients only show (1) public messages and (2) private messages of which the logged in user is either the sender or the recipient.
- Each message will be shown to its recipient(s) immediately (or at least, as immediate as network latency will allow).
- The client provides a list of logged in users on request.
- The server program implements a protocol to communicate with the client, supporting all the functionality needed to provide these client features. 
- The server program takes care of all necessary storage, at least to the extent that security requirements allow. The server may limit the number of simultaneous connections, but this limit must be no less that 10.
- Implement additional user and/or message metadata, interface elements, and protocol features to ensure the security of the application
- Where and how you need to use cryptography, and how to manage cryptographic keys.

Nonfunctional requirements: 
- All permanent state is stored in a SQLite database on the server side named chat.db, located directly within the application’s root directory. - - This state includes (but is not limited to) users and sent messages. 
- The client must retrieve this state from the server when needed. 
- Both the server and the client may use the disk to store cryptographic keys, but only in a dedicated directory named serverkeys or clientkeys respectively, located directly within the application’s root directory. 
- The programs may not access each other’s keys directories. 
- The programs may invoke the trusted third party (a script), which can access the ttpkeys directory. Nothing else may be stored on disk by either program. 
- Connection-bound information (which authenticated user is on the other end, which nonce was sent, etc.) may be stored in memory. 
- Restarting the server or any of the clients should not result in any loss of data other than the need to re-establish connections.
- Network connections are only set up by the clients, and only connect to the server. There are no direct connections between clients.



This is the final application, which should support all the requirements in the assignment. Even if you do not manage to meet all requirements, prioritize at least making sure that the program works. Make sure you pass all the tests in test.py (see Section ?? about testing).

The files to hand in are identical to deadline A, but now also optionally includes files for the web chat feature if you choose to implement it (web-related file types such as .html, .js, .css, etc).

**only allowed to use -lcrypto -lssl -lsqlite3**


--- grade explanation ---
[1.0/2.0] All message types are documented
[0.5/1.0] Confidentiality: connection protected against eavesdroppers
[0.5/1.5] Confidentiality: server cannot read private messages
[0.5/1.0] Integrity: connection protected against modification of data
[1.0/1.5] Integrity: server cannot forge or modify a user's message
[0.5/1.0] Authentication: client cannot impersonate another client to server
[0.0/1.0] Authentication: clients validate server identity/public key
[0.0/1.0] Authentication: clients validate other clients' identity/public key

--- feedback ---
An explicit definition of all different types of messages and the values stored in these messages is missing from the documentation.

C(onfidentiality):
- You describe when a client signs in using SSL... which is unclear. Does this mean that there is an SSL connection setup between the client and the server? I would suggest to implement this, so that the connection is protected from eavesdroppers and protected against modification.
- The encryption scheme for private messages is incorrect. Messages should be encrypted on the client-side, as the server should never be able to read the contents (it might be a compromised server). I suggest to use the following scheme:
* the sender finds out the public key of the recipient
 (may require an additional message)
* the sender generates a random symmetric key (for example AES)
* the sender encrypts the message using the symmetric key
* the sender encrypts the symmetric key using the recipient's public key
* the sender also encrypts the symmetric key using its own public key
* all three parts are stored by the server and forwarded to the recipient
* the recipient decrypts the symmetric key using its private key
* the recipient decrypts the message using the symmetric key

I(ntegrity):
- Again, it is not clear if you are using SSL to set up a connection from client to server.
- You do mention that you will use hashing to check if a message has been modified. Again, your description is quite vague. Make sure that you use the following scheme for your message signatures:
To protect against the server forging/modifying messages, they must be signed by the sender and the signature verified by the recipient. It is most sensible to use asymmetric signatures for this, for example RSA. The sender signs with their own private key, and the recipient verifies that signature using the sender's public key. This means the client must be able to get other client's certificates. They can be included in the message that is sent in this case.

A(uthentication):
- It is not mentioned how passwords are handled... I recommend sending the hashed password over a secure connection (SSL) to the server, which then salts the hash and recursively hashes the password again. This is done in order to protect against leaked password databases.
- For both client and server verification, it is unsure how the TTP is used or invoked to verify identities. When exchanging certificates, you *have* to check whether or not certificates are signed by the TTP and whether or not the common name on the certificate matches either the server or the respective client!
