# sp2021-asg1-secchat

### Katherine Lasonde and Mark Wiering
### Security and Privacy
### Assignment 1b

For client A to send a message to client B, client A sends a message to the server, which then reads and writes the message to client B via a socket. Thus, the server is always an intermediary between two clients sending and receiving messages, and there are no direct connections between clients. This is an important feature of our program since reading and modifying data sent over any network connection is explicit in our threat model. We want to lower the chances of one client taking advantage of another client's lax security behaviours and launching an attack.

There are two types of messages that a client can send to another client, private and public. Private messages are defined as messages which have recipients, while public messages are messages that all clients on the server will receive. Messages are displayed to the client with a timestamp, and author.

There are several cryptographic methods in place to protect users and their messages. One of our program's main priorities is protecting the addresses of our clients, since according to the threat model, Mallory will try to determine the addresses of all clients and servers. To protect users' addresses, we authenticate users via signing into accounts. Each user has their own unique username and password. We ensure that passwords cannot be easily guessed by a computer and have a high complexity for computers while being easy to remember for users. We ensure that only authenticated users can access permitted resources, and thus we check the user's permissions to a resource on every access request. 

Moreover, we assign each authenticated user a set of unique private and public keys. We generate and store the users' personal keys in the clientkey directory on the disk, while the server's keys are stored in the serverkeys directory on the disk. 
There is also a trusted, third-party (TTP) script which we wrote to verify keys via the **ttpkeys** directory. We invoke the TTP from our program when setting up a new user. However, since TTP is a separate server that is susceptible to attacks, we give it the bare minimum information and privileges necessary when verifying. It can only validate and read the keys from the directory. It cannot write to those directories. Do keep in mind that the TTP is really a separate server that should receive as little private information as possible. This TTP prevents Mallory from spoofing her network address to any possible value and then attempting to establish a connection with the client or server.
Specifically, we use the OpenSSL library to allow users to create a signature and then be able to validate that signature. We generate a private and public key pair for the client and place them into the aforementioned **clientkey** and **serverkey** directories. In our program, we use the function provided by the cryptographic library RSA_generate_key_ex to generate the initial keys. When a client signs in using SSL, we read their private key, and then we assign their key to an EVP key structure. Later on, when we verify a signature, we read the client's public key, assign it to an EVP key, and then we use a hash function to verify the user's identity.  

Since the **clientkey**, **serverkey**, and **ttpkeys** directory are all located locally within the root directory, attackers cannot access those keys unless they compromised our server and chat client. Thus, we decrease the odds of a data leak by storing keys locally. We also have specific permissions for each directory, however, these files are writable, which makes them even more important to protect. 

If the server is compromised, we ensure that users' private messages cannot be leaked by utilising encryption. Specifically, we use RSA encryption to encrypt and decrypt messages. To encrypt a message, a user sends a message to the server, which is then checked to be less than the available memory for the message. Using the client's public key, the message is encrypted via the XOR function and outputted on stdout. 

Furthermore, if the server is compromised – in other words, if we detect suspicious behaviour such as a program attempting to read or overwrite the **clientkey** or **serverkey** directories --  users are sent a message notifying them to change their password and to regenerate their private key. 

We also utilise the techniques of padding and cipher block chaining to provide an additional layer of security on users' private messages. We do not want Mallory to be able to find out anything about the messages for another recipient. To implement padding, we add extra bits to each byte of data (*even if they are a multiple of the key size*) using the cryptographic library. To implement cipher block chaining, we divide the messages a user intends to send into blocks, and then perform computations on those blocks. The computation performed on a block is the XOR of the previous blocks' ciphertext and the current block's plaintext. (*The initial block uses a randomly generated initialisation vector since there is no previous block.*) We also encrypt public messages to prevent users outside of the program from reading them. We do not want a banned user to connect and read public messages.

Additionally, code injections are a specific code in our threat model. Thus, to prevent code injections, we prevent users from being able to inject an escape sequence into our database. Thus, we check for special C-language escape characters \n, \r, \t, \a, \b, \f, \v, and many more whenever users input data. We also check for SQL injection sequences of characters, and thus we parse messages for the 'character. We use the C standard library, the OpenSSL crypto, SSL libraries, and the sqlite3 libraries to prevent escaping.

Finally, to prevent method modification, we are going to use hashing within RSA encryption to check if a message has been modified. If one client wants to send a message to a second client, they will generate a random hash and compute hash(m) where m is their message. The first client will then apply their private key to the hashed message, and send the message to the second client. The receiver will then apply the first client’s public key to the received message. In other words, the second client will compute the applied public key to the private key application of the hashed messaged. If the result is the same as hash(m), then the message was not modified. However, if the hash has changed, then a modification must have occurred. Thus, our program double checks all messages to ensure the hash(m) matches between the first and second client. 






Other:




This is the private repository for Security and Programming assignment #1 at VU. Please see the inside README.md for more details. 

TO DO from deadline 1a: 

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

#2 Both /exit and CTRL+D do not work. When typing /exit, it is recognized as an exitcommand, but the client freezes and does not exit.

#3 Bogus commands are simply sent as public messages.

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
