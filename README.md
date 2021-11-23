# sp2021-asg1-secchat

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
