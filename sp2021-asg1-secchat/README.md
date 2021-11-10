
The goal of this application is to build a secure chat application between a client and a server. 

To compile: run 'make all' in the root directory. 

#### Program description - The description should be sufficiently detailed for a third party to be able to write a new client or server program that is able to interface with your programs, without having to read your code.

#### TODO: Describe your server and clients communicate

#### TODO: Describe all possible types of interactions between server and clients, 


#### TODO: the data layout of all possible types of packets sent

#### TODO: a description of any cryptography you apply. 

SP2021-ASF1-SECCHAT is a standalone program that consists of a 'game server' which maintains a game state, as well as 'game client' to display the game. The goal of the game is to collect the most gold nuggets out of all of the players. The game ends when all of the nuggets have been collected.

### How we acheived our security goals: 

Throughout the project, we identified several potential types of attacks are program was susceptible to, as well as ways to prevent those attacks. 

##### List of potential attacks and approaches taken to prevent the attack:  


1. Determine at which addresses all clients and the server are running.
2. Read, modify, inject, and/or block data sent over any network connection between a client and the server.
3. Establish a connection with any client or the server, spoofing her network address to any possible value.


• Implement a malicious client to attack either the server or other clients by sending specially crafted data.
• Implement a malicious server and get clients to connect to it instead of the intended server, to attack clients by sending specially crafted data.
• Perform these actions any number of times, possibly simultaneously.
However, Mallory has no local access to the systems running your programs. She can only access them through your client and server programs. As such, she cannot access memory, access the disk, or intercept keyboard unless she compromises your program first.
7.2 Security properties
Within the threat model specified in the previous section, your programs must be able to satisfy the following security properties:
• Mallory cannot get information about private messages for which she is not either the sender or the intended recipient.
• Mallory cannot send messages on behalf of another user.
• Mallory cannot modify messages sent by other users.
• Mallory cannot find out users’ passwords, private keys, or private messages (even if the server is compromised).
• Mallory cannot use the client or server programs to achieve privilege es- calation on the systems they are running on.g
• Mallory cannot leak or corrupt data in the client or server programs.
• Mallory cannot crash the client or server programs.
• The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments.
• The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and clientkeys directories, or any operating system settings, even if Mallory attempts to force it to do so.
It should be noted that we only require that you protect confidentiality and integrity. Under the given threat model, it is not possible to ensure availability entirely.

#### Possible threats we did not prevent:

#### User interface

The games interfaces with the user in a number of ways.

First, the user must start the server. The program server is run from the application’s root directory with a single argument, port_num, which is the TCP port number for the server to listen on.

```bash
$ ./server port_num &
```

Then, the user runs the client side with the below parameters, at the same port as the server.

```bash
$ ./client localhost port_num
```

```c=
inputline
command
= [WHITESPACE] command [WHITESPACE] NEWLINE
= exitcommand | logincommand | privmsgcommand | pubmsgcommand |
  registercommand | userscommand
= "/exit"
= "/login" WHITESPACE username WHITESPACE password
exitcommand
logincommand
privmsgcommand  = "@" username WHITESPACE message
pubmsgcommand   = message
registercommand = "/register" WHITESPACE username WHITESPACE password
userscommand
username
password
= "/users"
= TOKEN
= TOKEN
```

#### Functional requirements

Client:

- The client is able to register a new account through a username and password. The max length for usernames and passwords is 30 characters.
- The client can only login to an account if he/she uses the associated password
- The client can exit by logging out from the server. This also terminates the client program
- When a user joins the server, all public messages previously are displayed as well as private messages sent for the recipient
- The client can send public messages to all users and private messages to a specified users
- Messages are displayed to the client with a timestamp, author, and recipient (for private messages)
- Duplicate usernames are not allowed on the server
- The maximum length for messages is 500 characters on the server
- Can provide a list of logged in users at a client's request
- Messages are displayed to the intended client(s) immediately

Server:

- The server program supports all the functionality needed to provide the aforementioned client features
- No more than 20 simultaneous connections are allowed
- The server program takes care of all necessary storage for security

#### Dataflow through modules

1. _main_ in `server.c` parses and validates arguments

#### Pseudo code (plain English-like language) for logic/algorithmic flow

**Server.c**

Purpose:

```c=

```

#### Testing plan

This is a very large piece of code on aggregate, so there are many things to test. To do this, both unit and integration testing are necessary.

- Validity of user agruments for client, spectator, and player
- Boundary cases (i.e. player = max players) in different map.txt files
- Behavior of movement (stops at walls, room becomes visible as player moves)
- If program works with multiple players (same or different computers)
- Program handles player leaving correctly
- Program exits correctly when there's an error or game over
