# Security and Privacy README.md 
# sp2021-asg1-seccaht
### Program Description
SP2021-ASF1-SECCHAT is a standalone program that consists of a 'chat server' which maintains a chat states which create conversation, as well as a 'chat client' to allow users to communicate with the server. The goal of the program is to host a secure chat application in C that runs on Linux. The states that the server will include but not limit to users sending and receiving private and public messages. 

The state of this README currently reflects the functionality as November 16 for the first deadline of assignment one. The goal of this deadline is to build a secure chat application between a client and a server. Specifically, we implemented the functionality of sending messages, receiving messages, parsing commands, and showing messages between two servers. 

# To compile: 
Run 'make all' in the root directory. 

#### How the server and the client communicate
Currently, we 


=======

# The goal of this application is to build a secure chat application between a client and a server. 

# To compile: run 'make all' in the root directory. 

#### Program description - The description should be sufficiently detailed for a third party to be able to write a new client or server program that is able to interface with your programs, without having to read your code.

SP2021-ASF1-SECCHAT is a standalone program that consists of a 'chat server' which maintains a chat states which create conversation, as well as a 'chat client' to allow users to communicate with the server. The goal of the program is to host a secure chat application in C that runs on Linux. The states that the server will include but not limit to users sending and receiving private and public messages. 
>>>>>>> 5979c934d686efd16a8c6a3c9329ef71bf370c6c

#### Functional requirements of the client and server

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

#### Nonfunctional program requirements

In addition to several functional requirements, our program also meets a set of nonfunctional requirements.  

In particular: 
1. Permanent state information is stored on a server-side database named chat.db, which can be retrieved by the client as needed. 
2. The server and client's keys are both stored in the directories serverkeys and clientkeys within the root directory
3. Programs may not access each other's keys without invoking a trusted third party to access the ttpkeys directory
4. Restarting the server does not result in any loss of data
#### How the server and clients communicate

#### Possible types of interactions between server and clients, 


#### TODO: the data layout of all possible types of packets sent

#### TODO: a description of any cryptography you apply. 

### How we acheived our security goals: 

Throughout the project, we identified several potential types of attacks are program was susceptible to, as well as ways to prevent those attacks. 

##### List of potential attacks and approaches taken to prevent the attack:  

Since a hacker does not have local access to our system, she can only access the program through the client or server. To prevent her from accessing sensitive information by compromising the program, we implemented several approaches defined below. 

1. Attacks may occur at the addresses at which clients and the server are running 

To prevent a hacker from utilizing server and client addresses to gain secret information, we placed extra protection on where those addresses can be accessed. 

2. Attackers may attempt to read, modify, inject, and/or block data sent over any network connection between a client and the server

To prevent a hacker from reading, modifying, injecting, or blocking data over a network, we implemented several approaches.

3. Attacks may attempt to establish a connection with any client or the server, spoofing her network address to any possible value.


4. Attackers may implement a malicious client to attack either the server or other clients by sending specially crafted data.

5. Attackers may implement a malicious server and get clients to connect to it instead of the intended server, to attack clients by sending specially crafted data.


Furthermore, attackers may try to perform these actions any number of times, possibly simultaneously. In order to prevent simultaneous attacks, we

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


#### Dataflow through modules

1. _main_ in `server.c` parses and validates arguments

#### Pseudo code (plain English-like language) for logic/algorithmic flow

**Server.c**

Purpose:

```c=

```

#### Testing plan

This is a very large piece of code on aggregate, so there are many things to test. To do this, both unit and integration testing are necessary.

- Validity of user agruments for client and server
- Boundary cases, such as sending the max length of the chat, sending a message to a user that doesn't exist, maximizing the number of clients on the server, 
- Private vs. public message visibility
- If server works with multiple client (same or different computers)
- Program handles player leaving correctly
- Program exits correctly when the server is closed (whether compromised or not)

Specific test attacks we tested: 
- Attackers sending messages on behalf of another user.
- Attackers modifying messages sent by other users
- Attackers finding out users’ passwords, private keys, or private messages (even if the server is compromised).
- Attackers using the client or server programs to achieve privilege escalation on the systems they are running on
- Attackers attempting to leak or corrupt data in the client or server programs
- Attackers crashing the client or server programs.
