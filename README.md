# Security and Privacy README.md 
# sp2021-asg1-seccaht

### Program Description
SP2021-ASF1-SECCHAT is a standalone program that consists of a '*chat server*' which maintains chat states to allow for a conversation to take place, as well as a '*chat client*' to allow users to communicate with the server. The goal of the program is to host a secure chat application in C that runs on Linux. The states that the server will include (*but won't be limited to*) are users sending and receiving private and public messages. 

The state of this README currently reflects the functionality as November 16 for the first deadline of assignment one. The goal of this deadline is to build a secure chat application between a client and a server. Specifically, we implemented the functionality of sending messages, receiving messages, parsing commands, and showing messages between two servers. 

# To compile: 
Run '*make*' or '*make all*' in the root directory. Linker tags include -lcrypto -lssl -lsqlite3. 

We recommend compiled with the following tags when looking for errors:
gcc -fporfile-arcs -ftest-coverage -o -parseint parseint.c
gcc -fsanitize=address -o buffer-overflow buffer-overflow.c
gcc -fsanitize=undefined -o buffer-overflow buffer-overflow.c valgrind ./myprogram param1 param2 afl-gcc -o hello hello.c (afl-fuzz -i in -o out ./hello) (sudo apt install afl)

### Methods in server.c
```c=
static int create_server_socket(uint16_t port)
static void child_add(struct server_state *state, int worker_fd)
static void children_check(struct server_state *state)
static void close_server_handles(struct server_state *state)
static int handle_connection(struct server_state *state)
static int handle_s2w_closed(struct server_state *state, int index)
static int handle_s2w_write(struct server_state *state, int index)
static void handle_sigchld(int signum)
static void register_signals(void)
static void usage(void)
static int server_state_init(struct server_state *state)
static int handle_incoming(struct server_state *state)
int main(int argc, char **argv)
```

### Data structures in server.c
```c=
struct server_child_state
{
	int worker_fd;  /* server <-> worker bidirectional notification channel */
	int pending; /* notification pending yes/no */
};

struct server_state
{
	int sockfd;
	struct server_child_state children[MAX_CHILDREN];
	int child_count;
};
```
The first data structure -- server_child_state -- holds infromation about the worker and if there is a notifcation available. The second data structure -- server_state -- holds information about the state of the chidl servers in a singular object. 

### Data flow through server.c

First, the user must start the server. The program server is run from the application’s root directory with a single argument, port_num, which is the TCP port number for the server to listen on.

```bash
$ ./server port_num &
```

In the main funtion, a reference for the port is defined as well as a new server_state struct. The arguments are then parsed to ensure that no malicious arguments may be entered by an attacker to manipulate our system. 

Then, we initialise the state of the server using the reference to the above struct. We clear the previous memory addresses and begin to initialise the correct sockets to the specified ports according to the system requirements. 

Now, the server is able to register SIGCHLD signals and will accept them, while SIGPIPE signals are completely ignored. The server then is called to make the connections between sockets and ports that were earlier initialised, thus allowing the server to start listening for incoming client conenctions. 

While the server is waiting, it will continuously check for new client connections through the **children_check** method. The server will infinitely check if a child has finished or not, and if they did finish, state how the child died. The server then parses the messages of all the existing children, by allocating read and write file descriptor references. The program will then infintely handle incoming notifcations and send outgoing notifications to the client until terminated. 

When the server is no longer needed, the allocated memory is freed and the program exits a return code of 0. 

### Methods in client.c
```c=
char* huidigeTijd()
static int client_connect(struct client_state *state, const char *hostname, uint16_t port) 
static int client_process_command(struct client_state *state) 
static int execute_request( struct client_state *state, const struct api_msg *msg) 
static int handle_server_request(struct client_state *state)
static int handle_incoming(struct client_state *state)
static int client_state_init(struct client_state *state)
static void client_state_free(struct client_state *state)
```

### Data structure in client.c
```c=
struct client_state
{
	struct api_state api;
	int eof;
	struct ui_state ui;
};
```
This data structure holds information about the state of the client in a singular object. 


### Data flow through client.c

The user runs the client side with the below parameters, at the same port as the server.

```bash
$ ./client localhost port_num
```

First, we disable buffering of the output to ensure that hackers are unable to mine for private data. Once this is done through the setvbuf function, we parse the number of inputted arguments for correctness, as well as ensuring that there are no possibilities of malicious inputs. 

Once the inputs are parsed, we initialise the client state. To do this, we clear the previous memory in the space we wish to store the reference, and then we create a new user interface reference.  Once the client is intialised, the client is connected to the server. Here, we check that the state and the hostname are the anticipated values and a hacker is not attempting to input malicious parameters. Then, we look up the hostname, create the TCP socket, and connect to the server. If any of the previous steps fail, we return an exit code of **-1**. 

Once the client has successfully connected, we initialised the associated APIs such that we are referencing the messages and the states of the API. Finally, the client is able to send and receive messages from the server as long as both parties are working. When the client exits the server properly, allocated memory is freed and the program returns an exit code of 0. 

### How the server and the client communicate
Currently, the server is first set up, then clients are able to join the server.  

### Functional requirements implemented within the client and server

Client:

- The client is able to register a new account through a username and password. The max length for usernames and passwords is 20 characters.
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
2. The server and client's keys are both stored in the directories **serverkeys** and **clientkeys** within the root directory
3. Programs may not access each other's keys without invoking a trusted third party to access the **ttpkeys** directory
4. Restarting the server does not result in any loss of data
#### How the server and clients communicate

The server makes multiple workers that handle incoming connections from an external client. Via a socket, the worker and the client can send data. Every worker is connected to the server by a different bidrectional socket. By reading or writing to this bidrectional socket, either the worker or the server can notify each other that an action has to be taken. In this way, the client can communicate with the server and the server can communicate with all the connected clients. 

Currently, there is no limit set to the size of the packets that the client may send to the server. The server, however, reads incoming packets with **size** 256, meaning that if you send a message that is longer than 256 ASCII characters, the server will split your message up in multiple smaller ones (*each with a maximum size of 256 characters, of course*). Only the last portion of the split, however, gets sent to other users. This is a bug that we still need to fix.

### Implemented security measures

For client A to send a message to client B, client A sends a message to the server, which then reads and writes the message to client B via a socket. Thus, the server is always an intermediary between two clients sending and receiving messages, and there are no direct connections between clients. This is an important feature of our program since reading and modifying data sent over any network connection is explicit in our threat model. We want to lower the chances of one client taking advantage of another client's lax security behaviours and launching an attack.

There are two types of messages that a client can send to another client, private and public. Private messages are defined as messages which have recipients, while public messages are messages that all clients on the server will receive. Messages are displayed to the client with a timestamp, and author.

There are several cryptographic methods in place to protect users and their messages. One of our program's main priorities is protecting the addresses of our clients, since according to the threat model, Mallory will try to determine the addresses of all clients and servers. To protect users' addresses, we authenticate users via signing into accounts. Each user has their own unique username and password. We ensure that passwords cannot be easily guessed by a computer and have a high complexity for computers while being easy to remember for users. We ensure that only authenticated users can access permitted resources, and thus we check the user's permissions to a resource on every access request. 

Moreover, we assign each authenticated user a set of unique private and public keys. We generate and store the users' personal keys in the clientkey directory on the disk, while the server's keys are stored in the serverkeys directory on the disk.  There is also a trusted, third-party (TTP) script which we wrote to verify keys via the **ttpkeys** directory. We invoke the TTP from our program when setting up a new user. However, since TTP is a separate server that is susceptible to attacks, we give it the bare minimum information and privileges necessary when verifying. It can only validate and read the keys from the directory. It cannot write to those directories. Do keep in mind that the TTP is really a separate server that should receive as little private information as possible. This TTP prevents Mallory from spoofing her network address to any possible value and then attempting to establish a connection with the client or server.
Specifically, we use the OpenSSL library to allow users to create a signature and then be able to validate that signature. We generate a private and public key pair for the client and place them into the aforementioned **clientkey** and **serverkey** directories. In our program, we use the function provided by the cryptographic library RSA_generate_key_ex to generate the initial keys. When a client signs in using SSL, we read their private key, and then we assign their key to an EVP key structure. Later on, when we verify a signature, we read the client's public key, assign it to an EVP key, and then we use a hash function to verify the user's identity.  

Since the **clientkey**, **serverkey**, and **ttpkeys** directory are all located locally within the root directory, attackers cannot access those keys unless they compromised our server and chat client. Thus, we decrease the odds of a data leak by storing keys locally. We also have specific permissions for each directory, however, these files are writable, which makes them even more important to protect. 

If the server is compromised, we ensure that users' private messages cannot be leaked by utilising encryption. Specifically, we use RSA encryption to encrypt and decrypt messages. 

To read encrypt and decrypt messages, we first read in the plaintext that the first client wants to send from stdin as well as their username. We check that the plaintext size fits within the key size (including padding) to ensure there are no buffer overflows. We chose our key length size to be 2048. 

Once this is complete, we generate RSA private and public keys using functions in the OpenSSL library. We write these to the clientkey directory within the repository. Next, we use the RSA_public_encrypt function in the OpenSSL library to encrypt the plain text with the public key or private key based upon the type of message. Once we have done this, we delete the original plaintext file with the message and send the encrypted file to the server. 

To decrypt the file, we use the private key of the second client and the RSA_ private_decrypt (or public) OpenSSL method. We are able to discern where the message is coming from based upon the associated certificate. 

Furthermore, if the server is compromised – in other words, if we detect suspicious behaviour such as a program attempting to read or overwrite the **clientkey** or **serverkey** directories --  users are sent a message notifying them to change their password and to regenerate their private key. 

We also utilise the techniques of padding and cipher block chaining to provide an additional layer of security on users' private messages. We do not want Mallory to be able to find out anything about the messages for another recipient. To implement padding, we add extra bits to each byte of data (*even if they are a multiple of the key size*) using the cryptographic library. To implement cipher block chaining, we divide the messages a user intends to send into blocks, and then perform computations on those blocks. The computation performed on a block is the XOR of the previous blocks' ciphertext and the current block's plaintext. (*The initial block uses a randomly generated initialisation vector since there is no previous block.*) We also encrypt public messages to prevent users outside of the program from reading them. We do not want a banned user to connect and read public messages.

Additionally, code injections are a specific code in our threat model. Thus, to prevent code injections, we prevent users from being able to inject an escape sequence into our database. Thus, we check for special C-language escape characters \n, \r, \t, \a, \b, \f, \v, and many more whenever users input data. We also check for SQL injection sequences of characters, and thus we parse messages for the 'character. We use the C standard library, the OpenSSL crypto, SSL libraries, and the sqlite3 libraries to prevent escaping.

Finally, to prevent method modification, we are going to use hashing within RSA encryption to check if a message has been modified. If one client wants to send a message to a second client, they will generate a random hash and compute hash(m) where m is their message. The first client will then apply their private key to the hashed message, and send the message to the second client. The receiver will then apply the first client’s public key to the received message. In other words, the second client will compute the applied public key to the private key application of the hashed messaged. If the result is the same as hash(m), then the message was not modified. However, if the hash has changed, then a modification must have occurred. Thus, our program double checks all messages to ensure the hash(m) matches between the first and second client. 

### How we acheived our security goals: 

Throughout the project, we identified several potential types of attacks our program was susceptible to, as well as ways to prevent those attacks. 

##### List of potential attacks and approaches taken to prevent the attack:  

Since Mallory does not have local access to our system, she can only access the program through the client or the server. To prevent her from accessing sensitive information by compromising the program, we implemented several approaches listed below. 

1. Attacks may occur at the addresses at which clients and the server are running.

To prevent a hacker from utilising server and client addresses to gain secret information, we placed extra protection on where those addresses can be accessed. 

2. Attackers may attempt to read, modify, inject, and/or block data sent over any network connection between a client and the server.

To prevent a hacker from reading, modifying, injecting, or blocking data over a network, we implemented multiple check functions to see whether or not malicious input was send.

3. Attacks may attempt to establish a connection with any client or the server, spoofing her network address to any possible value.

4. Attackers may implement a malicious client to attack either the server or other clients by sending specially crafted data.

5. Attackers may implement a malicious server and get clients to connect to it instead of the intended server, to attack clients by sending specially crafted data.

Furthermore, attackers may try to perform these actions any number of times, possibly simultaneously. In order to prevent simultaneous attacks, we plan to implement proper authorisation for every single client, as well as encrypted authentication in every single packet received by a client.

#### User interface

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

#### Testing plan

This is a very large piece of code on aggregate, so there are many things to test. To do this, both unit and integration testing are necessary.

- Validity of user agruments for client and server
- Boundary cases, such as sending the max length of the chat, sending a message to a user that doesn't exist, maximising the number of clients on the server etcetera. 
- Private versus public message visibility
- Whether the server works with multiple clients (same or different computers)
- The program handles users leaving correctly
- The program exits correctly when the server is closed (whether compromised or not)

Specific test attacks we tested: 
- Attackers sending messages on behalf of another user.
- Attackers modifying messages sent by other users
- Attackers finding out users’ passwords, private keys, or private messages (even if the server is compromised).
- Attackers using the client or server programs to achieve privilege escalation on the systems they are running on
- Attackers attempting to leak or corrupt data in the client or server programs
- Attackers crashing the client or server programs.

In the final hours of this assignment, we double that we intiailized memory correctly and that pointers were set to null after they were deallocated. (using valgrind and other methods). We checked for buffer overflows through arthimatic and chose specific types based on permissible inputs. We often check for incorrect inputs and exit( ) if so. We tested many boundary cases, including an attempted login with no users, an attempted login when there are already max users, repeated users names, and extreme/out of bounds/incorrect type inputs. 

