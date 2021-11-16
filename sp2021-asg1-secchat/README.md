# Security and Privacy README.md 
# sp2021-asg1-seccaht
### Program Description
SP2021-ASF1-SECCHAT is a standalone program that consists of a 'chat server' which maintains a chat states which create conversation, as well as a 'chat client' to allow users to communicate with the server. The goal of the program is to host a secure chat application in C that runs on Linux. The states that the server will include but not limit to users sending and receiving private and public messages. 

The state of this README currently reflects the functionality as November 16 for the first deadline of assignment one. The goal of this deadline is to build a secure chat application between a client and a server. Specifically, we implemented the functionality of sending messages, receiving messages, parsing commands, and showing messages between two servers. 

# To compile: 
Run 'make all' in the root directory. 

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

### Data flow through server.c

First, the user must start the server. The program server is run from the application’s root directory with a single argument, port_num, which is the TCP port number for the server to listen on.

```bash
$ ./server port_num &
```

In the main funtion, a reference for the port is defined as well as a new server_state struct. The arguments are then parsed to ensure that no malicious arguments may be inputted by an attacker and affect out system. 

Then, we initialize the state of the server using the reference to the above struct. We clear the previous memory and begin to initialize the correct sockets to the specified ports according to the system requirements. 

Now, the server is able to register SIGCHLD signals and will accept them, while SIGPIPE signals are completely ignored. The server then is called to make the connections between sockets and ports that were earlier initialized, thus allowing the server to start listening for incoming client conenctions. 

While the server is waiting, it will continuously check for new client connections through the children_check method. The server will infinitely check if a child has finished or not, and if they did finish, state how the child died. The server then parses the messages of all the existing children, by allocating read and write file descriptor references. The program will then inifintely handle incoming notifcations and send outgoing notifications to the client until terminated. 

When the server is no longer needed, allocated memory is freed and the program exits a return code of 0. 

### Methods in client.c
```c=
static int client_connect(struct client_state *state, const char *hostname, uint16_t port) 
static int client_process_command(struct client_state *state) 
execute_request( struct client_state *state, const struct api_msg *msg) 
static int handle_server_request(struct client_state *state)
static int handle_incoming(struct client_state *state)
static int client_state_init(struct client_state *state)
static void client_state_free(struct client_state *state)
```

### Data flow through client.c

The user runs the client side with the below parameters, at the same port as the server.

```bash
$ ./client localhost port_num
```

First, we disable buffering of the output to ensure that hackers are unable to mine for private data. Once this is done through the setvbuf function, we parse the number of inputted arguments for correctness, as well as ensuring that there are no possibilities of malicious inputs. 

Once the inputs are parsed, we initialize the client state. To do this, we clear the previous memory in the space we wish to store the reference, and then we create a new UI reference.  Once the client is intialized, the client is connected to the server. Here, we check that the state and the hostname are the anticipated values and a hacker is not attempting to input malicious parameters. Then, we look up the hostname, create the TCP socket, and connect to the server. If any of the previous steps fail, we return an exit code of -1. 

Once the client has successfully connected, we initialized the associated APIs such that we are reference the messages and the states of the API. Finally, the client is able to send and receive messages from the server as long as both parties are working. When the client exits the server properly, allocated memory is freed and the program returns an exit code of 0. 

### How the server and the client communicate
Currently, the server is first set up, then clients are able to join the server.  

### Functional requirements implemented within the client and server

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

The server makes multiple workers that handle incoming connections from an external client. Via a socket the worker and the client can send data. Every worker is connected to the server by a different bidrectional socket. By reading or writing to this bidrectional socket either the worker or the server can notify eachother that an action is to be taken. In this way the client can communicate with the server and the server can communicate with all the connected clients.

#### Possible types of interactions between server and clients, 
Interactions between the server and clients are mostly reading and writing via a socket.

#### TODO: the data layout of all possible types of packets sent

#### TODO: a description of any cryptography you apply. 

### How we acheived our security goals: 

Throughout the project, we identified several potential types of attacks are program was susceptible to, as well as ways to prevent those attacks. 

##### List of potential attacks and approaches taken to prevent the attack:  

Since a hacker does not have local access to our system, she can only access the program through the client or server. To prevent her from accessing sensitive information by compromising the program, we implemented several approaches defined below. 

1. Attacks may occur at the addresses at which clients and the server are running 

To prevent a hacker from utilizing server and client addresses to gain secret information, we placed extra protection on where those addresses can be accessed. 

2. Attackers may attempt to read, modify, inject, and/or block data sent over any network connection between a client and the server

To prevent a hacker from reading, modifying, injecting, or blocking data over a network, we implemented multiple check functions to see whether or not malicious input was send.

3. Attacks may attempt to establish a connection with any client or the server, spoofing her network address to any possible value.

4. Attackers may implement a malicious client to attack either the server or other clients by sending specially crafted data.

5. Attackers may implement a malicious server and get clients to connect to it instead of the intended server, to attack clients by sending specially crafted data.

Furthermore, attackers may try to perform these actions any number of times, possibly simultaneously. In order to prevent simultaneous attacks, we

#### Possible threats we did not prevent:

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
