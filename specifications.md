Functional specifications: 

- The user can register a new account by supplying a username and a password.
- Duplicate usernames are not allowed application prohibits registration of a user with a previously registered username.
- The user can only login if one knows the password
- The user can exit. This logs out from the server and terminates the client program.
- When the client starts, displays all public messages previously sent are displayed by anyone, and all private messages received and sent by the current user, in chronological order from old to new.
- The user can send a public message to all users and a private message to a specific user
- Each message is shown with a timestamp, the user who sent it, and for private messages also the recipient.
- The client provides a list of logged in users on request.

Nonfunctional requirements: 
- All permanent state is stored in a SQLite database on the server side named users.db, located directly within the application’s root directory
- The client must retrieve this state from the server when needed. 
- Both the server and the client may use the disk to store cryptographic keys in the directory named serverkeys or clientkeys respectively
- The programs may not access each other’s keys directories. 
- The programs may invoke the trusted third party (a script), which can access the ttpkeys directory. Nothing else may be stored on disk by either program. 
- Restarting the server or any of the clients should not result in any loss of data other than the need to re-establish connections.
- Network connections are only set up by the clients, and only connect to the server. There are no direct connections between clients.
