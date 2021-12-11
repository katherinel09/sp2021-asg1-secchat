#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "string.h"

#include <sqlite3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define TRUE 1
#define FALSE 0
#define TEKEN_LIMIET 256

/* METHODS FOR CONNECTING THE CLIENT TO THE DATABASE */

/* A method to create a new entry for a user in the users.db database :) */
int create_account_slot(const char *username, const char *password, int signature)
{

	// Add them to the database
	char const *initial2 = "INSERT OR IGNORE INTO PERSON (USERNAME, PASSWORD, STATUS, SIGNATURE) VALUES('";
	char const *rest = "', 'ONLINE', '";
	char const *formatting = "', '";
	char const *formatting2 = "');";

	char sigINT[100];
	sprintf(sigINT, "%d", signature);

	char *full_command;
	full_command = malloc(500 + strlen(initial2) + strlen(username) + strlen(username) + strlen(password) + strlen(rest) + 1 + 4);
	strcat(full_command, initial2);
	strcat(full_command, username);
	strcat(full_command, formatting);
	strcat(full_command, password);
	strcat(full_command, rest);
	strcat(full_command, sigINT);
	strcat(full_command, formatting2);

	sqlite3 *db;
	int ressy;
	ressy = sqlite3_open("users.db", &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3 database\n");
		exit(-1);
	}

	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3\n");
		exit(-1);
	}

	sqlite3_close(db);
	free(full_command);

	return ressy;
}

// Method to create a new user message in the log
int create_mess_for_database(sqlite3 *db, const char *username, const char *recipient, const char *message)
{

	// Otherwise, add them to the database
	char const *initial2 = "INSERT INTO MESSAGES (RECIPIENT, SENDER, MESSAGE) VALUES('";
	char const *rest = "', '";

	char const *formatting2 = ");";

	char *full_command;
	full_command = malloc(500 + strlen(initial2) + strlen(username) + strlen(recipient) + strlen(message) + 2 * strlen(rest) + 1 + 4);
	strcat(full_command, initial2);
	strcat(full_command, recipient);
	strcat(full_command, rest);
	strcat(full_command, username);
	strcat(full_command, rest);
	strcat(full_command, message);
	strcat(full_command, rest);
	strcat(full_command, formatting2);

	int ressy;
	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);
	sqlite3_close(db);
	free(full_command);

	return ressy;
}

/* A method to generate a certificate for the client */
int gen_certificates()
{

	/* initialize SSL */
	con_ssl = InitServerCTX();
	LoadCertificates(con_ssl, "/clientkey/username/public_key.pem", "/clientkey/username/private_key.pem"); /* load certs */

	// SSL_write(ssl, input, strlen(input)); /* encrypt & send message */

	return 0;
}

struct client_state
{
	struct api_state api;
	int eof;
	struct ui_state ui;

	/* TODO client state variables go here */
	char *username = "katherinelasonde";
	int status = 0; // 0 => user is logged in ; 1 => user is not logged in

	SSL *ssl;
	// SSL_CTX *c;
};

char *huidigeTijd()
{
	time_t groveTijd;
	struct tm *tijdInformatie;
	time(&groveTijd);
	tijdInformatie = localtime(&groveTijd);

	String s, tijd;
	nieuweString(&s, 25);
	nieuweString(&tijd, 9);
	char *momentOpname = asctime(tijdInformatie);

	for (int i = 0; i < 24; i++)
	{
		druk(&s, momentOpname[i]);
	}
	verkrijgWoord(&s, &tijd, 3);
	verwijderString(&s);

	return verkrijgString(&tijd);
}

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state, const char *hostname, uint16_t port)
{
	int fd;
	struct sockaddr_in addr;

	assert(state);
	assert(hostname);

	/* look up hostname */
	if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0)
		return -1;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	/* create TCP socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
	{
		perror("error: cannot allocate server socket");
		return -1;
	}

	/* connect to server */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		perror("error: cannot connect to server");
		close(fd);
		return -1;
	}

	printf("Hi! Welcome to Kat's secure chatting server to chat with your friends. Please type /login [username] [password] or /register [username] [password]\n");
	printf(" For reference, this is the UI for the command line chat server :)\n

			registercommand = /register [username] [password]\n
			logincommand = /login [username] [password] \n
			privmsgcommand  = @ [sender_username] [message]\n
			pubmsgcommand = message\n
			registercommand = /register [username] [password]\n
			list all users = /users\n	
			exitcommand = /exit (exitcommand) \n");


	return fd;
}

static int client_process_command(struct client_state *state)
{
	/* TODO read and handle user command from stdin;
	 * set state->eof if there is no more input (read returns zero)
	 */

	int blokAantal = 1;
	String invoer, woord_0, woord_1, woord_2, blokjes;
	nieuweString(&invoer, 20);
	nieuweString(&woord_0, 20);
	nieuweString(&woord_1, 20);
	nieuweString(&woord_2, 20);
	nieuweString(&blokjes, 20);
	verkrijgInvoer(&invoer);

	if (invoer.grootte > TEKEN_LIMIET)
	{
		for (int i = 0;; i++)
		{
			if (invoer.grootte - i * TEKEN_LIMIET <= 0)
			{
				blokAantal = i;
				break;
			}
		}

		printf("if your message is longer than 256 characters, only the last part of your message will reach the other users.\n\n");
	}

	int woordenteller = woordenTeller(&invoer);
	verkrijgWoord(&invoer, &woord_0, 0);
	verkrijgWoord(&invoer, &woord_1, 1);
	verkrijgWoord(&invoer, &woord_2, 2);

	char *username = verkrijgString(&woord_1);
	char *password = verkrijgString(&woord_2);

	if (invoer.grootte == 0)
	{
		state->eof = 1;
	}
	else
	{
		state->eof = 0;
	}

	if (strcmp(verkrijgString(&woord_0), "/exit") == 0)
	{
		exit(0);
	}
	else if (strcmp(verkrijgString(&woord_0), "/login") == 0) == 0)
		{
			if (woordenteller < 3)
			{
				printf("Try: /login [username] [password]\n");
			}
			else if (woordenteller >= 3 && woord_1.pointer >= 3 && woord_2.pointer >= 6)
			{
				send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0);
			}
			else
			{
				printf("Error: a username should have at least three characters; a password has at least six.\n");
			}
		}
	else if (strcmp(verkrijgString(&woord_0), "/register") == 0 || strcmp(verkrijgString(&woord_0)) == 0)
	{
		if (woordenteller < 3)
		{
			printf("Username: /login [username] [password]\n");
		}
		else if (woord_1.pointer < 3)
		{
			printf("Error: Your username must be at least three characters long..\n");
		}
		else if (woord_2.pointer < 6)
		{
			printf("Error: Your password must be at least six characters long.\n");
		}
		else
		{
			int ressy = check_for_double_username(woordenteller);
			if (ressy = -1)
			{
				printf("Sorry, that user name is already taken! ")
			}
			else
			{
				// add user to the database
				create_account_slot(username, password, 1234);

				send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0);
			}
		}
	}
	else if (strcmp(verkrijgString(&woord_0), "/users") == 0) == 0)
		{
			// Check that the user is logged in
			if (state->status != 0)
			{
				sprintf("Please log in to see a list of users.");
				exit(0);
			}

			// Print all of the users in the database
			print_all_users_in_database();
		}
	else if (verkrijgString(&woord_0)[0] == '@')
	{
		printf("privébericht\n");
	}
	// sending a public message
	else if (verkrijgString(&woord_0)[0] == 'message')
	{
		// To send a public message, encrypt with your public key
		unsigned char *inbuf, *outbuf;
		ssize_t inlen, outlen;

		// Based on the example code in the OpenSSL library rsa-encrypt.c
		char *pathToKey = "/clientkeys/public/channelkey/"; // Use a public key that everyone in the channel has access to a private key to match :)
		char *full_path = malloc(500);
		strcat(full_path, pathToKey);

		FILE *keyfile = fopen(pathToKey, "r");
		RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
		fclose(keyfile);

		/* read plaintext from stdin */
		inbuf = malloc(RSA_size(key));
		inlen = read(0, inbuf, RSA_size(key));

		/* plaintext size must fit in key size, including padding */
		if (inlen > RSA_size(key) - 42)
		{
			return 1;
		}

		/* perform decryption from inbuf to outbuf */
		outbuf = malloc(RSA_size(key));
		outlen = RSA_public_encrypt(inlen, inbuf, outbuf, key, RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */

		/* write ciphertext to stdout */
		write(1, outbuf, outlen);

		RSA_free(key);

		ssl_block_write(state->ssl, state->api.fd, outbuf, outlen);
		return 0;
	}
	// Method to send a private message
	else if (verkrijgString(&woord_0)[0] == '@')
	{
		char *receiver_username = verkrijgString(&woord_1);
		char *message = verkrijgString(&woord_2);

		// To send a private message, encrypt with THEIR private key
		unsigned char *inbuf, *outbuf;
		ssize_t inlen, outlen;

		// Based on the example code in the OpenSSL library rsa-encrypt.c
		char *pathToKey = "/clientkeys/private/";
		char *full_path = malloc(500);
		strcat(full_path, pathToKey);
		strcat(full_path, receiver_username);

		FILE *keyfile = fopen(pathToKey, "r");
		RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
		fclose(keyfile);

		/* read plaintext from stdin */
		inbuf = malloc(RSA_size(key));
		inlen = read(0, inbuf, RSA_size(key));

		/* plaintext size must fit in key size, including padding */
		if (inlen > RSA_size(key) - 42)
		{
			return 1;
		}

		/* perform decryption from inbuf to outbuf */
		outbuf = malloc(message);
		outlen = RSA_public_encrypt(inlen, inbuf, message, key, RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */

		/* write ciphertext to a single user  */
		ssl_block_write(state->ssl, state->api.fd, outbuf, outlen);

		// NOW, compute the signature!
		// generate the signature using the OpenSSL commandline
		char *path_to_sign = malloc(100);
		char *path = "./setup.sh signature ";

		char *full_dir = malloc(500);
		char *dir = " ./clientkeys/privatekeys/";
		strcat(full_dir, dir);
		strcar(full_dir, username);
		char *space = " ";
		strcar(full_dir, space);
		strcar(full_dir, message);

		// put all of the pieces together :)
		strcat(path_to_sign, path);
		strcat(path_to_sign, full_dir);
		// Call the shell script to generate the functions
		system(path_to_sign);

		RSA_free(key);
		free(outbuf);
		free(inbuf);
		free(path_to_sign);

		return 0;
	}
	else if (verkrijgString(&woord_0)[0] == '/exit')
	{
		printf("Thank you so much for using the secure chat server today!! Thank you for logging out. ")
			exit(1);
	}

	else
	{
		if (blokAantal > 1)
		{
			for (int i = 0; i < blokAantal; i++)
			{
				sleep(1);
				geefBlok(&invoer, &blokjes, TEKEN_LIMIET, i);

				if (blokjes.grootte > TEKEN_LIMIET)
				{
					exit(1);
				}
				send(state->api.fd, verkrijgString(&blokjes), blokjes.grootte, 0);
			}
		}
		else
		{
			send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0);
		}
	}

	/* Geheugenadressen opschonen */
	verwijderString(&invoer);
	verwijderString(&woord_0);
	verwijderString(&woord_1);
	verwijderString(&woord_2);
	verwijderString(&blokjes);
	return 0;

	/* Opmerking: persoonlijk vind ik het makkelijker om mijn eigen functies en variabelen Nederlandse namen te geven, zodat het makkelijker voor mij is om te onderscheiden tussen wat ik zelf heb geschreven en wat door anderen is geschreven.*/
}

// Based on the OpenSSL sample code from rsa-decrypt
int decrypt_a_message(char *username_of_sender, char *message)
{
	// To decrypt a private message, encrypt with client private key
	unsigned char *inbuf, *outbuf;
	ssize_t inlen, outlen;

	// Based on the example code in the OpenSSL library rsa-decrypt.c
	char *pathToKey = "/clientkeys/private/";
	char *full_path = malloc(500);
	strcat(full_path, pathToKey);
	strcat(full_path, username_of_sender);

	/* read key from argv[1] */
	FILE *keyfile = fopen(pathToKey, "r");
	RSA *key = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
	fclose(keyfile);

	/* read ciphertext from stdin */
	inbuf = malloc(RSA_size(key));
	inlen = read(0, inbuf, RSA_size(key));

	/* ciphertext size must match key size */
	if (inlen != RSA_size(key))
	{
		return 1;
	}

	/* perform decryption from inbuf to outbuf */
	outbuf = malloc(RSA_size(key));

	/* random padding, needs 42 bytes */
	outlen = RSA_private_decrypt(sizeof(message), message, outbuf, key, RSA_PKCS1_OAEP_PADDING);

	/* write plaintext to stdout */
	write(1, outbuf, outlen);

	RSA_free(key);

	// NOW VERIFY THE SIGNATURE USING THE COMMAND LINE OPEN SSL !
	// generate the signature using the OpenSSL commandline
	char *path_to_sign = malloc(100);
	char *path = "./setup.sh signature ";

	char *full_dir = malloc(500);
	char *dir = " ./clientkeys/privatekeys/";
	strcat(full_dir, dir);
	strcar(full_dir, username_of_sender);
	char *space = " ";
	strcar(full_dir, space);
	strcar(full_dir, message);

	// put all of the pieces together :)
	strcat(path_to_sign, path);
	strcat(path_to_sign, full_dir);
	// Call the shell script to generate the functions
	system(path_to_sign);

	RSA_free(key);
	free(outbuf);
	free(inbuf);
	free(path_to_sign);

	return 0;
}

void print_all_users_in_database()
{
	char *full_command;
	full_command = malloc(1000);

	strcat(full_command, "SELECT USERNAME FROM PERSONS\n users = {name[0] for USERNAMES in users.fetchall() \n print(users)} ");

	sqlite3 *db;
	int ressy;
	ressy = sqlite3_open("users.db", &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3 database\n");
		exit(-1);
	}

	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);
	// querey_database_for_username(username, password);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3\n");
		exit(-1);
	}

	sqlite3_close(db);
	free(full_command);
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
/* Wordt altijd door handle_server_request() aangeroepen. */
static int execute_request(struct client_state *state, const struct api_msg *msg)
{
	return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state)
{
	struct api_msg msg;
	int r, success = 1;
	log("CLIENT: static int handle_server_request(struct client_state *state)");
	assert(state);

	/* wait for incoming request, set eof if there are no more requests */
	r = api_recv(&state->api, &msg);
	if (r < 0)
	{
		return -1;
	}
	if (r == 0)
	{
		state->eof = 1;
		return 0;
	}

	/* execute request */
	if (execute_request(state, &msg) != 0)
	{
		log("if (execute_request(state, &msg) != 0)");
		success = 0;
	}

	/* clean up state associated with the message */
	api_recv_free(&msg);

	return success ? 0 : -1;
}

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 */
static int handle_incoming(struct client_state *state)
{
	int fdmax, r;
	fd_set readfds;
	assert(state);

	/* if we have work queued up, this might be a good time to do it */

	/* ask user for input if needed */
	print("Here is the list of commands: \n
		  For reference,
		  this is the UI for the command line chat server:)\n

		registercommand = / register[username][password]\n
								logincommand = / login[username][password] \n
													 privmsgcommand = @[ username ][message]\n
												   pubmsgcommand = message\n
													   registercommand = / register[username][password]\n
																			   list all users = / users\n
																									  exitcommand = / exit(exitcommand) \n "
		);

	/* list file descriptors to wait for */
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	FD_SET(state->api.fd, &readfds);
	fdmax = state->api.fd;

	/* wait for at least one to become ready */
	r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
	if (r < 0)
	{
		if (errno == EINTR)
		{
			return 0;
		}
		perror("error: select failed");
		return -1;
	}

	/* handle ready file descriptors */
	if (FD_ISSET(STDIN_FILENO, &readfds))
	{
		return client_process_command(state);
	}

	// int ssl_has_data(SSL *ssl) => verify that at least one byte of user data is available
	/* return value => 0: nothing available => 1: data, end-of-file, or error available */
	if (ssl_has_data(state->ssl))
	{
		return handle_server_request(state);
	}

	if (FD_ISSET(state->api.fd, &readfds))
	{
		return handle_server_request(state);
	}
	return 0;
}

static int client_state_init(struct client_state *state)
{
	/* clear state, invalidate file descriptors */
	memset(state, 0, sizeof(*state));

	/* initialize UI */
	ui_state_init(&state->ui);

	/* TODO any additional client state initialization */
	printf("Hello! ");
	printf(state->username);
	printf("\nPlease type /users to see a list of users in the database. If you would like to send a message to a user, type /privatemessage [their user name] [your message]\n");
	printf("If you would like to send a public message (to all users), type /publicmessage [your message]\n");
	return 0;
}

/* A function to check for double user names */
int check_for_double_username(char *username)
{
	sqlite3 *db;
	sqlite3_open("users.db", &db);

	char *initial = "SELECT USERNAME FROM PERSONS\n
		all_usernames = {PERSON[0] for USERNAME in db.fetchall()}\n
		if usernameinput in names:
	{
		return 1
	}
	else { return -1 }
	";

		char *full_command;
	full_command = malloc(1000);
	strcat(full_command, initial);

	int ressy;
	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);

	free(full_command);

	return ressy;
}

static void client_state_free(struct client_state *state)
{
	/* cleanup API state */
	api_state_free(&state->api);

	/* cleanup UI state */
	ui_state_free(&state->ui);
}

static void usage(void)
{
	printf("usage:\n");
	printf("  client host port\n");
	exit(1);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int fd;
	uint16_t port;
	struct client_state state;

	/* check arguments */
	if (argc != 3)
		usage();
	if (parse_port(argv[2], &port) != 0)
		usage();

	/* preparations */
	client_state_init(&state);

	/* connect to server */
	fd = client_connect(&state, argv[1], port);
	if (fd < 0)
	{
		return 1;
	}

	/* initialize API */
	api_state_init(&state.api, fd);

	/* client things */
	while (!state.eof && handle_incoming(&state) == 0)
		;

	/* clean up */
	client_state_free(&state);
	close(fd);

	return 0;
}

/* This example verifies an RSA signature for the message specified in the
 * second argument, using a RSA private key loaded from the file specified
 * by the first argument. The signature is provided through to stdin.
 *
 * Example to sign "Hello world" with key in file keypriv.pem,
 * and then verify signature with key in file keypub.pem:
 * ./rsa-sign keypriv.pem 'Hello world' | ./rsa-verify keypub.pem 'Hello world'
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int rsa_validate_signature(int argc, char **argv)
{
	int r;
	unsigned char *sig;
	unsigned siglen;
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_PKEY *evpKey = EVP_PKEY_new();

	/* read key from argv[1] */
	FILE *keyfile = fopen(argv[1], "r");
	RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
	fclose(keyfile);

	/* make EVP key using RSA key (RSA key will be automatically freed) */
	EVP_PKEY_assign_RSA(evpKey, key);

	/* read signature from stdin into sig */
	sig = malloc(EVP_PKEY_size(evpKey));
	siglen = read(0, sig, EVP_PKEY_size(evpKey));

	/* verify signature */
	EVP_VerifyInit(ctx, EVP_sha1());
	EVP_VerifyUpdate(ctx, argv[2], strlen(argv[2]));
	r = EVP_VerifyFinal(ctx, sig, siglen, evpKey);
	printf("signature is %s\n", (r == 1) ? "good" : "bad");

	EVP_PKEY_free(evpKey);
	EVP_MD_CTX_free(ctx);
	return 0;
}
