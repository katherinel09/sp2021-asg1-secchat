#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "string.h"
#include "inloggegevens.h"

#include "sqlite3.h"
#include <stdio.h>

#include <assert.h>
#include <stdio.h>

#include "ui.h"
#include "util.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#define DATABASE "users.db"

#define READ_SIZE 256
#define BUFFERGROOTTE 256
#define DATABANKGROOTTE 80

#define TRUE 1
#define FALSE 0

Login gl[DATABANKGROOTTE]; // gl: gebruikerslijst

/* METHODS FOR THE DATABASE :) */

/* Method to create a database of the users*/
int create_user_table()
{
	sqlite3 *db;
	int ressy = 0;
	ressy = sqlite3_open(DATABASE, &db);

	const char sql1[5000] = "CREATE TABLE PERSON("
							"USERNAME 		TEXT	NOT NULL, "
							"PASSWORD		TEXT    NOT NULL, "
							"STATUS         TEXT    NOT NULL, "
							"SIGNATURE      INT 	NOT NULL, "
							"PRIMARY KEY (USERNAME) );";

	ressy = sqlite3_exec(db, sql1, NULL, 0, NULL);
	sqlite3_close(db);
	return ressy;
}

// Method to create the documentation & list of fields (message table (sender, recipient, other important things))
int create_message_table()
{
	int ressy = 0;
	sqlite3 *db;
	ressy = sqlite3_open(DATABASE, &db);

	const char sql1[5000] = "CREATE TABLE MESSAGES("

							"RECIPIENT			TEXT	NOT NULL, "
							"SENDER				TEXT    NOT NULL, "
							"MESSAGE			TEXT    NOT NULL, "
							"CERTIFICATE        TEXT 	NOT NULL, "
							"PRIMARY KEY (CERTIFICATE) );";

	ressy = sqlite3_exec(db, sql1, NULL, 0, NULL);
	sqlite3_close(db);
	return ressy;
}

int create_account_slot(sqlite3 *db, const char *username, const char *password, int signature)
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

	int ressy;
	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);
	// querey_database_for_username(username, password);

	sqlite3_close(db);
	free(full_command);

	return ressy;
}


char *huidigeDatumEnTijd()
{
	time_t groveTijd;
	struct tm *tijdInformatie;
	time(&groveTijd);
	tijdInformatie = localtime(&groveTijd);

	String s, jaar, maand, maandteller, dag, einddatum, tijd;
	nieuweString(&s, 25);
	nieuweString(&jaar, 5);
	nieuweString(&maand, 4);
	nieuweString(&maandteller, 2);
	nieuweString(&dag, 2);
	nieuweString(&einddatum, 11);
	nieuweString(&tijd, 9);
	char *momentOpname = asctime(tijdInformatie);

	// formaat: Tue Dec  7 07:30:37 2021
	for (int i = 0; i < 24; i++)
	{
		druk(&s, momentOpname[i]);
	}
	verkrijgWoord(&s, &jaar, 4);
	verkrijgWoord(&s, &maand, 1);
	verkrijgWoord(&s, &dag, 2);
	verkrijgWoord(&s, &tijd, 3);

	if (maand.buffer[0] == 'J')
	{
		druk(&maandteller, '1');
	}
	else if (maand.buffer[0] == 'F')
	{
		druk(&maandteller, '2');
	}
	else if (maand.buffer[0] == 'M' && maand.buffer[2] == 'r')
	{
		druk(&maandteller, '3');
	}
	else if (maand.buffer[0] == 'A' && maand.buffer[1] == 'p')
	{
		druk(&maandteller, '3');
	}
	else if (maand.buffer[0] == 'M' && maand.buffer[2] == 'y')
	{
		druk(&maandteller, '5');
	}
	else if (maand.buffer[0] == 'J' && maand.buffer[2] == 'n')
	{
		druk(&maandteller, '6');
	}
	else if (maand.buffer[0] == 'J' && maand.buffer[2] == 'l')
	{
		druk(&maandteller, '7');
	}
	else if (maand.buffer[0] == 'A' && maand.buffer[1] == 'u')
	{
		druk(&maandteller, '8');
	}
	else if (maand.buffer[0] == 'S')
	{
		druk(&maandteller, '9');
	}
	else if (maand.buffer[0] == 'O')
	{
		druk(&maandteller, '1');
		druk(&maandteller, '0');
	}
	else if (maand.buffer[0] == 'N')
	{
		druk(&maandteller, '1');
		druk(&maandteller, '1');
	}
	else if (maand.buffer[0] == 'D')
	{
		druk(&maandteller, '1');
		druk(&maandteller, '2');
	}

	for (int i = 0; i < jaar.pointer; i++)
	{
		druk(&einddatum, jaar.buffer[i]);
	}
	druk(&einddatum, '-');
	for (int i = 0; i < maandteller.pointer; i++)
	{
		druk(&einddatum, maandteller.buffer[i]);
	}
	druk(&einddatum, '-');
	for (int i = 0; i < dag.pointer; i++)
	{
		druk(&einddatum, dag.buffer[i]);
	}
	druk(&einddatum, ' ');
	for (int i = 0; i < tijd.pointer; i++)
	{
		druk(&einddatum, tijd.buffer[i]);
	}

	return verkrijgString(&einddatum);
}

void kopieerString(char *origineel, char *kopie, int grootte)
{
	// kopie = (char*) malloc(grootte*sizeof(char));
	for (int i = 0; i < grootte; i++)
	{
		kopie[i] = origineel[i];
	}
}

struct worker_state
{
	struct api_state api;
	int eof;
	int server_fd; /* server <-> worker bidirectional notification channel */
	int server_eof;

	int fd, logintoestand, usernameSIZE, passwordSIZE;
	char *username;
	char *password;
	char *invoer;

	// Variables for database
	int public_key;
	int private_key;

	// Variables for OpenSSL
	SSL *ssl;
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state)
{
	// Create database upon starting up!
	sqlite3 *db;
	int ressy = sqlite3_open("users.db", &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3\n");
		exit(-1);
	}

	ressy = create_user_table(db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue creating the user table\n");
		exit(-1);
	}

	ressy = create_message_table(db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue creating the message table\n");
		exit(-1);
	}

	// char *message[READ_SIZE];
	// ressy = create_message(state->username, recipient, verkrijgString(&message));
	// FILE *fp = fopen("database", "r");
	// fread(message, 1, READ_SIZE, fp);
	//  const char *message = "message";

	// fclose(fp);

	// printf("Het message dat ik net gelezen heb: %s\n", message);
	sqlite3_close(db);
	//send(state->api.fd, message, READ_SIZE, 0);

	return ressy;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* Call this function to notify other workers through server */
__attribute__((unused)) static int notify_workers(struct worker_state *state)
{
	// Varbiables
	char buf = 0;
	ssize_t r;

	/*
	 * We only need to send something to notify the other workers, data does not matter
	 */
	r = write(state->server_fd, &buf, sizeof(buf));

	if (r < 0 && errno != EPIPE)
	{
		perror("error: write of server_fd failed");
		return -1;
	}
	return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *msg)
{
	// Create the database
	sqlite3 *db;

	int ressy = 0;
	ressy = sqlite3_open(DATABASE, &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3\n");
		exit(-1);
	}

	char *invoer = msg->message;

	String woord_0, woord_1, woord_2, message, tijdelijk;
	nieuweString(&woord_0, 20);	  // Verstel de begingrootte naar twintig.
	nieuweString(&woord_1, 20);	  // Verstel de begingrootte naar twintig.
	nieuweString(&woord_2, 20);	  // Verstel de begingrootte naar twintig.
	nieuweString(&message, 20);	  // Verstel de begingrootte naar twintig.
	nieuweString(&tijdelijk, 20); // Verstel de begingrootte naar twintig.

	for (int i = 0;; i++)
	{
		druk(&tijdelijk, invoer[i]);
		if (invoer[i] == '\0')
		{
			break;
		}
	}

	int woordenteller = woordenTeller(&tijdelijk);
	verkrijgWoord(&tijdelijk, &woord_0, 0);
	verkrijgWoord(&tijdelijk, &woord_1, 1);
	verkrijgWoord(&tijdelijk, &woord_2, 2);

	if ((strcmp(verkrijgString(&woord_0), "/login") == 0 || strcmp(verkrijgString(&woord_0), "/signup") == 0) && woordenteller >= 3)
	{
		if (woord_1.pointer >= 3 && woord_2.pointer >= 6)
		{
			// controleer of het inloggen werkt
			if (strcmp(state->username, verkrijgString(&woord_1)) == 0 && strcmp(state->password, verkrijgString(&woord_2)) == 0)
			{
				send(state->api.fd, "[server] Welcome! You logged in!", READ_SIZE, 0);
				state->logintoestand = 0;
			}
			else
			{
				send(state->api.fd, "[server] There was an error logging in :( ", READ_SIZE, 0);
			}
			return 0;
		}
		else
		{
			send(state->api.fd, "[server] How to login: /login [username] [password]\n", READ_SIZE, 0);
			return 0;
		}
	}
	else if ((strcmp(verkrijgString(&woord_0), "/register") == 0 || strcmp(verkrijgString(&woord_0), "/registreer") == 0 || strcmp(verkrijgString(&woord_0), "/register") == 0) && woordenteller >= 3)
	{
		
		if (woord_1.pointer >= 3 && woord_2.pointer >= 6)
		{
			// TO DO add the customer to the database
			// int signature = 0;
			// char *username = verkrijgString(&woord_1);
			// char *password = verkrijgString(&woord_2);

			// Call setup.sh

			// Write the public and priavte key to the path in the client directory

			// create_account_slot(*username, password, signature);

			kopieerString(verkrijgString(&woord_1), state->username, woord_1.pointer);
			kopieerString(verkrijgString(&woord_2), state->password, woord_2.pointer);
			state->usernameSIZE = woord_1.pointer;
			state->passwordSIZE = woord_2.pointer;

			send(state->api.fd, "[server] You are now registered. Please /login [username] [password] to continue.", READ_SIZE, 0);
			return 0;
		}
		else
		{
			send(state->api.fd, "[server] /register [username] [password]\n", READ_SIZE, 0);
			return 0;
		}
	}

	if (state->logintoestand == -1)
	{
		send(state->api.fd, "[server] You are not logged in yet. Log in with: /login [username] [password]\n[server] If you would like to register, please type the follow: /register [username] [password] and then login :)", READ_SIZE, 0);
		return 0;
	}

	char *datumEnTijd = huidigeDatumEnTijd();
	for (int i = 0; i < 18; i++)
	{
		druk(&message, datumEnTijd[i]);
	}
	druk(&message, ' ');
	for (int i = 0; i < state->usernameSIZE; i++)
	{
		druk(&message, state->username[i]);
	}
	druk(&message, ' ');
	for (int i = 0;; i++)
	{
		druk(&message, invoer[i]);
		if (invoer[i] == '\0')
		{
			break;
		}
	}

	//fwrite(verkrijgString(&message), 1, READ_SIZE, fp);
	// const char *recipient = "SERVER";
	// create_message(state->username, recipient, verkrijgString(&message));

	// Send the message with ssl
	// SSL_write(ssl, verkrijgString(&message), strlen(verkrijgString(&message))); /* encrypt & send message */

	//fclose(fp);
	notify_workers(state);

	verwijderString(&woord_0);	 // Verstel de begingrootte naar twintig.
	verwijderString(&woord_1);	 // Verstel de begingrootte naar twintig.
	verwijderString(&woord_2);	 // Verstel de begingrootte naar twintig.
	verwijderString(&message);	 // Verstel de begingrootte naar twintig.
	verwijderString(&tijdelijk); // Verstel de begingrootte naar twintig.
	/* TODO handle request and reply to client */
	return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state)
{
	struct api_msg msg;
	int r, success = 1;
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
		success = 0;
	}

	/* clean up state associated with the message */
	api_recv_free(&msg);

	return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state)
{
	char buf[BUFFERGROOTTE];
	ssize_t r;

	/* 
	 * Nnotification from the server that the workers must notify their clients
	 * about new messages; these notifications are idempotent so the number
	 * does not actually matter, nor does the data sent over the pipe
	 */


	errno = 0;
	r = read(state->server_fd, buf, sizeof(buf));
	if (r < 0)
	{
		perror("error: read server_fd failed");
		return -1;
	}
	if (r == 0)
	{
		state->server_eof = 1;
		return 0;
	}

	/* notify our client */
	if (handle_s2w_notification(state) != 0)
	{
		return -1;
	}

	return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state)
{
	int fdmax, r, success = 1;
	fd_set readfds;

	assert(state);

	/* list file descriptors to wait for */
	FD_ZERO(&readfds);
	/* wake on incoming messages from client */
	FD_SET(state->api.fd, &readfds);
	/* wake on incoming server notifications */
	if (!state->server_eof)
	{
		FD_SET(state->server_fd, &readfds);
	}

	fdmax = max(state->api.fd, state->server_fd);

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
	/* TODO once you implement encryption you may need to call ssl_has_data
	 * here due to buffering (see ssl-nonblock example)
	 */
	if (FD_ISSET(state->api.fd, &readfds))
	{
		if (handle_client_request(state) != 0)
		{
			success = 0;
		}
	}
	if (FD_ISSET(state->server_fd, &readfds))
	{
		if (handle_s2w_read(state) != 0)
		{
			success = 0;
		}
	}
	return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(struct worker_state *state, int connfd, int server_fd)
{
	/* initialize */
	memset(state, 0, sizeof(*state));
	state->server_fd = server_fd;

	state->logintoestand = -1;
	state->username = (char *)malloc(BUFFERGROOTTE * sizeof(char));
	state->password = (char *)malloc(BUFFERGROOTTE * sizeof(char));
	state->usernameSIZE = 0;
	state->passwordSIZE = 0;


	/* set up API state */
	api_state_init(&state->api, connfd);

	/* TODO any additional worker state initialization */
	

	return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(struct worker_state *state)
{
	/* clean up API state */
	api_state_free(&state->api);

	/* close file descriptors */
	close(state->server_fd);
	close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn)) void worker_start(int connfd, int server_fd)
{
	struct worker_state state;
	int success = 1;

	/* initialize worker state */
	if (worker_state_init(&state, connfd, server_fd) != 0)
	{
		goto cleanup;
	}
	/* TODO any additional worker initialization */

	/* handle for incoming requests */
	while (!state.eof)
	{
		if (handle_incoming(&state) != 0)
		{
			success = 0;
			break;
		}
	}

cleanup:
	/* cleanup worker */
	/* TODO any additional worker cleanup */
	worker_state_free(&state);

	exit(success ? 0 : 1);
}
