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

#define READ_SIZE 256
#define BUFFERGROOTTE 256
#define DATABANKGROOTTE 80

#define TRUE 1
#define FALSE 0

Login gl[DATABANKGROOTTE]; // gl: gebruikerslijst

//int ontbeestW = TRUE;
int ontbeestW = FALSE;
#define log(x) if(ontbeestW) { printf(x); printf("\n"); }

char* huidigeDatumEnTijd()
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
	char* momentOpname = asctime(tijdInformatie);
	
	//formaat: Tue Dec  7 07:30:37 2021
	for(int i = 0; i < 24; i++) { druk(&s, momentOpname[i]); }
	verkrijgWoord(&s, &jaar, 4);
	verkrijgWoord(&s, &maand, 1);
	verkrijgWoord(&s, &dag, 2);
	verkrijgWoord(&s, &tijd, 3);
	
	if(maand.buffer[0] == 'J') { druk(&maandteller, '1'); }
	else if(maand.buffer[0] == 'F') { druk(&maandteller, '2'); }
	else if(maand.buffer[0] == 'M' && maand.buffer[2] == 'r') { druk(&maandteller, '3'); }
	else if(maand.buffer[0] == 'A' && maand.buffer[1] == 'p') { druk(&maandteller, '3'); }
	else if(maand.buffer[0] == 'M' && maand.buffer[2] == 'y') { druk(&maandteller, '5'); }
	else if(maand.buffer[0] == 'J' && maand.buffer[2] == 'n') { druk(&maandteller, '6'); }
	else if(maand.buffer[0] == 'J' && maand.buffer[2] == 'l') { druk(&maandteller, '7'); }
	else if(maand.buffer[0] == 'A' && maand.buffer[1] == 'u') { druk(&maandteller, '8'); }
	else if(maand.buffer[0] == 'S') { druk(&maandteller, '9'); }
	else if(maand.buffer[0] == 'O') { druk(&maandteller, '1'); druk(&maandteller, '0'); }
	else if(maand.buffer[0] == 'N') { druk(&maandteller, '1'); druk(&maandteller, '1'); }
	else if(maand.buffer[0] == 'D') { druk(&maandteller, '1'); druk(&maandteller, '2'); }
	
	for(int i = 0; i < jaar.bladwijzer; i++)
		{ druk(&einddatum, jaar.buffer[i]); }
	druk(&einddatum, '-');
	for(int i = 0; i < maandteller.bladwijzer; i++)
		{ druk(&einddatum, maandteller.buffer[i]); }
	druk(&einddatum, '-');
	for(int i = 0; i < dag.bladwijzer; i++)
		{ druk(&einddatum, dag.buffer[i]); }
	druk(&einddatum, ' ');
	for(int i = 0; i < tijd.bladwijzer; i++)
		{ druk(&einddatum, tijd.buffer[i]); }
	
	// Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
	//~ verwijderString(&s);
	
	return verkrijgString(&einddatum);
}

void kopieerString(char* origineel, char* kopie, int grootte)
{
	//kopie = (char*) malloc(grootte*sizeof(char));
	for(int i = 0; i < grootte; i++) { kopie[i] = origineel[i]; }
}

struct worker_state
{
	struct api_state api;
	int eof;
	int server_fd;  /* server <-> worker bidirectional notification channel */
	int server_eof;
	
	int fd, logintoestand, gebruikersnaamGROOTTE, wachtwoordGROOTTE;
	char* gebruikersnaam;
	char* wachtwoord;
	char* invoer;
	/* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state)
{
	log("WORKER: static int handle_s2w_notification(struct worker_state *state)");
	log(" ");
	char bericht[READ_SIZE];
	FILE *fp = fopen("database", "r");
	fread(bericht, 1, READ_SIZE, fp);
	fclose(fp);

	//printf("Het bericht dat ik net gelezen heb: %s\n", bericht);
	send(state->api.fd, bericht, READ_SIZE, 0);
	return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state)
{
	log("WORKER: static int notify_workers(struct worker_state *state)");
	char buf = 0;
	ssize_t r;

	/* we only need to send something to notify the other workers,
    * data does not matter
    */
	r = write(state->server_fd, &buf, sizeof(buf));
	if (r < 0 && errno != EPIPE)
		{ perror("error: write of server_fd failed"); return -1; }
	return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *msg)
{
	log("WORKER: static int execute_request(struct worker_state *state, const struct api_msg *msg)");
	FILE *fp = fopen("database", "w");
	char* invoer = msg->message;

	String woord_0, woord_1, woord_2, bericht, tijdelijk;
	nieuweString(&woord_0, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&woord_1, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&woord_2, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&bericht, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&tijdelijk, 20); 	// Verstel de begingrootte naar twintig.
	
	for(int i = 0; ; i++)
		{ druk(&tijdelijk, invoer[i]); if(invoer[i] == '\0') { break; } }
	
	int woordenteller = woordenTeller(&tijdelijk);
	verkrijgWoord(&tijdelijk, &woord_0, 0);
	verkrijgWoord(&tijdelijk, &woord_1, 1);
	verkrijgWoord(&tijdelijk, &woord_2, 2);
	
	if((strcmp(verkrijgString(&woord_0), "/login") == 0 || strcmp(verkrijgString(&woord_0), "/aanmelden") == 0) && woordenteller >= 3)
	{
		if(woord_1.bladwijzer >= 3 && woord_2.bladwijzer >= 6)
		{
			//controleer of het inloggen werkt
			if(strcmp(state->gebruikersnaam, verkrijgString(&woord_1)) == 0 && strcmp(state->wachtwoord, verkrijgString(&woord_2)) == 0)
			{
				send(state->api.fd, "[server] Jij hebt jou aangemeld!", READ_SIZE, 0);
				state->logintoestand = 0;
			}
			else
			{
				send(state->api.fd, "[server] Inloggen mislukt.", READ_SIZE, 0);
			}
			return 0;
		}
		else
		{
			send(state->api.fd, "[server] Gebruik: /login [gebruikersnaam] [wachtwoord]\nvoorbeeld: /login willem test123", READ_SIZE, 0);
			return 0;
		}
	}
	else if((strcmp(verkrijgString(&woord_0), "/register") == 0 || strcmp(verkrijgString(&woord_0), "/registreer") == 0 || strcmp(verkrijgString(&woord_0), "/inschrijven") == 0) && woordenteller >= 3)
	{
		printf("Een lekker kopje thee!");
		if(woord_1.bladwijzer >= 3 && woord_2.bladwijzer >= 6)
		{
			kopieerString(verkrijgString(&woord_1), state->gebruikersnaam, woord_1.bladwijzer);
			kopieerString(verkrijgString(&woord_2), state->wachtwoord, woord_2.bladwijzer);
			state->gebruikersnaamGROOTTE = woord_1.bladwijzer;
			state->wachtwoordGROOTTE = woord_2.bladwijzer;
			
			send(state->api.fd, "[server] Jij hebt jou ingeschreven!", READ_SIZE, 0);
			return 0;
		}
		else
		{
			send(state->api.fd, "[server] Gebruik: /inschrijven [gebruikersnaam] [wachtwoord]\nvoorbeeld: /inschrijven willem test123", READ_SIZE, 0);
			return 0;
		}
	}
	
	if(state->logintoestand == -1)
	{
		send(state->api.fd, "[server] Jij bent nog niet aangemeld. Meld jou aan met: /aanmelden [naam] [wachtwoord]\n[server] Als jij nog niet bent ingeschreven, doe dat dan met: /inschrijven [naam] [wachtwoord]\n[server] Doe daarna /aanmelden [naam] [wachtwoord]", READ_SIZE, 0);
		return 0;
	}
	
	char *datumEnTijd = huidigeDatumEnTijd();
	for(int i = 0; i < 18; i++) { druk(&bericht, datumEnTijd[i]); }
	druk(&bericht, ' ');
	for(int i = 0; i < state->gebruikersnaamGROOTTE; i++)
		{ druk(&bericht, state->gebruikersnaam[i]); }
	druk(&bericht, ' ');
	for(int i = 0; ; i++)
		{ druk(&bericht, invoer[i]); if(invoer[i] == '\0') { break; } }
	
	fwrite(verkrijgString(&bericht), 1, READ_SIZE, fp);
	fclose(fp);
	notify_workers(state);
	
	verwijderString(&woord_0); 	// Verstel de begingrootte naar twintig.
	verwijderString(&woord_1); 	// Verstel de begingrootte naar twintig.
	verwijderString(&woord_2); 	// Verstel de begingrootte naar twintig.
	verwijderString(&bericht); 	// Verstel de begingrootte naar twintig.
	verwijderString(&tijdelijk); 	// Verstel de begingrootte naar twintig.
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
	log("WORKER: static int handle_client_request(struct worker_state *state)");
	assert(state);

	/* wait for incoming request, set eof if there are no more requests */
	r = api_recv(&state->api, &msg);
	if (r < 0) { return -1; }
	if (r == 0) { state->eof = 1; return 0; }

	/* execute request */
	if (execute_request(state, &msg) != 0) { success = 0; }

	/* clean up state associated with the message */
	api_recv_free(&msg);

	return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state)
{
	char buf[BUFFERGROOTTE];
	ssize_t r;
	log("WORKER: static int handle_s2w_read(struct worker_state *state)");
	/* notification from the server that the workers must notify their clients
	 * about new messages; these notifications are idempotent so the number
	 * does not actually matter, nor does the data sent over the pipe
	 */
	errno = 0;
	r = read(state->server_fd, buf, sizeof(buf));
	if (r < 0)  { perror("error: read server_fd failed"); return -1; }
	if (r == 0) { state->server_eof = 1; return 0; }
	
	/* notify our client */
	if (handle_s2w_notification(state) != 0) { return -1; }

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
	log("WORKER: static int handle_incoming(struct worker_state *state)");
	int fdmax, r, success = 1;
	fd_set readfds;

	assert(state);

	/* list file descriptors to wait for */
	FD_ZERO(&readfds);
	/* wake on incoming messages from client */
	FD_SET(state->api.fd, &readfds);
	/* wake on incoming server notifications */
	if (!state->server_eof) { FD_SET(state->server_fd, &readfds); }
	fdmax = max(state->api.fd, state->server_fd);

	/* wait for at least one to become ready */
	r = select(fdmax+1, &readfds, NULL, NULL, NULL);
	if (r < 0)
	{
		if (errno == EINTR) { return 0; }
		perror("error: select failed");
		return -1;
	}
	
	/* handle ready file descriptors */
	/* TODO once you implement encryption you may need to call ssl_has_data
	 * here due to buffering (see ssl-nonblock example)
	 */
	if (FD_ISSET(state->api.fd, &readfds))
		{ if (handle_client_request(state) != 0) { success = 0; } }
	if (FD_ISSET(state->server_fd, &readfds))
		{ if (handle_s2w_read(state) != 0) { success = 0; } }
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
	log("WORKER: static int worker_state_init(struct worker_state *state, int connfd, int server_fd)");
	/* initialize */
	memset(state, 0, sizeof(*state));
	state->server_fd = server_fd;
	
	state->logintoestand = -1;
	state->gebruikersnaam = (char*) malloc(BUFFERGROOTTE * sizeof(char));
	state->wachtwoord = (char*) malloc(BUFFERGROOTTE * sizeof(char));
	state->gebruikersnaamGROOTTE = 0;
	state->wachtwoordGROOTTE = 0;
	
	//state->gebruikersnaam = NULL;
	//state->wachtwoord = NULL;
	//state->invoer = NULL;
	
	//printf("Login toestand vlak na initialisatie: %i\n", state->logintoestand);
	
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
	log("WORKER: static void worker_state_free(struct worker_state *state)");
	/* TODO any additional worker state cleanup */
	
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
__attribute__((noreturn))
void worker_start(int connfd, int server_fd)
{
	/* Hier alles gelijkschakelen op nul (inloggegevens) */
	//Login gebruikerslijst[DATABANKGROOTTE];
	
	/*	char *gebruikersnaam;
	char *wachtwoord;
	int bestandsbeschrijver;
	int gebruikersnaamGROOTTE;
	int wachtwoordGROOTTE;*/
	
	for(int i = 0; i < DATABANKGROOTTE; i++)
	{
		gl[i].gebruikersnaam = NULL;
		gl[i].wachtwoord = NULL;
		gl[i].bestandsbeschrijver = -1;
		
		gl[i].gebruikersnaamGROOTTE = 0;
		gl[i].wachtwoordGROOTTE = 0;
	}
	
	log("WORKER: void worker_start(int connfd, int server_fd)");
	struct worker_state state;
	
	int success = 1;

	/* initialize worker state */
	if (worker_state_init(&state, connfd, server_fd) != 0) { goto cleanup; }
	/* TODO any additional worker initialization */

	/* handle for incoming requests */
	while (!state.eof)
		{ if (handle_incoming(&state) != 0) { success = 0; break; } }
	
	cleanup:
	/* cleanup worker */
	/* TODO any additional worker cleanup */
	worker_state_free(&state);
	
	exit(success ? 0 : 1);
}
