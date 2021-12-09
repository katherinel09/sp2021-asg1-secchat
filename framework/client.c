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

#define TRUE 1
#define FALSE 0
#define TEKEN_LIMIET 256

//int ontbeest = TRUE;
int ontbeest = FALSE;
#define log(x) if(ontbeest) { printf(x); printf("\n"); }

char* huidigeTijd()
{
	time_t groveTijd;
	struct tm *tijdInformatie;
	time(&groveTijd);
	tijdInformatie = localtime(&groveTijd);
	
	String s, tijd;
	nieuweString(&s, 25);
	nieuweString(&tijd, 9);
	char* momentOpname = asctime(tijdInformatie);
	
	for(int i = 0; i < 24; i++) { druk(&s, momentOpname[i]); }
	verkrijgWoord(&s, &tijd, 3);
	verwijderString(&s);
	
	return verkrijgString(&tijd);
}

struct client_state
{
	struct api_state api;
	int eof;
	struct ui_state ui;
	/* TODO client state variables go here */
};

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
	if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	/* create TCP socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("error: cannot allocate server socket");
		return -1;
	}

	/* connect to server */
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		perror("error: cannot connect to server");
		close(fd);
		return -1;
	}

	return fd;
}

static int client_process_command(struct client_state *state)
{
	/* TODO read and handle user command from stdin;
	* set state->eof if there is no more input (read returns zero)
	*/
	
	int blokAantal = 1;
	String invoer, woord_0, woord_1, woord_2, blokjes;
	nieuweString(&invoer, 20); 		// Verstel de begingrootte naar twintig.
	nieuweString(&woord_0, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&woord_1, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&woord_2, 20); 	// Verstel de begingrootte naar twintig.
	nieuweString(&blokjes, 20); 	// Verstel de begingrootte naar twintig.
	verkrijgInvoer(&invoer); 		// Leest de invoer van de gebruiker
	
	if(invoer.grootte > TEKEN_LIMIET)
	{
		for(int i = 0;;i++)
			{ if(invoer.grootte - i*TEKEN_LIMIET <= 0) { blokAantal = i; break; } }
		
		printf("\nOpmerking: hou er rekening mee dat als jouw bericht langer is dan 256 tekens, dat alleen het laatste gedeelte van jouw bericht aankomt bij de andere gebruikers.\n\n");
	}
	
	int woordenteller = woordenTeller(&invoer);
	//printf("Aantal woorden: %i\n", woordenteller);
	verkrijgWoord(&invoer, &woord_0, 0); // Achterhaal het eerste woord van de zin.
	verkrijgWoord(&invoer, &woord_1, 1); // Achterhaal het tweede woord van de zin.
	verkrijgWoord(&invoer, &woord_2, 2); // Achterhaal het derde woord van de zin.
	
	/*printf("\nArgument 0: %s\n", verkrijgString(&woord_0));
	printf("Argument 1: %s\n", verkrijgString(&woord_1));
	printf("Argument 2: %s\n", verkrijgString(&woord_2));*/
	
	if(invoer.grootte == 0) { state->eof = 1; }
	else { state->eof = 0; }
	
	if(strcmp(verkrijgString(&woord_0), "/exit") == 0)
		{ exit(0); }
	else if(strcmp(verkrijgString(&woord_0), "/login") == 0 || strcmp(verkrijgString(&woord_0), "/aanmelden") == 0)
	{
		if(woordenteller < 3)
		{
			printf("Gebruik: /aanmelden [gebruikersnaam] [wachtwoord]\nvb: /aanmelden willem test123\n");
		}
		else if(woordenteller >= 3 && woord_1.bladwijzer >= 3 && woord_2.bladwijzer >= 6)
		{
			send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0);
		}
		else
		{
			printf("Fout: een gebruikersnaam heeft minimaal drie tekens; een wachtwoord minimaal zes.\n");
		}
	}
	else if(strcmp(verkrijgString(&woord_0), "/register") == 0 || strcmp(verkrijgString(&woord_0), "/registreer") == 0 || strcmp(verkrijgString(&woord_0), "/inschrijven") == 0)
	{
		if(woordenteller < 3)
		{
			printf("Gebruik: /inschrijven [gebruikersnaam] [wachtwoord]\nvb: /inschrijven willem test123\n");
		}
		else if(woord_1.bladwijzer < 3)
		{
			printf("Fout: jouw gebruikersnaam moet minimaal drie tekens lang zijn.\n");
		}
		else if(woord_2.bladwijzer < 6)
		{
			printf("Fout: jouw wachtwoord moet minimaal zes tekens lang zijn.\n");
		}
		else 
		{ send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0); }
	}
	else if(strcmp(verkrijgString(&woord_0), "/users") == 0 || strcmp(verkrijgString(&woord_0), "/gebruikers") == 0)
	{
		printf("gebruikerscommando\n");
	}
	else if(verkrijgString(&woord_0)[0] == '@')
		{ printf("privébericht\n"); }
	else
	{
		if(blokAantal > 1)
		{
			for(int i = 0; i < blokAantal; i++)
			{
				sleep(1);
				geefBlok(&invoer, &blokjes, TEKEN_LIMIET, i);
				//printf(verkrijgString(&blokjes));
				if(blokjes.grootte > TEKEN_LIMIET) { printf("FOUT!!!"); exit(1); }
				send(state->api.fd, verkrijgString(&blokjes), blokjes.grootte, 0);
			}
		}
		else { send(state->api.fd, verkrijgString(&invoer), invoer.grootte, 0); }
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

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
 /* Wordt altijd door handle_server_request() aangeroepen. */
static int execute_request(struct client_state *state, const struct api_msg *msg)
{
	log("CLIENT: static int execute_request(struct client_state *state, const struct api_msg *msg)");
	/* TODO handle request and reply to client */
	
	return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
 /* Wordt altijd aangeroepen nadat de klant een bericht naar de server heeft verstuurd*/
static int handle_server_request(struct client_state *state)
{
	struct api_msg msg;
	int r, success = 1;
	log("CLIENT: static int handle_server_request(struct client_state *state)");
	assert(state);

	/* wait for incoming request, set eof if there are no more requests */
	r = api_recv(&state->api, &msg);
	if (r < 0) 	{ return -1; }
	if (r == 0) { state->eof = 1; return 0; }
	
	//printf("Verzoek: %s\n", msg.message);
	
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
/* Deze functie wordt na elk commando aangeroepen */
static int handle_incoming(struct client_state *state)
{
	int fdmax, r;
	fd_set readfds;
	log("CLIENT: static int handle_incoming(struct client_state *state)");
	assert(state);

	/* TODO if we have work queued up, this might be a good time to do it */

	/* TODO ask user for input if needed */

	/* list file descriptors to wait for */
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	FD_SET(state->api.fd, &readfds);
	fdmax = state->api.fd;

	/* wait for at least one to become ready */
	r = select(fdmax+1, &readfds, NULL, NULL, NULL);
	if (r < 0) {
		if (errno == EINTR) { return 0; }
		perror("error: select failed");
		return -1;
		}

	/* handle ready file descriptors */
	if (FD_ISSET(STDIN_FILENO, &readfds))
		{ return client_process_command(state); }
	/* TODO once you implement encryption you may need to call ssl_has_data
	 * here due to buffering (see ssl-nonblock example)
	 */
	if (FD_ISSET(state->api.fd, &readfds))
		{ return handle_server_request(state); }
	return 0;
}

static int client_state_init(struct client_state *state) {
	/* clear state, invalidate file descriptors */
	memset(state, 0, sizeof(*state));

	/* initialize UI */
	ui_state_init(&state->ui);

	/* TODO any additional client state initialization */

	return 0;
}

static void client_state_free(struct client_state *state) {

	/* TODO any additional client state cleanup */

	/* cleanup API state */
	api_state_free(&state->api);

	/* cleanup UI state */
	ui_state_free(&state->ui);
}

static void usage(void) {
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
	if (argc != 3) usage();
	if (parse_port(argv[2], &port) != 0) usage();

	/* preparations */
	client_state_init(&state);

	/* connect to server */
	fd = client_connect(&state, argv[1], port);
	if (fd < 0) { return 1; }

	/* initialize API */
	api_state_init(&state.api, fd);

	/* TODO any additional client initialization */

	/* client things */
	while (!state.eof && handle_incoming(&state) == 0);

	/* clean up */
	/* TODO any additional client cleanup */
	client_state_free(&state);
	close(fd);

	return 0;
}

/*
 * 
 * ############## Werkwijze ############## 
 * 
 * 1. Na elke client_process_command() wordt handle_incoming() aangeroepen, ongeacht het commando.
 * 2. Na berichtversturing wordt handle_server_request() aangeroepen.
 * 3. Vanuit hier wordt execute_request() altijd aangeroepen.
 * 4. Dan opnieuw handle_incoming()
 * 
 * */
