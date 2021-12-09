#ifndef _API_H_
#define _API_H_

#include <stdbool.h>

struct api_msg
{
	char* message;
	int length;
};

struct api_state
{
	int fd;
	//  logintoestand -1 is niet ingelogd, 0 is ingelogd
	//int fd, logintoestand, gebruikersnaamGROOTTE, wachtwoordGROOTTE;
	//char* gebruikersnaam;
	//char* wachtwoord;
	//char* invoer;
	
	/* TODO add required fields */
};


struct argument{
    int length;
    char* arg;
};


int api_recv(struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);


/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
