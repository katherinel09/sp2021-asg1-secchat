#ifndef _API_H_
#define _API_H_

#include <stdbool.h>

struct api_msg {
  char* message;
};

struct api_state {
  int fd;
  char* username;
  char* input;
  
  /* TODO add required fields */
};


struct argument{
    int length;
    char* data;
};


int api_recv(struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

int getInput(char* input);
bool checkInput(char* input);
bool checkBoundsValidity(char* input);
void clearStdin();
void getArgument(char* input, struct argument* argument, int argNumber);
int getArgumentLength(char* input, int argNumber);
int getStartPoint(char* input, int argNumber);
void argumentFree(struct argument* argument);
void printTime();


/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
