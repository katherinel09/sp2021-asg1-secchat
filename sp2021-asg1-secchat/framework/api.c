#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <time.h>

#include "api.h"

#define BLANKSPACE 32
#define TAB 9
#define NEWLINE 10


/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {

  assert(state);
  assert(msg);

  msg->message = calloc(100,1);
  int length = recv(state->fd, msg->message,100,0);
  //printf("message: %s", msg->message);

  if(length == -1 || length == 0) {
    return length;
  }
  else {
    return 1;
  }
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);
  free(msg->message);

  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

  assert(state);

  free(state->input);

  /* TODO clean up API state */
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  state->input = calloc(100,1);

}

bool checkInput(char* input) {
    if(input[0] == NEWLINE) {
        return false;
    }
    else {
        bool valid = checkBoundsValidity(input);
        if(!valid){
            printf("Input needs to be between 1 and 99 characters try again\n");
            clearStdin();
            return false;
        }
        else {
            return true;
        }
    }
}

bool checkBoundsValidity(char* input) {
    for(int i = 0; i < 100; i++) {
        if(input[i] == NEWLINE) {
            return true;
        }
    }
    return false;
}

void clearStdin() {
    int c = getchar(); 
    while (c != NEWLINE) c = getchar();
}

void getArgument(char* input, struct argument* argument, int argNumber) {
    int length = getArgumentLength(input,argNumber);
    argument->data = malloc(length);

    int startPoint;

    startPoint = getStartPoint(input,argNumber);

    int j = 0;
    for(int i = startPoint; i < startPoint+length; i++) {
        argument->data[j] = input[i];
        j++;
    }
}

int getArgumentLength(char* input, int argNumber) {
    int startPoint = getStartPoint(input,argNumber);
    if(startPoint == -1) {
        return startPoint;
    }

    int endPoint = 0;

    for(int i = startPoint+1; i < 100; i++) {
        if((input[i] == BLANKSPACE) || (input[i] == TAB) || (input[i] == NEWLINE)) {
            endPoint = i;
            break;
        }
    }
    
    int size = endPoint - startPoint;
    return size;
}

int getStartPoint(char* input, int argNumber) {
    int startPoint = 0;
    int tempPoint = 0;
    bool valid = false;
    
    for(int j = 0; j < argNumber; j++) {
        valid = false;

        for(int i = tempPoint; i < 100; i++) {
            if((input[i] != BLANKSPACE) && (input[i] != TAB) && (input[i] != NEWLINE)) {
                startPoint = i;
                tempPoint = i;
                valid = true;
                break;
            }
        }
        for(int i = tempPoint+1; i < 100; i++) {
            if((input[i] == BLANKSPACE) || (input[i] == TAB) || (input[i] == NEWLINE)) {
                tempPoint = i;
                break;
            }
        }
    }

    if(valid) {
        return startPoint;
    }
    else {
        return -1;
    }
}

void argumentFree(struct argument* argument) {
    free(argument->data);
    free(argument);
}

void printTime() {
    time_t rawtime;
    struct tm* timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime );
    char time[100];
    strftime(time,100,"%F %T ",timeinfo);
    printf("%s",time);
}

int getInput(char* input) {
    int length = 0;
    char c;
    for(int i = 0; i < 100; i++) {
        c = fgetc(stdin);
        if(c == EOF) {
            printf("eof");
            return -1;
        }
        else if(c != NEWLINE){
            input[i] = c;
            length++;
        }
        else {
            input[i] = c;
            break;
        }
    }
    return length;
}