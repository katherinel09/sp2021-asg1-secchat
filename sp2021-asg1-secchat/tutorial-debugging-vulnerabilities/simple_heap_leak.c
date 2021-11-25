/**
  *   
  *  This program highlights a heap based uninitialized read that leads to a data leak.
  *  Every time the user types in a string the client will send a dummy 
  *  message to the server and the server will compute the time and send it back to the
  *  client via a struct msg data type. Unlike simple_leak.c the server will respond
  *  to the client with NMESSAGES messages. In this example, get_server_time will
  *  allocate a buffer of size NMESSAGES*sizeof(struct msg) and will write a 
  *  secret pattern in multiple locations of the buffer (buffer is called @sensitiveBuffer).
  *  The server frees the buffer releasing the memory chunk but does not zero
  *  out the chunk. When the server will allocate memory for the messages he
  *  will send back to the client he will receive the same memory chunk previously
  *  allocated to @sensitiveBuffer. The padding bytes of the messages allocated
  *  by the server in prepare_send_server_message will overlay on top of the
  *  sensitive patterns we previously written in @sensitiveBuffer. Even though
  *  we explicitly initialize all messages in the server, we do not initialize
  *  the entire memory location of the messages (and the paddings will still
  *  contain the sensitive pattern). As a result when we send the message to
  *  the client, the client can access the sensitive pattern through the 
  *  messages' padding bytes. This does not happen for the first message as 
  *  freeing the @sensitiveBuffer will also overwrite the first 16 bytes of the
  *  chunk with references needed for malloc's freelist design (i.e., next and
  *  previous freelist chunk fields). However, all messages past the first will
  *  still contain the data previously written in @sensitiveBuffer.
  *
  *
  *  Running the program: ./simple_heap_leak (then type in any message).
  *
  *
***/
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>


#include "util.h"
#define MAX_LEN_STR 256
#define NMESSAGES 2

#define MSG_TYPE_RQ 0
#define MSG_TYPE_RS 1

/* We'll send this without marshalling as it is */
struct msg {
  unsigned char type;
  unsigned long long time;
};

static void print_as_char(char *mem_loc, int size){
  int i;
  printf("Memory location is:");
  for (i = 0; i < size; i++){
      printf("%c ", mem_loc[i]);
  }
  printf("\n");
}

static void prepare_send_client_message(int fd, unsigned long long time){
  struct msg message;
  /* Initialize message */
  memset(&message, 0, sizeof(struct msg));
  message.type = MSG_TYPE_RQ;
  message.time = time;

  safe_write(fd, &message, sizeof(struct msg));
  
}

static unsigned long long get_server_time(){
   unsigned long long s_time;
   /* Some secret information that only the server should know */
   char *sensitiveBuffer;
   

   s_time = (unsigned long long)time(NULL);

   sensitiveBuffer = malloc(NMESSAGES*sizeof(struct msg));
   assert(sensitiveBuffer);
   /* fill in secret buffer with info do some dummy work */
   memset(sensitiveBuffer, 0 , NMESSAGES*sizeof(struct msg));
   memcpy(sensitiveBuffer, " secr798", strlen(" secr798"));
   memcpy(sensitiveBuffer+sizeof(struct msg), " secr798", strlen(" secr798"));

   /* we didn't zero out the freed memory sadly */
   free(sensitiveBuffer);

   return s_time;
}

static void prepare_send_server_message(int fd, unsigned long long time){
  struct msg *message;
  int i;
  
  message = malloc(NMESSAGES*sizeof(struct msg));
  /* TODO decomment this if you want to fix the leak */
  //memset(message, 0, NMESSAGES*sizeof(struct msg));
  assert(message);

  /* Again we only explicitly initialize all message fields but not the entire
     msg structure */
  for (int i = 0; i < NMESSAGES; i++){
      message[i].type = MSG_TYPE_RS;
      message[i].time = time;
  }
  
  /* Send all messages */
  safe_write(fd, message, NMESSAGES*sizeof(struct msg));

 

  free(message);

}

static struct msg* recv_msg(int fd){
   struct msg *received;
   received = malloc(sizeof(struct msg));
   memset(received, 0, sizeof(struct msg));

   safe_read(fd, received, sizeof(struct msg));

   return received;
}

static void free_recv_msg(struct msg **msg){
  memset(*msg, 0, sizeof(struct msg));
  free(*msg);
  *msg = NULL;
}

void client_loop(int fd){
 char line[MAX_LEN_STR];
 struct msg *rcv;
 /* Loop forever */
 while(1){
     /* Initialize stdin buffer */
     memset(line, 0 , MAX_LEN_STR);
     /* No overflow here */
     read_line(stdin, line, sizeof(line));
    
     prepare_send_client_message(fd, 0);

     
    
     for (int i = 0; i < NMESSAGES; i++){

       rcv = recv_msg(fd);

       if (rcv->type == MSG_TYPE_RS){
           printf("client: Received response %lld\n", rcv->time);

           print_as_char((char *)rcv, sizeof(struct msg));
       }
       
       free_recv_msg(&rcv);
     }
     
      
 }
}

void server_loop(int fd){
 struct msg *rcv;
 unsigned long long time;
 while(1){
     rcv = recv_msg(fd);
   
     if (rcv->type == MSG_TYPE_RQ){
         time = get_server_time();
         prepare_send_server_message(fd, time);
         free_recv_msg(&rcv);
     } 
 }
}

int main(){
  pid_t pid;
  int sockets[2];

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        perror("error: opening stream socket pair");
        return -1;
  }

  /* fork server process */
  pid = fork();
  if (pid == 0) {
    /* worker process */
    close(sockets[0]);
    server_loop(sockets[1]);
    exit(0);
  }

  /* Error while forking? */
  if (pid == -1) {
    perror("error: cannot fork");
    close(sockets[0]);
    close(sockets[1]);
    return -1;
  } 

  /* client code goes here */

  close(sockets[1]); 
  
  client_loop(sockets[0]);
  
}
