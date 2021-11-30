/**
  *   
  *  This program highlights a simple stack based uninitialized read that leads to a data leak.
  *  Every time the user types in a string the client will send a dummy 
  *  message to the server and the server will compute the time and send it back to the
  *  client via a struct msg data type. The msg structure has a padding of
  *  7 bytes in between the @type and @time fields. Function prepare_send_server_message
  *  will allocate a message on the stack initialize its fields and send a 
  *  message back to the client (it does not call memset so the padding memory
  *  space remains uninitialized). In our example the padding field
  *  will pick up whatever was previously allocated on the stack in that memory
  *  slot. Prior to calling prepare_send_server_message we called
  *  get_server_time which places some secret data on the stack.The unitialized 
  *  padding in the structure will be allocated over this secret data. When we send
  *  the msg structure to the client (line 72) we also send the secret data through the
  *  structure's padding. The client will print each byte in 
  *  the structure showing the secret data.
  *
  *
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


#include "util.h"
#define MAX_LEN_STR 256

#define MSG_TYPE_RQ 0
#define MSG_TYPE_RS 1

/* We'll send this without marshalling as it is */
struct msg {
  unsigned char type;
  // padding[7];
  unsigned long long time;
};

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
   char sensitivePassword[7] = "secr798";
   s_time = (unsigned long long)time(NULL);
   /* presumably we also do something with the sensitive information*/

   return s_time;
}

static void prepare_send_server_message(int fd, unsigned long long time){
  struct msg message; // zero allocated
  /* TODO decomment this if you want to fix the uninitialized leak */
  //memset(&message, 0, sizeof(struct msg));
  message.type = MSG_TYPE_RS;
  message.time = time;

  safe_write(fd, &message, sizeof(struct msg));
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

static void print_as_char(char *mem_loc, int size){
  int i;
  printf("Memory location is:");
  for (i = 0; i < size; i++){
      printf("%c ", mem_loc[i]);
  }
  printf("\n");
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

     rcv = recv_msg(fd);

     if (rcv->type == MSG_TYPE_RS){
        printf("client: Received response %lld\n", rcv->time);

        print_as_char((char *)rcv, sizeof(struct msg));
     }

     free_recv_msg(&rcv);
     
      
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
