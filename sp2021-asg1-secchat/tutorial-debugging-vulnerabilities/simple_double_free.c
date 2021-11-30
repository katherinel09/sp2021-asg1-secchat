/**
  *   
  *  This program highlights a simple double free error. The server will free
  *  the rcv structure twice (line 183 and 185) which creates a circular chain
  *  in malloc's freelist implementation. All allocations that can be served 
  *  from rcv's previously allocated chunk will allocate rcv's chunk (even
  *  if they do not free it). In other words, all allocations will point to
  *  the same memory area. As a result the pub and priv allocated structures
  *  will esssentially point to the same memory chunk.
  *
  *  Running the program: ./simple_double_free
  *  After that, any message written on the console will trigger the client to
  *  send a dummy message to the server which in turn will trigger the bug
  *  in the server.
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
#include <pthread.h>


#include "util.h"
#define MAX_LEN_STR 256

#define MSG_TYPE_RQ 0
#define MSG_TYPE_RS 1




/* Structure used to send messages between server/client*/
struct msg {
  unsigned char type;
  unsigned long long time;
};

/* The private data structure */
struct private_data {
  char message[14];
};

/* The public data structure */
struct public_data {
  char message[16];
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
  struct msg message;
  /* No initialization of message (decomment the line in order to do this) */
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

/* Faulty free function */
static void free_recv_msg(struct msg *msg){
  memset(msg, 0, sizeof(struct msg));
  free(msg);
  /* Never gets passed upwards to free_recv_msg's caller */
  msg = NULL;
}

static void print_as_char(char *mem_loc, int size){
  int i;
  printf("Memory location is:");
  for (i = 0; i < size; i++){
      printf("%c ", mem_loc[i]);
  }
  printf("\n");
}

/* Allocate a chunk of private data with malloc */
struct private_data* create_private_data(){
  struct private_data *data;
  data =  (struct private_data*) malloc(sizeof(struct private_data));
  return data;
}

/* Prepare private data (writes some sensitive string in the location) */
void process_private_data(struct private_data *data){
   memset(data, 0, sizeof(struct private_data));
   /* Write some secret pattern in the private data structure */
   memcpy(data->message, "Really secret9", 14);
}

/* Allocate a chunk of public data with malloc */
struct public_data* create_public_data(){
  struct public_data *data;
  data =  (struct public_data*) malloc(sizeof(struct public_data));
  return data;
}

/* Prepare public data (just zeroes the data) */
void process_public_data(struct public_data *data){
   /* We just zero initialize the data */
   memset(data, 0, sizeof(struct public_data));
}

/* Print data in the struct. We hardcoded the length of the message for simplicity */
void print_public_data(struct public_data *data){
   int i = 0;
   printf("Public data is:");
   for (i = 0; i < 16; i++){
       printf("%c ", data->message[i]);
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

     /* Error is in server. The client just triggers it so don't do anything 
        with response */

     free_recv_msg(rcv);
     rcv = NULL;
      
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
         /* example freelist before first free
           head->elem1->elem2; 
            after first free rcv
           head->rcv->elem1->elem2;
            after second faulty free (circular list)
            head->rcv->rcv (broken link)|-> elem1 -> elem2
            result: all mallocs that fit in rcv's previously allocated
                    chunk will receive rcv's chunk as allocation (all
                    these allocations will point to the rcv chunk)
           
          */
         free_recv_msg(rcv);
         /* Error we freed message a second time (comment the following line to fix the double free) */
         if (rcv) {free(rcv); rcv = NULL;}
         /* We intermix some public and private data processing here */
         struct private_data *priv = create_private_data();
         struct public_data  *pub = create_public_data();

         /* When we double free rcv pub == priv. Both priv and pub will point to the same chunk of memory */
         if ((unsigned long long)pub == (unsigned long long)priv) printf("We have a double free bug pub==priv.\n");

         /* We set public data to 0 */
         process_public_data(pub);
         /* Write some secret data to priv (reflects on pub as it points to the same chunk) */
         process_private_data(priv);
         /* Now a print from pub will print everything that was written on priv */
         print_public_data(pub);

         
         memset(pub, 0, sizeof(struct public_data));
         memset(priv, 0, sizeof(struct private_data));
         /* Double free again (doesn't really matter) */   
         free(pub);
         free(priv);
                           
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
    /* Run the server in the child */
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
  
  /* Runs the client in the parent */
  client_loop(sockets[0]);
  
}
