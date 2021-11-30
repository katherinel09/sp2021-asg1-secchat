/**
  *   
  *  This program highlights a heap leak gone wrong. For each message from the
  *  client the server will do some processing (in @process_request) in which
  *  he allocates a buffer called @data (either via malloc or mmap) but never
  *  frees the buffer. Try this example first with malloc than with mmap and
  *  you will notice some differences in behavior. With malloc your system will
  *  freeze (and you will be killed by the oom killer) but with mmap even 
  *  though we still allocate virtual memory, the server will execute normally
  *  and will fail at some point with a "Not enough memory" -1 error. Why is
  *  that?
  *  
  *  To trigger the bug run: echo "some message" | ./simple_mem_leak
  *  
  *  As in our example we do not treat the EOF properly, the command above will
  *  make the client loop forever sending a dummy request to the server. On each
  *  request, the server will allocate a buffer but never free it. While the
  *  program is running, in another terminal type in "free -t". What's the 
  *  difference in memory utilization if the test is run with malloc/mmap? 
  *  Try to understand why this happens.
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
#include <sys/mman.h>


#include "util.h"
#define MAX_LEN_STR 256

#define MSG_TYPE_RQ 0
#define MSG_TYPE_RS 1

#define SCALE (float)1/4

/* We'll send this without marshalling as it is */
struct msg {
  unsigned char type;
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

static unsigned long long get_server_time(void){
   unsigned long long s_time;
   /* Some secret information that only the server should know */
   char sensitivePassword[7] = "secr798";
   s_time = (unsigned long long)time(NULL);
   /* presumably we also do something with the sensitive information*/

   return s_time;
}

static void prepare_send_server_message(int fd, unsigned long long time){
  struct msg message;
  /* No initialization of message */
  memset(&message, 0, sizeof(struct msg));
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

void client_loop(int fd){
 char line[MAX_LEN_STR];
 struct msg *rcv;
 /* Loop forever */
 while(1){
     /* Initialize stdin buffer */
     memset(line, 0 , MAX_LEN_STR);
     /* No overflow here */
     read_line(stdin, line, sizeof(line));
 
     if (strcmp(line, "exit\n") == 0){
        exit(0);
     }
   
     prepare_send_client_message(fd, 0);

     rcv = recv_msg(fd);

     if (rcv->type == MSG_TYPE_RS){
        printf("client: Received response %lld\n", rcv->time);

     }

     free_recv_msg(&rcv);
     
      
 }
}
void process_request(void){
  size_t page_size = sysconf(_SC_PAGESIZE);

  /* TODO A1. decomment this and comment B1 to use malloc for your test */
  unsigned char *data = (unsigned char *)malloc(SCALE*page_size*sizeof(unsigned char));

  /* TODO B1. decomment this and comment A1 to use mmap for your test. */
  //unsigned char *data = mmap(0, SCALE*page_size*sizeof(unsigned char), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);


  if (data == NULL){
     printf("Not enough memory\n");
     exit(-1);
  }

  
  /* TODO A2. decomment this and A1 to fix the leak (if you use malloc for allocation) */
  //free(data);

  /* TODO B2. decomment this and B1 to fix the leak (if you use mmap for allocation) */
  //munmap(data, SCALE*page_size*sizeof(unsigned char));
  
}
void server_loop(int fd){
 struct msg *rcv;
 unsigned long long time;
 while(1){
     rcv = recv_msg(fd);
   
     if (rcv->type == MSG_TYPE_RQ){
         time = get_server_time();
         process_request(); 
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
