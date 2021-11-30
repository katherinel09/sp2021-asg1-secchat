/**
  *   
  *  This program should be debugged with valgrind.
  *  The program contains multiple types of errors:
  *  -> leak errors (some buffers don't get freed)
  *  -> double frees 
  *  -> invalid read/writes (past the size of buffers)
  *  -> uninitialized variables used as parameters for syscalls or to control
  *  the outcome of a branch.
  *
  *  To see a complete list of bugs run the program under valgrind:
  *  -> ./valgrind.sh memory_errors
  *
  *  Based on our valgrind.sh script all errors will be outputed in valgrind-out.txt
  *  Check the file and try to understand/fix each error outputed by valgrind.
  *  
  *
***/
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "util.h"
struct msg {
  unsigned char type;
  unsigned long long time;
};

void some_func(){
    printf("Test\n");
}

int doubleValue(int value){
   return 2*value;
}

int *deadVariable(void){
   int x = 3;
   int *y;
   y = &x;
   return y;
}

int *deadVariable2(void){
   int *y = malloc(sizeof(int));
   *y = 3;
   return y;
}

int main() {
    int i;
    char *src_p, *dst_p;
    struct msg stackMDst, stackMSrc;
    struct msg *heapMDst, *heapMSrc;
    int  jmp_test, *jmp_test_p;
    char *src, *dst;
    char *reallocP, *reallocR;
    char *realloc2;
    char *strBuff;
    int sockets[2];
    struct msg sock_msg;
    int *deadb;

    

    //src_p = NULL;
    dst_p = src_p;
    if (dst_p){
       some_func();
    }

    // Message stackMSrc uninitialized
    //memset(&stackMSrc, 0, sizeof(struct msg));
    //stackMSrc.time = 0; stackMSrc.type = 1;
    stackMDst = stackMSrc;

    printf("%c %llx", stackMDst.type, stackMDst.time);

    // Message heapMSrc allocated but uninitialized
    heapMSrc = malloc(sizeof(struct msg));
    //heapMSrc->type = 1;
    heapMDst = heapMSrc;
    int type = (int)heapMDst->type + 3;
    type = doubleValue(type);

    if (type == 3){
       printf("Uninitialized heap message\n");
    }


    /* Uninitialized jump */
    // jmp_test = 0;
    if (jmp_test){
       some_func();
    }
    jmp_test_p = malloc(sizeof(int));
    // *jmp_test_p = 3;
    if (*jmp_test_p >= 2){
        some_func();
    }  

    free(jmp_test_p);

    src = malloc(10 * sizeof(char));
    dst = malloc(9 * sizeof(char));

    for (i = 0; i < 10; i++){
        src[i] = 'a';
    }

    /* Write past the boundaries of the buffer */
    src[i] = '\0';

    /* Read by one error and write by two error */
    for (i = 0; i < 11; i++){
        dst[i] = src[i];
    }
    
    /* Error write by one */
    memcpy(dst, src, 10);
      
    free(src);

    int size;
    reallocP = calloc(10, sizeof(char));
    free(dst);
    reallocR = realloc(reallocP, 100000 * 10 *sizeof(char));
    /* Error if realloc returns a different address */
    reallocP[0] = 'd';

    /* We do not free reallocP */

    /* We double free the same buffer*/
    free(heapMSrc);
    free(heapMDst);


    /* We free the buffer prior to realloc */
    realloc2 = malloc(10 * sizeof(char));
    free(realloc2);
    realloc2 = realloc(realloc2, 20 *sizeof(char));

    /* strncpy error when copying the 0 byte */
    strBuff = malloc(5*sizeof(char));
    strncpy((char *)strBuff, "12345", strlen("12345")+1);
    
    
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        perror("error: opening stream socket pair");
        return -1;
    }
    /* Presumably we initialized the structure */
    sock_msg.type = 0;
    sock_msg.time = 0;
    memset(&sock_msg, 0 , sizeof(struct msg));

    safe_write(sockets[0], &sock_msg, sizeof(struct msg));
    safe_read(sockets[1], &sock_msg, sizeof(struct msg));
    
    deadb = deadVariable();

    printf("%d\n", *deadb);

    return 0;
}
