/**
  *   
  *  This program highlights a simple heap metadata corruption bug.
  *  Initially we have to buffers @pub and @priv. We call @modify_bits
  *  on @pub to zero out the buffer and additionally write byte 128 (decimal)
  *  to position @pos. However, when we pass pos we pass it through a char
  *  variable equal to 248. As char is signed and can contain values between
  *  (-127, 128) the number 248 as a signed char is actually -8. When we pass
  *  this char to @modify_bits which accepts it as an integer (also signed) the
  *  number will be sign extended to an integer and will also equal -8.
  *  On line 42 we overwrite msg->message[-8] with the value 128. This essentially
  *  overwrites @pub's malloc metadata ( bytes -8 to -1 prior to the buffer 
  *  will be interpreted as an unsigned long long representing the size of @pub's
  *  allocation). When the buffer will be freed on line 81 we trick the allocator
  *  that @pub's chunk (which gets freed here) is 128 bytes long (even though
  *  prior to the metadata corruption the buffer was less than 32 bytes).
  *  On line 86 @large_buf's allocation will receive the previous chunk 
  *  freed by @pub (even though large_buf is 118 bytes and cannot fit in this
  *  chunk). This is because the allocator thinks that this chunk is larger (128 bytes)
  *  and can fit @large_buffer. As a result, @large_buffer now spans past 
  *  the @priv buffer (i.e., it also contains the memory area reserved for @priv).
  *  When we do a @print_data on @large_buffer we also print @priv's bytes.
  *
  *  Runnin
  *  
  *
***/
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

struct private_data {
  int userid;
  char secretkey[8];
  char userData[32];
};

struct public_message {
  char message[16];
};

/* Writes all bytes to 0 except byte pos */
void modify_bits(struct public_message *msg, int pos, int size){
  /* Some dummy check */
  if (pos > size){
     return;
  }
  for (int i = 0; i < size; i++){
      if (i != pos){
          msg->message[i] = 0;
      }
  }
  msg->message[pos] = 128; // msg->message[-8] = 128

  //printf("Size:%d\n", *(int *)(msg->message-8));
}

void print_data(char *buff, unsigned int size){
   /* We also hit some internal buffers */
   printf("Public data is:");
   for (unsigned int i = 0; i < size; i++){
        if (buff[i]){
            printf("%c ", buff[i]);
        }
   }
   printf("\n");
}

void fill_private_data(struct private_data *priv){
   priv->userid = 0;
   memcpy(priv->secretkey, "ABCDEFGH", 8);
   memset(priv->userData, 0, 32);
   memcpy(priv->userData, "This is some private user data", sizeof("This is some private user data"));
}

int main(){
    char pos = 248;
    struct public_message *pub = malloc(sizeof(struct public_message));
    struct private_data *priv = malloc(sizeof(struct private_data));
    char *large_buf;
    //printf("%p %ld\n", pub, (char*)priv - (char*)pub);

    // Put some private data together
    fill_private_data(priv);
    
    // Trigger a write through an type error to pub->message[-8] and overwrite heap metadata
    modify_bits(pub, (int)pos, sizeof(pub->message));

    free(pub);
    // We will allocate over private data now
    large_buf = malloc(118);

    print_data(large_buf, 118);
    //printf("%p\n", large_buf);

}
