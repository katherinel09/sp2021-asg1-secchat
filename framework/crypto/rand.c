#include <stdio.h>
#include <stdlib.h>

#include <openssl/rand.h>

int main(int argc, char **argv) {
  unsigned char byte;

  /* request a single random byte and print it to stdout */
  RAND_bytes(&byte, 1);
  printf("%u\n", byte);

  return 0;
}
