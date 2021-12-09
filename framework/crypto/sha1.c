#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/sha.h>

/* This example generates a SHA1 hash for a file specified on the command line,
 * and prints the hash as a hexadecimal string.
 */

static void printhex(unsigned char *buf, size_t len) {
  int i;
  for (i = 0; i < len; i++) printf("%.2x", buf[i]);
  printf("\n");
}

int main(int argc, char **argv) {
  char buf[4096];
  SHA_CTX ctx;
  int fd;
  unsigned char hash[SHA_DIGEST_LENGTH];
  ssize_t len;

  /* read file specified by argv[1] block by block to hash it */
  fd = argv[1] ? open(argv[1], O_RDONLY) : 0;
  SHA1_Init(&ctx);
  for (;;) {
    len = read(fd, buf, sizeof(buf));
    if (len == 0) break;
    SHA1_Update(&ctx, buf, len);
  }
  SHA1_Final(hash, &ctx);
  close(fd);

  printhex(hash, sizeof(hash));
  return 0;
}
