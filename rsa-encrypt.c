#include <stdlib.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

/* This example encrypts the data sent on stdin using a RSA public key
 * loaded from a file, which is specified on the command line.
 * The ciphertext is written to stdout.
 * Note that it will only encrypt a single block.
 *
 * Example to encrypt "Hello world" with key in file keypub.pem,
 * and then decrypt with key in file keypriv.pem:
 * echo Hello world | ./rsa-encrypt keypub.pem | ./rsa-decrypt keypriv.pem
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int main(int argc, char **argv) {
  unsigned char *inbuf, *outbuf; ssize_t inlen, outlen;

  /* read key from argv[1] */
  FILE *keyfile = fopen(argv[1], "r");
  RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
  fclose(keyfile);

  /* read plaintext from stdin */
  inbuf = malloc(RSA_size(key));
  inlen = read(0, inbuf, RSA_size(key));

  /* plaintext size must fit in key size, including padding */
  if (inlen > RSA_size(key) - 42) return 1;

  /* perform decryption from inbuf to outbuf */
  outbuf = malloc(RSA_size(key));
  outlen = RSA_public_encrypt(inlen, inbuf, outbuf, key,
    RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */

  /* write ciphertext to stdout */
  write(1, outbuf, outlen);

  RSA_free(key);
  return 0;
}
