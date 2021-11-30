#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

/* This example decrypts the data sent on stdin using a RSA private key
 * loaded from a file, which is specified on the command line.
 * The plaintext is written to stdout.
 * Note that it will only decrypt a single block.
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
  RSA *key = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
  fclose(keyfile);

  /* read ciphertext from stdin */
  inbuf = malloc(RSA_size(key));
  inlen = read(0, inbuf, RSA_size(key));

  /* ciphertext size must match key size */
  if (inlen != RSA_size(key)) return 1;

  /* perform decryption from inbuf to outbuf */
  outbuf = malloc(RSA_size(key));
  outlen = RSA_private_decrypt(inlen, inbuf, outbuf, key,
    RSA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */

  /* write plaintext to stdout */
  write(1, outbuf, outlen);

  RSA_free(key);
  return 0;
}
