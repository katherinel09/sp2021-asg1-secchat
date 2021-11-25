#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* This example verifies an RSA signature for the message specified in the
 * second argument, using a RSA private key loaded from the file specified
 * by the first argument. The signature is provided through to stdin.
 *
 * Example to sign "Hello world" with key in file keypriv.pem,
 * and then verify signature with key in file keypub.pem:
 * ./rsa-sign keypriv.pem 'Hello world' | ./rsa-verify keypub.pem 'Hello world'
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int main(int argc, char **argv) {
  int r; unsigned char *sig; unsigned siglen;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  EVP_PKEY *evpKey = EVP_PKEY_new();

  /* read key from argv[1] */
  FILE *keyfile = fopen(argv[1], "r");
  RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
  fclose(keyfile);

  /* make EVP key using RSA key (RSA key will be automatically freed) */
  EVP_PKEY_assign_RSA(evpKey, key);

  /* read signature from stdin into sig */
  sig = malloc(EVP_PKEY_size(evpKey));
  siglen = read(0, sig, EVP_PKEY_size(evpKey));

  /* verify signature */
  EVP_VerifyInit(ctx, EVP_sha1());
  EVP_VerifyUpdate(ctx, argv[2], strlen(argv[2]));
  r = EVP_VerifyFinal(ctx, sig, siglen, evpKey);
  printf("signature is %s\n", (r == 1) ? "good" : "bad");

  EVP_PKEY_free(evpKey);
  EVP_MD_CTX_free(ctx);
  return 0;
}
