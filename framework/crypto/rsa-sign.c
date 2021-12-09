#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* This example generates an RSA signature for the message specified in the
 * second argument, using a RSA private key loaded from the file specified
 * by the first argument. The signature is written to stdout.
 *
 * Example to sign "Hello world" with key in file keypriv.pem,
 * and then verify signature with key in file keypub.pem:
 * ./rsa-sign keypriv.pem 'Hello world' | ./rsa-verify keypub.pem 'Hello world'
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int main(int argc, char **argv) {
  unsigned char *sig; unsigned siglen;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  EVP_PKEY *evpKey = EVP_PKEY_new();

  /* read key from argv[1] */
  FILE *keyfile = fopen(argv[1], "r");
  RSA *key = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
  fclose(keyfile);

  /* make EVP key using RSA key (RSA key will be automatically freed) */
  EVP_PKEY_assign_RSA(evpKey, key);

  /* compute signature for argv[2], store into sig */
  sig = malloc(EVP_PKEY_size(evpKey));
  EVP_SignInit(ctx, EVP_sha1());
  EVP_SignUpdate(ctx, argv[2], strlen(argv[2]));
  EVP_SignFinal(ctx, sig, &siglen, evpKey);

  /* write signature to stdout */
  write(1, sig, siglen);

  EVP_PKEY_free(evpKey);
  EVP_MD_CTX_free(ctx);
  return 0;
}
