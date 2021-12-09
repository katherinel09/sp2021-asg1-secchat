// #include <stdlib.h>
// #include <unistd.h>

// #include <openssl/crypto/rsa/rsa_local.h>


// // SSL_write(ssl, input, strlen(input));   /* encrypt & send message */

// // Main code from example slides, tweaked slightly
// int main(int argc, char **argv)
// {
//     unsigned char *inbuf, *outbuf;
//     ssize_t inlen, outlen;

//     /* read key from argv[1] */
//     FILE *keyfile = fopen(argv[1], "r");
//     RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
//     fclose(keyfile);

//     /* read plaintext from stdin */
//     inbuf = malloc(RSA_size(key));
//     inlen = read(0, inbuf, RSA_size(key));

//     /* plaintext size must fit in key size, including padding */
//     if (inlen > RSA_size(key) - 42) {return 1;}

//     /* perform decryption from inbuf to outbuf */
//     outbuf = malloc(RSA_size(key));
//     outlen = RSA_public_encrypt(inlen, inbuf, outbuf, key, SA_PKCS1_OAEP_PADDING); /* random padding, needs 42 bytes */

//     /* write ciphertext to stdout */
//     write(1, outbuf, outlen);
//     SSL_write(ssl, input, strlen(input)); /* encrypt & send message */

//     RSA_free(key);
//     return 0;
// }

// int main_encrypt()
// {
//     int key_length = 2048;
//     char plainText[key_length] = "this is the message"; // key length : 2048

//     RSA *private_key = create_pub_priv_keys(*key, 0);
//     RSA *public_key = create_pub_priv_keys(*key, 1);

//     unsigned char encrypted[2 * keylength] = {};
//     // IMPORTANT
//     int enc_len = RSA_public_encrypt(strlen(plainText), plainText, encrypted, public_key, RSA_PKCS1_PADDING); // (plainText, strlen(plainText), public_key, encrypted);

//     if (encrypted_length == -1)
//     {
//         printLastError("Public encrypt went wrong :( ");
//         exit(1);
//     }

//     int encrypted_length = private_encrypt(plainText, strlen(plainText), privateKey, encrypted);
//     if (encrypted_length == -1)
//     {
//         printLastError("Private encrypt went wrong :(");
//         exit(0);
//     }

//     // NOW send the message!

//     // Step 5: Delete the original file with the message
//     // $ rm -f message_to_send.txt

//     // Step 6: send the encrypted file to user 2
//     // $  scp message_to_send.enc bob@bob-machine-or-ip:/path/
// }

// // Step 1: Generate a pair of keys for the user
// // public.pem is RSA public key in PEM format.
// // private.pem is RSA private key in PEM format.
// // RSA *private_key = create_pub_priv_keys(*key, 0);
// // RSA *public_key = create_pub_priv_keys(*key, 1);

// RSA *create_pub_priv_keys(char *username_dir, int public_true)
// {

//     FILE *fp = fopen(username_dir, "rb");

//     if (fp == NULL)
//     {
//         printf("Couldn't add a new key to the directory\n");
//         return NULL;
//     }

//     RSA *rsa = RSA_new();

//     if (public)
//     {
//         rsa = PEM_read_RSA_PUBKEY(username_key, &rsa, NULL, NULL);
//     }
//     else
//     {
//         rsa = PEM_read_RSAPrivateKey(username_key, &rsa, NULL, NULL);
//     }

//     return rsa;
// }



// // including more

// int gen_certificates() {

//     // SSL_CTX* InitServerCTX(void)
//     // void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
//     // void ShowCerts(SSL* ssl)

//     con_ssl = InitServerCTX();        /* initialize SSL */
//     LoadCertificates(con_ssl, "/clientkey/username/public_key.pem", "/clientkey/username/private_key.pem");  /* load certs */

//     // SSL_write(ssl, input, strlen(input)); /* encrypt & send message */


//     return 0;
// }
