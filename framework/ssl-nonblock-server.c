#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl-nonblock.h"

/* Simple SSH server that waits for a single connection and then echos any
 * input back to the client. It uses the ssl-nonblock functions,
 * which allow using select while still getting blocking I/O over SSL.
 * The private key file, server certificate file, and the port to listen on
 * are specified on the command line.
 *
 * Example to run the server:
 * ./ssl-nonblock-server server-key.pem server-self-cert.pem 1234
 *
 * Example to connect to it (in a separate terminal):
 * ./ssl-nonblock-client localhost 1234
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int create_server_socket(unsigned short port) {
  int fd, r;
  struct sockaddr_in addr;

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { /* handle error */ }

  /* bind socket to specified port on all interfaces */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) { /* handle error */ }

  /* start listening for incoming client connections */
  r = listen(fd, 0);
  if (r != 0) { /* handle error */ }

  return fd;
}

static void connection_echo(int fd, const char *pathkey, const char *pathcert) {
  char buf[1024];
  int len;

  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL *ssl = SSL_new(ctx);
  SSL_use_certificate_file(ssl, pathcert, SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(ssl, pathkey, SSL_FILETYPE_PEM);

  /* set up SSL connection with client */
  set_nonblock(fd);
  SSL_set_fd(ssl, fd);
  ssl_block_accept(ssl, fd);

  /* echo any incoming data from the client */
  for (;;) {
    len = ssl_block_read(ssl, fd, buf, sizeof(buf));
    if (len <= 0) break;
    ssl_block_write(ssl, fd, buf, len);
  }

  /* clean up SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
  int connfd, servfd;
  unsigned short port;

  /* listen for an incoming connection */
  port = atoi(argv[3]);
  servfd = create_server_socket(port);
  connfd = accept(servfd, NULL, NULL);

  /* interact with client */
  connection_echo(connfd, argv[1], argv[2]);

  /* clean up */
  close(connfd);
  close(servfd);

  return 0;
}
