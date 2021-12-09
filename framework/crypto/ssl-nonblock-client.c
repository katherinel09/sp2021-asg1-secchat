#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl-nonblock.h"

#ifdef __CYGWIN__
#define gethostent() NULL
#endif

/* Simple SSH client that sends input from the user to the server,
 * and prints input from the server to stdout. It uses the ssl-nonblock
 * functions to use select while still getting blocking I/O over SSL.
 * The server's hostname and port are specified on the command line.
 *
 * This example does not verify the server's certificate,
 * see ssl-client-verify.c for an example of how to do that.
 *
 * Example to run the server:
 * ./ssl-nonblock-server server-key.pem server-self-cert.pem 1234
 *
 * Example to connect to it (in a separate terminal):
 * ./ssl-nonblock-client localhost 1234
 *
 * See Makefile and/or slides for how to generate the keys.
 */

static int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  /* unknown host */
  return -1;
}

int client_connect(const char *hostname, unsigned short port) {
  struct sockaddr_in addr;
  int fd, r;

  /* look up hostname */
  r = lookup_host_ipv4(hostname, &addr.sin_addr);
  if (r != 0) { /* handle error */ }

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { /* handle error */ }

  /* connect to server */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  r = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) { /* handle error */ abort(); }
  
  return fd;
}

static void talk_to_server(int fd) {
  char buf[1024];
  int len;
  fd_set readfds;

  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL *ssl = SSL_new(ctx);

  /* configure the socket as non-blocking */
  set_nonblock(fd);

  /* set up SSL connection with client */
  SSL_set_fd(ssl, fd);
  ssl_block_connect(ssl, fd);

  /* interact with the server and the user at the same time */
  for (;;) {
    /* wait for either stdin or the socket to have input */
    FD_ZERO(&readfds);
    FD_SET(0, &readfds);
    FD_SET(fd, &readfds);
    select(fd+1, &readfds, NULL, NULL, NULL);

    /* handle input from the server, ignore in case it is just control data */
    if (FD_ISSET(fd, &readfds) && ssl_has_data(ssl)) {
      /* send data from server to stdout */
      len = ssl_block_read(ssl, fd, buf, sizeof(buf));
      if (len <= 0) break; /* error or end-of-file */
      write(1, buf, len);
    }

    /* handle input from the user */
    if (FD_ISSET(0, &readfds)) {
      /* send data from stdin to server */
      len = read(0, buf, sizeof(buf));
      if (len <= 0) break; /* error or end-of-file */
      ssl_block_write(ssl, fd, buf, len);
    }
  }

  /* clean up SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
  int connfd;
  const char *host;
  unsigned short port;

  /* connect to server */
  host = argv[1];
  port = atoi(argv[2]);
  connfd = client_connect(host, port);

  /* interact with server */
  talk_to_server(connfd);

  /* clean up */
  close(connfd);

  return 0;
}
