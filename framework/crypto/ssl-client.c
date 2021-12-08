#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef __CYGWIN__
#define gethostent() NULL
#endif

/* Simple SSH client that sends a line of input from stdin to the server,
 * and then displays the server's response. The server's hostname and port are
 * specified on the command line.
 *
 * This example does not verify the server's certificate,
 * see ssl-client-verify.c for an example of how to do that.
 *
 * Example to run the server:
 * ./ssl-server server-key.pem server-self-cert.pem 1234
 *
 * Example to connect to it (in a separate terminal):
 * ./ssl-client localhost 1234
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

  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL *ssl = SSL_new(ctx);

  /* set up SSL connection with client */
  SSL_set_fd(ssl, fd);
  SSL_connect(ssl);

  /* read user input from stdin */
  len = read(0, buf, sizeof(buf));

  /* send to server */
  SSL_write(ssl, buf, len);

  /* receive server result */
  len = SSL_read(ssl, buf, sizeof(buf));

  /* show reply on stdout */
  write(1, buf, len);

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
