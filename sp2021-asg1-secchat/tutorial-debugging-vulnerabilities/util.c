#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

size_t read_line(FILE *file, char *buf, size_t size) {
  int c;
  char *p = buf, *pend = buf + size;

  while (p < pend) {
    c = fgetc(file);
    if (c == EOF) break;
    *(p++) = c;
    if (c == '\n') break;
  }
  return p - buf;
}


size_t read_line_nonewline(FILE *file, char *buf, size_t size) {
  int c;
  char *p = buf, *pend = buf + size;

  while (p < pend) {
    c = fgetc(file);
    if (c == EOF) break;
    *(p++) = c;
    if (c == '\n') {*(p-1) = 0; break;}
  }
  return p - buf;
}

void flush_print(char *string){
  printf(string);
  fflush(stdout);
}

ssize_t safe_read(int fd, void *buf, size_t len) {
 char *p = buf, *pend = p + len;
 ssize_t r;

  /* we may need to do multiple reads in case one returns prematurely */
  while (p < pend) {
    r = read(fd, p, pend - p);
    if (r < 0) {
      if (errno == EINTR) continue;
      perror("error: read from socket failed");
      return r;
    }
    if (r == 0) break;
    p += r;
  }

  r = p - (char *) buf;

  return r;
}

ssize_t safe_write(int fd, const void *buf, size_t len) {
  const char *p = buf, *pend = p + len;
  ssize_t r;

  /* we may need to do multiple writes in case one returns prematurely */
  while (p < pend) {
    r = write(fd, p, pend - p);
    if (r < 0) {
      if (errno == EINTR) continue;
      perror("error: write to socket failed");
      return r;
    }
    if (r == 0) {
      fprintf(stderr, "warning: zero bytes written\n");
      break;
    }
    p += r;
  }
  return p - (const char *) buf;
}
