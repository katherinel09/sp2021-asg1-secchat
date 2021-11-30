#ifndef __UTIL_H__
size_t read_line(FILE *file, char *buf, size_t size);
size_t read_line_nonewline(FILE *file, char *buf, size_t size);
ssize_t safe_read(int fd, void *buf, size_t len);
ssize_t safe_write(int fd, const void *buf, size_t len);
void flush_print(char *string);
#define __UTIL_H__

#endif
