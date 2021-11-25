/**
  *   
  *  This program should be debugged with ltrace/strace.
  *  For the private test create a root file private.txt: 
  *  -> sudo touch private.txt; sudo cat "Test" > private.txt
  *
  *  In this example we make some library/syscalls without proper error handling.
  *  Hints on the errors:
  *  1. On line 32 the strncpy will not copy the null terminating byte. As a
  *  result on line 47 and line 55 we will try to open an unexisting file (the
  *  filename is wrong due to our string manipulation operations).
  *  2. After we fix this error we still cannot read the file on line 67. We need
  *  to decomment the fclose on line 63.
  *  3. After both errors are fixed we still cannot open private.txt.
  *  
  *  Running the program to check all of these errors:
  *  ->  ltrace ./ltrace_strace_fun test
  *  or
  *  -> strace ./ltrace_strace_fun test
  *
  *  If we want to trace a specific library:
  *  ->  ltrace -l libname ./ltrace_strace_fun test
  *  For example:
  *  ->  ltrace -l libc.so.6 ./ltrace_strace_fun test
  *  If we want to find the dynamic library name we want to trace we can do:
  *  ->  ldd ./ltrace_strace_fun
  *
  *  If we want to trace a specific library/syscall we can do:
  *  -> ltrace -s 100 -f -e strncpy ./ltrace_strace_fun test
  *  -> strace -s 100 -f -e trace=openat,read  ./ltrace_strace_fun test
  *
  *  @HINT ltrace is really useful when we want to debug sql or openssl.
  *  
  *  For the tests with the private file:
  *  -> strace ./ltrace_strace_fun private
  *  
  *
***/
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"

int main(int argc, char *argv[]){
   char testFile[100];
   char destFile[100];
   char resBuf[50];
   int fd; FILE *fp;
   char *b = malloc(100);
   /* Memset the file to 50 g's and 50 0's */
   memset(testFile, '0', 100);
   //memset(testFile+50, 0, 50);

   if (argc == 2){
      /* Error here we did not add the terminating null char */
      strncpy(testFile, argv[1], strlen(argv[1]));
   } else {
     printf("Add some parameters\n");
     exit(1);
   }

   /* Add .txt terminator */
   strcat(testFile, ".txt");

   memset(destFile, 0, 100);
   strcpy(destFile, testFile);

   memset(resBuf, 0, 50);
    /* No error check on open */
   fd = open(destFile, O_RDONLY);

    /* No error check on read */
   read(fd, resBuf, 10);

   printf("read returned:%s\n", resBuf);

   /* No error check on fopen */
   fp = fopen(destFile, "r");

   /* No error check on fp */
   fclose(fp);

   memset(resBuf, 0, 50);

   /* No error check on fread */
   fread(resBuf, 1, 50, fp);

   printf("fread returned:%s\n", resBuf);

   return 0;

}
