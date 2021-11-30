/**
  *   
  *  This program highlights a simple overflow that can corrupt a function 
  *  pointer. At 103 we call strcpy without previously checking to see if
  *  line fits into uc->password. If when prompted for a password we write
  *  more than 8 bytes when strcpy gets called all surplus bytes will overflow
  *  past uc->password's bounds and land in uc->loginfunc. On line 66 we have
  *  an unsanitized print of a greeting message on which we can launch a string
  *  formatting attack to bypass ASLR.
  *
  *  We need to pass our input through a formatter such that we can type in 
  *  specific byte values in order to overflow uc->loginfunc with a meaningfull 
  *  function address(address of private_function or show_admin_password).
  *
  *  Running the program:
  *  python formatter.py | ./simple_cp_hijack
  *
  *  When prompted for a greeting message type in:
  *  %llx %llx %llx %llx %llx %llx %llx %llx %llx (enter)
  *  
  *  -> Second to last element printed is the "address of public_function" (which
  *  was saved on the stack, line 65).
  *  -> nm simple_cp_hijack ( in another terminal) and look for the offset at which
  *  private_function and public_function lies (do a grep for them).
  *  -> (hex computation) compute private_function's address = "address of public_function" - "offset of public_function (nm)" + "offset of private_function (nm)"
  *
  *
  *  When prompted for user: anything (enter)
  *  When prompted for password (now its time to overflow strcat):
  *  Lets say the address of private_function is: 0x667788994b5a based on your computation.
  *  Then type in: BBBBBBBB\x5a\x4b\x99\x88\x77\x66\x00\x00
  *  
  *  Explanation: "BBBBBBBB" (8 bytes that go in uc->password), \x5a\x4b\x99\x88\x77\x66\x00\x00 the 0x667788994b5a address that overflows in uc->loginfunc
  *  when strcat gets called.
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

typedef void (*fun_ptr)(void);
struct user_cred {
   char user[8];
   char password[8]; // overwriting past this field overflows directly in loginfunction.
   fun_ptr loginfunc; // field of eight bytes. 
};

void public_function(void){
  printf("Unpriviledged user has logged in\n");
}

void private_function(void){
  printf("Admin has logged in\n");
}

#define MAX_LEN_STR 1024
char line[MAX_LEN_STR];

char *adminpassword = "XYZT";

void show_admin_password(void){
  printf("Admin password is %s\n", adminpassword);
}

int main(){
   /* Normally you wouldn't put a password in plain n'or in a writable section */
   struct user_cred *uc;
   int x = 36;
   fun_ptr publogin = &public_function;

   uc = malloc(sizeof(struct user_cred));

   /* Initialize the structure */
   memset(uc, 0, sizeof(struct user_cred));

   //printf("Public function is x%llx\n", (unsigned long long)publogin);
   
   uc->loginfunc = publogin;
   /* Zero out line to get greeting */
   memset(line, 0 , MAX_LEN_STR*sizeof(char));
   flush_print("Input greeting message:");
   read_line_nonewline(stdin, line, MAX_LEN_STR);
   flush_print("Greeting message is:");
   printf(line);
   printf("\n");

   /* Zero out line to get user */
   memset(line, 0 , MAX_LEN_STR*sizeof(char));
   flush_print("Input user:");
   read_line_nonewline(stdin, line, MAX_LEN_STR);
   /* Not the best way to do this but still safe */
   strncpy(uc->user, line, 7);
   printf("User is %s\n", uc->user);

   /* Zero out line to get password */
   memset(line, 0 , MAX_LEN_STR*sizeof(char));
   flush_print("Input password:");
   read_line_nonewline(stdin, line, MAX_LEN_STR);
   /* Clearly not safe to do this */
   strcpy(uc->password, line);  
   
   if (!strcmp(uc->user, "admin")){
       if (!strcmp(uc->password, adminpassword)){
               uc->loginfunc = &private_function;
       }
       else {
            printf("Error bad admin password\n");
            exit(1);
       }
   } 

   uc->loginfunc();
}
