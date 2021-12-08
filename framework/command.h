#ifndef _COMMAND_H_
#define _COMMAND_H_

struct argument{
    int length;
    char* arg;
};

void getCommand(char* input, struct argument* argument);
int getCommandLength(char* input);
int getStartPoint(char* input, int argNumber);



#endif /* defined(_COMMAND_H_) */