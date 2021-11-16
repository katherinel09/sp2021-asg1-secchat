#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "command.h"

#define BLANKSPACE 32
#define TAB 9
#define NEWLINE 10

void getCommand(char* input, struct argument* argument) {
    int length = getCommandLength(input);
    argument->arg = malloc(length);

    int startPoint;

    startPoint = getStartPoint(input,1);

    int j = 0;
    for(int i = startPoint; i < startPoint+length; i++) {
        argument->arg[j] = input[i];
        j++;
    }
}

int getCommandLength(char* input) {
    int startPoint = -1;
    int endPoint = 0;

    for(int i = 0; i < 100; i++) {
        if((input[i] != BLANKSPACE) && (input[i] != TAB) && (input[i] != NEWLINE)) {
            startPoint = i;
            break;
        }
    }

    if(startPoint == -1) {
        return startPoint;
    }

    for(int i = startPoint+1; i < 100; i++) {
        if((input[i] == BLANKSPACE) || (input[i] == TAB) || (input[i] == NEWLINE)) {
            endPoint = i;
            break;
        }
    }
    
    int size = endPoint - startPoint;
    return size;
}

int getStartPoint(char* input, int argNumber) {
    int startPoint = 0;
    int tempPoint = 0;
    bool valid = false;
    
    for(int j = 0; j < argNumber; j++) {
        valid = false;

        for(int i = tempPoint; i < 100; i++) {
            if((input[i] != BLANKSPACE) && (input[i] != TAB) && (input[i] != NEWLINE)) {
                startPoint = i;
                tempPoint = i;
                valid = true;
                break;
            }
        }
        for(int i = tempPoint+1; i < 100; i++) {
            if((input[i] == BLANKSPACE) || (input[i] == TAB) || (input[i] == NEWLINE)) {
                tempPoint = i;
                break;
            }
        }
    }

    if(valid) {
        return startPoint;
    }
    else {
        return -1;
    }
}
