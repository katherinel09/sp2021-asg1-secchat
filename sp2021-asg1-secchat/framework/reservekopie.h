/*::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::      Reservekopie van api.c      :::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/

bool checkBoundsValidity(char* input) {
    for(int i = 0; i < READ_SIZE; i++) {
        if(input[i] == NEWLINE) {
            return true;
        }
    }
    return false;
}

void clearStdin() {
    int c = getchar(); 
    while (c != NEWLINE) c = getchar();
}

void getArgument(char* input, struct argument* argument, int argNumber) {
    int length = getArgumentLength(input,argNumber);
    argument->arg = malloc(length);

    int startPoint;

    startPoint = getStartPoint(input,argNumber);

    int j = 0;
    for(int i = startPoint; i < startPoint+length; i++) {
        argument->arg[j] = input[i];
        j++;
    }
}

int getArgumentLength(char* input, int argNumber) {
    int startPoint = getStartPoint(input,argNumber);
    if(startPoint == -1) {
        return startPoint;
    }

    int endPoint = 0;

    for(int i = startPoint+1; i < READ_SIZE; i++) {
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

        for(int i = tempPoint; i < READ_SIZE; i++) {
            if((input[i] != BLANKSPACE) && (input[i] != TAB) && (input[i] != NEWLINE)) {
                startPoint = i;
                tempPoint = i;
                valid = true;
                break;
            }
        }
        for(int i = tempPoint+1; i < READ_SIZE; i++) {
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

/*::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::      Reservekopie van api.h      :::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/

bool checkBoundsValidity(char* input);
void clearStdin();

void getArgument(char* input, struct argument* argument, int argNumber);
int getArgumentLength(char* input, int argNumber);
int getStartPoint(char* input, int argNumber);
