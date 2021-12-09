/* Dit is het hoofdbestand string.h */

struct String
{
	int sp;
	int size;
	char *buffer;
};
typedef struct String String;

void newString(String *n, int size)
{
	n -> size = size;
	n -> buffer = (char*) malloc(size*sizeof(char));
	n -> sp = 0;
}

void resetString(String *n)
{
	for(int i = 0; i < n->size; i++) { n -> buffer[i] = '\0'; }
	n -> sp = 0;
}

void verwijderString(String *s) { free(s->buffer); }

void setToSize(String *s, int n_size)
{
	if(n_size == 0) { n_size = 1; }
	char *temp = (char*) malloc(s->size*sizeof(char));
	for(unsigned short int i = 0; i < s->size; i++) { temp[i] = s->buffer[i];}
	free(s->buffer); s->buffer = (char*) malloc(n_size*sizeof(char));
	int t = (s->size > n_size ? n_size : s->size);
	if(t > s->sp) { t = s->sp; }
	for(unsigned short int i = 0; i < t; i++)
	{ s->buffer[i] = temp[i]; }
	free(temp); s->size = n_size;
}

void trim(String *s) { setToSize(s, s->sp); }

void doubleStringSize(String *s)
{
	char *temp = (char*) malloc(s->size*sizeof(char));
	for(unsigned short int i = 0; i < s->size; i++) { temp[i] = s->buffer[i];}
	free(s->buffer); s->size *= 2;
	s->buffer = (char*) malloc(s->size*sizeof(char));
	for(unsigned short int i = 0; i < s->size / 2; i++) { s->buffer[i] = temp[i]; }
	free(temp);
}

void push(String* s, char element)
{
	s -> buffer[s -> sp] = element;
	s -> sp++;
	
	if(s->sp >= s->size) { doubleStringSize(s); }
}

void set(String *s, int i, char c)
{
	if(! (i >= 0 && i < s->sp)) { return; }
	s->buffer[i] = c;
}

char get(String *s, int i)
{
	if(! (i >= 0 && i < s->sp)) { return '\0'; }
	return s->buffer[i];
}

char pop(String* s)
{
	if(s -> sp == 0) { return '\0'; }
	
	s -> sp--;
	char c = s -> buffer[s -> sp];
	s -> buffer[s -> sp] = '\0';
	return c;
}

char* getString(String *s) { return s->buffer; }

void verkrijgInvoer(String *s)
{
	resetString(s);
	char ch = ' ';
	while(ch != '\n')
	{
		ch = getchar();
		push(s, ch);
	}

	trim(s);
	pop(s);
}

void verkrijgArgument(String *invoer, String *verkregenArgument, int argumentNummer)
{
	int argumentTeller = 0;
	resetString(verkregenArgument);
	for(int i = 1; i < invoer->size; i++)
	{
		if(invoer->buffer[i-1] == ' ' || invoer->buffer[i-1] == '\t') { continue; }
		if(argumentTeller == argumentNummer)
			{ push(verkregenArgument, invoer->buffer[i-1]); }
		if(i == invoer->size-1 || invoer->buffer[i] == ' ' || invoer->buffer[i] == '\t') { argumentTeller++; }
	}
	if(invoer->buffer[invoer->size-1] == ' ' || invoer->buffer[invoer->size-1] == '\t')
		{ push(verkregenArgument, invoer->buffer[invoer->size-1]); }
}
