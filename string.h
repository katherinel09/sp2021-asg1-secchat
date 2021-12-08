/* Dit is het hoofdbestand string.h */

struct String
{
	int bladwijzer;
	int grootte;
	char *buffer;
};
typedef struct String String;

void nieuweString(String *n, int grootte)
{
	n -> grootte = grootte;
	n -> buffer = (char*) malloc(grootte*sizeof(char));
	n -> bladwijzer = 0;
}

void herstelString(String *n)
{
	for(int i = 0; i < n->grootte; i++) { n -> buffer[i] = '\0'; }
	n -> bladwijzer = 0;
}

void verwijderString(String *s) { free(s->buffer); }

void wijzigGrootte(String *s, int n_grootte)
{
	if(n_grootte == 0) { n_grootte = 1; }
	char *tijdelijk = (char*) malloc(s->grootte*sizeof(char));
	for(unsigned short int i = 0; i < s->grootte; i++) { tijdelijk[i] = s->buffer[i];}
	free(s->buffer); s->buffer = (char*) malloc(n_grootte*sizeof(char));
	int t = (s->grootte > n_grootte ? n_grootte : s->grootte);
	if(t > s->bladwijzer) { t = s->bladwijzer; }
	for(unsigned short int i = 0; i < t; i++)
	{ s->buffer[i] = tijdelijk[i]; }
	free(tijdelijk); s->grootte = n_grootte;
}

void snoei(String *s) { wijzigGrootte(s, s->bladwijzer); }

void verdubbelStringGrootte(String *s)
{
	char *t = (char*) malloc(s->grootte*sizeof(char));
	for(unsigned short int i = 0; i < s->grootte; i++) { t[i] = s->buffer[i];}
	free(s->buffer); s->grootte *= 2;
	s->buffer = (char*) malloc(s->grootte*sizeof(char));
	for(unsigned short int i = 0; i < s->grootte / 2; i++) { s->buffer[i] = t[i]; }
	free(t);
}

void druk(String* s, char element)
{
	s -> buffer[s -> bladwijzer] = element;
	s -> bladwijzer++;
	
	if(s->bladwijzer >= s->grootte) { verdubbelStringGrootte(s); }
}

void wijzig(String *s, int i, char c)
{
	if(! (i >= 0 && i < s->bladwijzer)) { return; }
	s->buffer[i] = c;
}

char verkrijg(String *s, int i)
{
	if(! (i >= 0 && i < s->bladwijzer)) { return '\0'; }
	return s->buffer[i];
}

char knal(String* s)
{
	if(s -> bladwijzer == 0) { return '\0'; }
	
	s -> bladwijzer--;
	char c = s -> buffer[s -> bladwijzer];
	s -> buffer[s -> bladwijzer] = '\0';
	return c;
}

char* verkrijgString(String *s) { return s->buffer; }

void verkrijgInvoer(String *s)
{
	herstelString(s);
	char ch = ' ';
	while(ch != '\n')
	{
		ch = getchar();
		druk(s, ch);
	}

	snoei(s);
	knal(s);
}

void verkrijgWoord(String *s, String *verkregenWoord, int woordNummer)
{
	int woordenteller = 0;
	herstelString(verkregenWoord);
	for(int i = 1; i < s->grootte; i++)
	{
		if(s->buffer[i-1] == ' ' || s->buffer[i-1] == '\t') { continue; }
		if(woordenteller == woordNummer)
			{ druk(verkregenWoord, s->buffer[i-1]); }
		if(i == s->grootte-1 || s->buffer[i] == ' ' || s->buffer[i] == '\t') { woordenteller++; }
	}
	if(s->buffer[s->grootte-1] == ' ' || s->buffer[s->grootte-1] == '\t')
		{ druk(verkregenWoord, s->buffer[s->grootte-1]); }
}

int woordenTeller(String *s)
{
	int woordenteller = 0;
	for(int i = 1; i < s->grootte; i++)
	{
		if(s->buffer[i-1] == ' ' || s->buffer[i-1] == '\t') { continue; }
		if(i == s->grootte-1 || s->buffer[i] == ' ' || s->buffer[i] == '\t') { woordenteller++; }
	}
	return woordenteller;
}

void geefBlok(String *s, String *blok, int blokGrootte, int blokNummer)
{
	if(blokNummer < 0) { blokNummer *= -1; }
	if(blokGrootte < 0) { blokGrootte *= -1; }
	if(blokGrootte == 0) { return; }
	
	int begin = blokGrootte * blokNummer;
	int eind = begin + blokGrootte;
	
	if(begin >= s->grootte) { return; }
	if(eind >= s->grootte) { eind = s->grootte - 1; }
	
	herstelString(blok);
	for(int i = begin; i < eind; i++) { druk(blok, s->buffer[i]); }
	snoei(blok);
}

void geefDeelString(String *s, String *deel, int begin, int eind)
{
	if(eind > begin) { int t = begin; begin = eind; eind = t; }
	if(begin >= s->grootte) { return; }
	if(eind >= s->grootte) { eind = s->grootte - 1; }
	
	herstelString(deel);
	for(int i = begin; i <= eind; i++) { druk(deel, s->buffer[i]); }
}
