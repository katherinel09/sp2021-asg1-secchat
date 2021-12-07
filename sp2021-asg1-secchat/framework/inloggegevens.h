/* Dit is het hoofdbestand inloggegevens.h */

struct Login
{
	char *gebruikersnaam;
	char *wachtwoord;
	int bestandsbeschrijver;
	int gebruikersnaamGROOTTE;
	int wachtwoordGROOTTE;
};
typedef struct Login Login;

void nieuweLogin(Login *n, char* GN, int grootteGN, char* WW, int grootteWW, int bb)
{
	n -> gebruikersnaamGROOTTE = grootteGN;
	n -> wachtwoordGROOTTE = grootteWW;
	n -> gebruikersnaam = (char*) malloc(grootteGN*sizeof(char));
	n -> wachtwoord = (char*) malloc(grootteWW*sizeof(char));
	n -> bestandsbeschrijver = bb;
	
	for(int i = 0; i < grootteGN; i++) { n->gebruikersnaam[i] = GN[i]; }
	for(int i = 0; i < grootteWW; i++) { n->wachtwoord[i] = WW[i]; }
}

void herstelLogin(Login *n)
{
	for(int i = 0; i < n->gebruikersnaamGROOTTE; i++)
		{ n -> gebruikersnaam[i] = '\0'; }
	for(int i = 0; i < n->wachtwoordGROOTTE; i++)
		{ n -> wachtwoord[i] = '\0'; }
	n -> bestandsbeschrijver = -1;
}

void verwijderLogin(Login *s)
	{ free(s->gebruikersnaam); free(s->wachtwoord); }

void wijzigGrootteGN(Login *s, int n_grootte)
{
	if(n_grootte == 0) { n_grootte = 1; }
	char *tijdelijk = (char*) malloc(s->gebruikersnaamGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->gebruikersnaamGROOTTE; i++) { tijdelijk[i] = s->gebruikersnaam[i];}
	free(s->gebruikersnaam); s->gebruikersnaam = (char*) malloc(n_grootte*sizeof(char));
	int t = (s->gebruikersnaamGROOTTE > n_grootte ? n_grootte : s->gebruikersnaamGROOTTE);
	for(unsigned short int i = 0; i < t; i++)
	{ s->gebruikersnaam[i] = tijdelijk[i]; }
	free(tijdelijk); s->gebruikersnaamGROOTTE = n_grootte;
}

void wijzigGrootteWW(Login *s, int n_grootte)
{
	if(n_grootte == 0) { n_grootte = 1; }
	char *tijdelijk = (char*) malloc(s->wachtwoordGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->wachtwoordGROOTTE; i++) { tijdelijk[i] = s->wachtwoord[i];}
	free(s->wachtwoord); s->wachtwoord = (char*) malloc(n_grootte*sizeof(char));
	int t = (s->wachtwoordGROOTTE > n_grootte ? n_grootte : s->wachtwoordGROOTTE);
	for(unsigned short int i = 0; i < t; i++)
	{ s->wachtwoord[i] = tijdelijk[i]; }
	free(tijdelijk); s->wachtwoordGROOTTE = n_grootte;
}

void snoeiGN(Login *s) { wijzigGrootteGN(s, s->gebruikersnaamGROOTTE); }
void snoeiWW(Login *s) { wijzigGrootteWW(s, s->wachtwoordGROOTTE); }

void verdubbelGNGrootte(Login *s)
{
	char *t = (char*) malloc(s->gebruikersnaamGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->gebruikersnaamGROOTTE; i++) { t[i] = s->gebruikersnaam[i];}
	free(s->gebruikersnaam); s->gebruikersnaamGROOTTE *= 2;
	s->gebruikersnaam = (char*) malloc(s->gebruikersnaamGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->gebruikersnaamGROOTTE / 2; i++) { s->gebruikersnaam[i] = t[i]; }
	free(t);
}

void verdubbelWWGrootte(Login *s)
{
	char *t = (char*) malloc(s->wachtwoordGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->wachtwoordGROOTTE; i++) { t[i] = s->wachtwoord[i];}
	free(s->wachtwoord); s->wachtwoordGROOTTE *= 2;
	s->wachtwoord = (char*) malloc(s->wachtwoordGROOTTE*sizeof(char));
	for(unsigned short int i = 0; i < s->wachtwoordGROOTTE / 2; i++) { s->wachtwoord[i] = t[i]; }
	free(t);
}
