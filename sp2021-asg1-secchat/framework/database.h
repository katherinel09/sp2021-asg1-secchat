#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

struct client_info
{
	char *username;
	char *password;
};

// void new_client(char usrnm, char *pwd)
// {
// 	username -> usrnm;
// }

/* Method to create a database */
int create_database();

/* Method to create a table */
int create_table();

// Method to create a new user given a username and password

// Method to authenticate an existing user given their username and password
int authenticate_user(sqlite3 *db, char *username, char *password);

