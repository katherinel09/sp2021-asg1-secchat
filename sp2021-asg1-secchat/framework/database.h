#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

/* Method to create a database */
int create_database();

/* Method to create a table */
int create_table();

// Method to create a new user given a username and password
void create_account_slot(const char *username, const char *password, const char *signature); // create_account_slot()

// Method to authenticate an existing user given their username and password
int authenticate_user(char *username, char *password);

static int callback(void *NotUsed, int argc, char **argv, char **azColName);

