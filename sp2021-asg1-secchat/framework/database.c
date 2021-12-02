#include "sqlite3.h"
#include <stdio.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <stdio.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "string.h"
#include "database.h"

#define DATABASE "users.db"

/* Main method */
int main()
{
	char *kat = "kat";
	char *katkat = "katkat";
	create_database();
	create_table();
	create_account_slot(kat, katkat);
}

/* Method to create a database */
int create_database() {
	sqlite3 *db;
	int ressy = 0;
	//sqlite3_stmt *statement;

	// Create the data base
	ressy = sqlite3_open(DATABASE, &db);

	sqlite3_close(db);

	return ressy;
}

/* Method to create a database */
int create_table() {
	sqlite3 *db;
	int ressy = 0;
	ressy = sqlite3_open(DATABASE, &db);


	const char sql1[5000] = "CREATE TABLE PERSON("
                      
                      "USERNAME          TEXT    NOT NULL, "
                      "PASSWORD          TEXT     NOT NULL, "
                      "STATUS            TEXT     NOT NULL, "
                      "SIGNATURE         INT 	NOT NULL);";

	// CONSTRAINT USERID PRIMARY KEY (USERNAME)
	//"ID INT PRIMARY KEY     NOT NULL, "
	ressy = sqlite3_exec(db, sql1, NULL, 0, NULL);

	sqlite3_close(db);

	return ressy;
}

// On registration, put in everything right away (name, password, status, certificates)
// Have an sql file, with a bunch of creates that set up the properties of the table
// Accounts table, message log table, sessions table (keep track of time)
// create table if not exists, primary key, etc, look for documentation & list of fields (message table (sender, recipient, other important things))
// name type name type (text is text, signature usignt)
void create_account_slot(const char *username, const char *password)
{
	// const char *username, const char *password
	sqlite3 *db;
	int ressy = sqlite3_open("users.db", &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3\n");
		exit(-1);
	}

	//char usr[5000]; 
    // if (usr == NULL) {
    //     printf("There was an issue allocating memory\n");
    //     exit(1);
    // }

    // Place data into memory and print.

    // strcpy(usr, "INSERT INTO PERSON (USERNAME, PASSWORD, STATUS, SIGNATURE) VALUES('");
    // strcat(usr, "AKAKA");
	// strcat(usr, "', '");
	// strcat(usr, "KATKAT");
	// strcat(usr, "'COOLIO', '98765');");
    //printf("User: %s\n", buff);

    // Free memory and return.




	const char usr[5000] = "INSERT INTO PERSON (USERNAME, PASSWORD, STATUS, SIGNATURE) VALUES('KATHERINELASONDE', 'PWDDDD', 'COOLIO', '98765');";

	
	// "
	// 	(INSERT INTO PERSON 
	// 		(ID, USERNAME, PASSWORD, STATUS, SIGNATURE) 
	// 	VALUES
	// 		('2023', 'KATHERINELASONDE', 'PWDDDD', 'COOLIO', '98765');");

	ressy = sqlite3_exec(db, usr, NULL, 0, NULL);

	//if (ressy != SQLITE_OK)
	// {
	// 	printf("There is an error creating your new user slot");
	// 	exit(1);
	// }
	sqlite3_close(db);

	//free(usr);
}


int authenticate_user(sqlite3 *db, char *username, char *password)
{
	int found, ressy;
	char user_table[500];
	sqlite3_stmt *stmt;

	// TODO properly  allocate
	char *usrnm = username;
	char *pwd = password;

	//int bad_char_index = 0;
	if ((strchr(usrnm, '\'') != NULL) || (strchr(pwd, '\'') != NULL))
	{
		printf("Bad characters in the username or password. Do not include single quote");
		exit(-1);
	}
	else if ((strchr(usrnm, '<') != NULL) || (strchr(pwd, '<') != NULL))
	{
		printf("Bad characters in the username or password. Do not include < or >");
		exit(-1);
	}
	else if ((strchr(usrnm, '>') != NULL) || (strchr(pwd, '>') != NULL))
	{
		printf("Bad characters in the username or password. Do not include < or >");
		exit(-1);
	}
	else if ((strchr(usrnm, '\"') != NULL) || (strchr(pwd, '\"') != NULL))
	{
		printf("Bad characters in the username or password. Do not include &");
		exit(-1);
	}
	else if ((strchr(usrnm, '\\') != NULL) || (strchr(pwd, '\\') != NULL))
	{
		printf("Bad characters in the username or password. Do not include \\");
		exit(-1);
	}
	else if ((strchr(usrnm, '%') != NULL) || (strchr(pwd, '%') != NULL))
	{
		printf("Bad characters in the username or password. Do not include the percent symbol");
		exit(-1);
	}
	else if ((strchr(usrnm, '#') != NULL) || (strchr(pwd, '#') != NULL))
	{
		printf("Bad characters in the username or password. Do not include #");
		exit(-1);
	}

	else if ((strchr(usrnm, '?') != NULL) || (strchr(pwd, '?') != NULL))
	{
		printf("Bad characters in the username or password. Do not include ?");
		exit(-1);
	}

	else if ((sizeof(username) > 20) || sizeof(password) > 20)
	{
		printf("Length of username or password too long. Please type less than 20 characters");
		exit(-1);
	}

	/* build query */
	sprintf(user_table, "SELECT userid "
						"FROM user WHERE name='%s' "
						"AND pwd='%s'",
			username, password);

	ressy = sqlite3_prepare_v2(db, user_table, -1, &stmt, NULL);

	if (ressy != SQLITE_OK)
	{
		printf("There was an issue connecting to SQLLite3");
		exit(-1);
	}

	/* execute query */
	switch (sqlite3_step(stmt))
	{
	case SQLITE_DONE:
		found = 0;
		break;
	case SQLITE_ROW:
		found = 1;
		break;
	}

	ressy = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	ressy = sqlite3_bind_text(stmt, 2, pwd, -1, SQLITE_STATIC);

	sqlite3_finalize(stmt);

	fprintf(stderr, "db error: %s\n",
			sqlite3_errmsg(db));
	if (stmt)
		sqlite3_finalize(stmt);
	return -1;
}

//int get_pwd_with_db(sqlite3 *db, const char *name, char **pwd_p)
//{
	//sqlite3_stmt *stmt;
	//*pwd_p = NULL;
	//*pwd_p = strdup((char *)sqlite3_column_text(stmt, 0));
	//return 0;
//}


int get_pwd(char *dbpath, char *name, char **pwd_p)
{
	sqlite3 *db;
	int r;
	
	
	/* open database */
	r = sqlite3_open(dbpath, &db);
	if (r != SQLITE_OK)
	{
		//fprintf(stderr, "open database %s "
		//				"failed: %s\n",
		//		sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	// /* perform query */
	// if (get_pwd_with_db(
	// 		db, name, pwd_p) != 0)
	// {
	// 	sqlite3_close(db);
	// 	return -1;
	// }
	/* clean up */
	sqlite3_close(db);
	return 0;
}

void login(int fd)
{
	sqlite3 *db;
	int ressy = sqlite3_open("users.db", &db);
	// flag = 0;
	if (ressy != SQLITE_OK)
	{
		printf("There was an error connecting to SQLLite3");
		exit(-1);
	}

	//char usertable[500] = {0};

	//char *usrnm = client->username;

	// db.username = username_from_db;
	// db.password = password_from_db;

	ressy = sqlite3_open("users.db", &db);

	char *query_results;
	query_results = "SELECT * FROM USERNAME";
	ressy = sqlite3_exec(db, query_results, NULL, 0, NULL);

	sqlite3_close(db);

	// ressy = sqlite3_exec(db, usertable, login_callback_function, &fd, NULL);
	sqlite3_close(db);
}

int login_callback_function(int column_count, char **column_value, char **column_name)
{
	sqlite3 *db;

	int ressy = sqlite3_open("users.db", &db);

	if (ressy != SQLITE_OK)
	{
		printf("There was an error connecting to SQLLite3");
		exit(-1);
	}
	if (column_value[0] != NULL && column_value[1] != NULL)
	{
		char user_table[128] = {0};
		// char user_table2[128] = {0};
		// strcpy(user_table2, column_value);

		ressy = sqlite3_exec(db, user_table, NULL, NULL, NULL);
	}

	sqlite3_close(db);
	return 0;
}


// void register_new_user(int fd, struct client_info *client)
// {
// 	sqlite3 *db;
// 	int ressy = sqlite3_open("users.db", &db);

// 	if (ressy != SQLITE_OK)
// 	{
// 		printf("There was an error connecting to SQLLite3");
// 	}

// 	char *usertable[128] = {0};

// 	sprintf(usertable, "Please enter a password!,'%s'", *client->password);
// 	ressy = sqlite3_exec(db, usertable, NULL, NULL, NULL);

// 	if (ressy != SQLITE_OK)
// 	{
// 		printf("There was an issue making your password");
// 	}

// 	sqlite3_close(db);
// }

// void register_new_user(int fd, struct client_info *client)
// {
// 	int fd2, r;
// 	fd_set readfds;

// 	// username
// 	char *username = (char *)malloc(20 * sizeof(char));

// 	// ask user for input username
// 	printf("Please enter a username to login or to register (less than 20 characters.)");

// 	/* wait for a file descriptor */
// 	FD_ZERO(&readfds);
// 	FD_SET(STDIN_FILENO, &readfds);
// 	FD_SET(&client, &readfds);

// 	// intialize fd2
// 	fd2 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client;

// 	// handle the user input
// 	if (FD_ISSET(STDIN_FILENO, &readfds))
// 	{
// 		handle_user_input();
// 	}
// 	if (FD_ISSET(&client, &readfds))
// 	{
// 		username = handle_socket_input(&client);
// 	}

// 	// check if the username is already in the database
// 	// prepare the database
// 	int ressy;
// 	ressy = query_database_for_username(username);

// 	int ressy2;

// 	if (ressy)
// 	{
// 		ressy2 = ask_user_for_password(*username, &client);
// 	}
// 	else
// 	{
// 		ressy2 = set_new_user_password(*username, &client);
// 	}

// }

// static int querey_database_for_username(char *username, struct client_info *client)
// {
// 	// start up the database
// 	sqlite3 *db;
// 	sqlite3_stmt *usrnm = *username;

// 	int new_q = sqlite3_open(STDIN_FILENO, &db);

// 	if (new_q != SQLITE_OK)
// 	{

// 		fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
// 		sqlite3_close(db);
// 		return 1;
// 	}
// 	else
// 	{
// 		// prepare because you have to!
// 		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);

// 		if (new_q != SQLITE_OK)
// 		{
// 			fprintf(stderr, "Failed to prepare data");
// 			sqlite3_close(db);
// 			return 1;
// 		}
// 	}

// 	// now step with the username
// 	new_q = sqlite3_step(usrnm);

// 	if (new_q == SQLITE_ROW)
// 	{
// 		printf("Welcome! Please enter your passcode to continue.");

// 		sqlite3_finalize(usrnm);
// 		sqlite3_close(db);

// 		return 0;
// 	}
// 	else
// 	{
// 		printf("Welcome new user! Please enter your passcode to complete your registration.");

// 		sqlite3_finalize(usrnm);
// 		sqlite3_close(db);

// 		return 1;
// 	}
// }

// int ask_user_for_password(char *username, struct client_info *client)
// {
// 	// username
// 	char *password = (char *)malloc(20 * sizeof(password));
// 	fd_set readfds;
// 	int fd3;

// 	// ask user for input username
// 	printf("Please enter your password");

// 	/* wait for a file descriptor */
// 	FD_ZERO(&readfds);
// 	FD_SET(STDIN_FILENO, &readfds);
// 	FD_SET(&client, &readfds);

// 	// start up the database
// 	sqlite3 *db;
// 	sqlite3_stmt *usrnm = *username;

// 	int new_q = sqlite3_open(STDIN_FILENO, &db);

// 	if (new_q != SQLITE_OK)
// 	{

// 		fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
// 		sqlite3_close(db);
// 		return 1;
// 	}
// 	else
// 	{
// 		// prepare because you have to!
// 		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);

// 		if (new_q != SQLITE_OK)
// 		{
// 			fprintf(stderr, "Failed to prepare data");
// 			sqlite3_close(db);
// 			return 1;
// 		}
// 	}

// 	// now step with the username
// 	new_q = sqlite3_step(usrnm);

// 	if (new_q == SQLITE_ROW)
// 	{
// 		printf("Welcome! Please enter your passcode to continue.");

// 		// intialize fd3
// 		fd3 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client;

// 		// handle the user input
// 		if (FD_ISSET(STDIN_FILENO, &readfds))
// 		{
// 			handle_user_input();
// 		}
// 		if (FD_ISSET(&client, &readfds))
// 		{
// 			password = handle_socket_input(&client);
// 		}

// 		sqlite3_finalize(usrnm);
// 		sqlite3_close(db);
// 	}

// 	// now step with the username
// 	new_q = sqlite3_step(password);

// 	if (new_q == SQLITE_ROW)
// 	{
// 		printf("Welcome! You have successfully logged in.");

// 		sqlite3_finalize(password);
// 		sqlite3_close(db);
// 		return 0;
// 	}
// 	else
// 	{
// 		printf("Incorrect password. Try again");
// 		return 1;
// 	}
// }

// static int set_new_user_password(char *username, struct client_info *client)
// {
// 	// username
// 	char *password = (char *)malloc(20 * sizeof(password));
// 	fd_set readfds;
// 	int fd3;

// 	// ask user for input username
// 	printf("Please enter your password");

// 	/* wait for a file descriptor */
// 	FD_ZERO(&readfds);
// 	FD_SET(STDIN_FILENO, &readfds);
// 	FD_SET(&client, &readfds);

// 	// start up the database
// 	sqlite3 *db;
// 	sqlite3_stmt *usrnm = *username;

// 	int new_q = sqlite3_open(STDIN_FILENO, &db);

// 	if (new_q != SQLITE_OK)
// 	{

// 		fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
// 		sqlite3_close(db);
// 		return 1;
// 	}
// 	else
// 	{
// 		// prepare because you have to!
// 		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);

// 		if (new_q != SQLITE_OK)
// 		{
// 			fprintf(stderr, "Failed to prepare data");
// 			sqlite3_close(db);
// 			return 1;
// 		}
// 	}

// 	// now step with the username
// 	new_q = sqlite3_step(usrnm);

// 	if (new_q == SQLITE_ROW)
// 	{
// 		printf("Welcome! Please enter your passcode to continue.");

// 		// intialize fd3
// 		fd3 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client;

// 		// handle the user input
// 		if (FD_ISSET(STDIN_FILENO, &readfds))
// 		{
// 			handle_user_input();
// 		}
// 		if (FD_ISSET(&client, &readfds))
// 		{
// 			password = handle_socket_input(&client);
// 		}

// 		sqlite3_finalize(usrnm);
// 		sqlite3_close(db);
// 		return 0;
// 	}
// 	else
// 	{
// 		printf("Failed to assign you a password password. Try again");
// 		return 1;
// 	}
// }
