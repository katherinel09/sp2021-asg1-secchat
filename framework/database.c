// #include "sqlite3.h"
// #include <stdio.h>

// #include <assert.h>
// #include <errno.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <sqlite3.h>
// #include <stdio.h>

// #include "api.h"
// #include "ui.h"
// #include "util.h"
// #include "string.h"
// //#include "database.h"

// #define DATABASE "users.db"

// /* Main method */
// int main()
// {
// 	char *kat = "kat";
// 	char *katkat = "katkat";
// 	int signature = 120900;
// 	create_database();
// 	create_table();
// 	create_account_slot(kat, katkat, signature);
// 	create_table_log();
// 	querey_database_for_username(kat, katkat);
// }

// /* Method to create a database */
// int create_database()
// {
// 	sqlite3 *db;
// 	int ressy = 0;

// 	// Create the data base
// 	ressy = sqlite3_open(DATABASE, &db);

// 	sqlite3_close(db);

// 	return ressy;
// }

// /* Method to create a database of the users*/
// int create_table()
// {
// 	sqlite3 *db;
// 	int ressy = 0;
// 	ressy = sqlite3_open(DATABASE, &db);

// 	const char sql1[5000] = "CREATE TABLE PERSON("

// 							"USERNAME 		TEXT	NOT NULL, "
// 							"PASSWORD			TEXT    NOT NULL, "
// 							"STATUS           TEXT    NOT NULL, "
// 							"SIGNATURE        INT 	NOT NULL, "
// 							"PRIMARY KEY (USERNAME) );";

// 	ressy = sqlite3_exec(db, sql1, NULL, 0, NULL);
// 	sqlite3_close(db);
// 	return ressy;
// }

// // Method to create the documentation & list of fields (message table (sender, recipient, other important things))
// int create_table_log()
// {
// 	sqlite3 *db2;
// 	int ressy = 0;
// 	ressy = sqlite3_open(DATABASE, &db2);

// 	const char sql1[5000] = "CREATE TABLE MESSAGES("

// 							"RECIPIENT			TEXT	NOT NULL, "
// 							"SENDER				TEXT    NOT NULL, "
// 							"MESSAGE			TEXT    NOT NULL, "
// 							"CERTIFICATE        TEXT 	NOT NULL, "
// 							"PRIMARY KEY (CERTIFICATE) );";

// 	ressy = sqlite3_exec(db2, sql1, NULL, 0, NULL);
// 	sqlite3_close(db2);
// 	return ressy;
// }

// // Method to create a new user message in the log
// void create_message(const char *username, const char *recipient, const char *message)
// {
// 	sqlite3 *db;
// 	int ressy = sqlite3_open("users.db", &db);

// 	// Otherwise, add them to the database
// 	char const *initial2 = "INSERT INTO MESSAGES (RECIPIENT, SENDER, MESSAGE, CERTIFICATE) VALUES('";
// 	char const *rest = "', '";

// 	char const *formatting2 = "CERTIFICATE');";

// 	char *full_command;
// 	full_command = malloc(500 + strlen(initial2) + strlen(username) + strlen(recipient) + strlen(message) + 2 * strlen(rest) + 1 + 4);
// 	strcat(full_command, initial2);
// 	strcat(full_command, recipient);
// 	strcat(full_command, rest);
// 	strcat(full_command, username);
// 	strcat(full_command, rest);
// 	strcat(full_command, message);
// 	strcat(full_command, rest);
// 	strcat(full_command, formatting2);

// 	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);
// 	sqlite3_close(db);
// 	free(full_command);
// }

// /*
//  * is called by sqlite3_exec() to print db tables or elements.
//  * use sqlite3_get_table() as an alternative if you wish to retrieve
//  * data, as opposed to just printing it.
//  */
// // static int callback(int argc, char **argv, char **col)
// // {
// // 	int i;
// // 	return 0;
// // }

// // On registration, put in everything right away (name, password, status, certificates)
// // Have an sql file, with a bunch of creates that set up the properties of the table
// // Accounts table, message log table, sessions table (keep track of time)
// // create table if not exists, primary key, etc, look for documentation & list of fields (message table (sender, recipient, other important things))
// // name type name type (text is text, signature usignt)
// void create_account_slot(const char *username, const char *password, const char *signature)
// {
// 	// const char *username, const char *password
// 	sqlite3 *db;
// 	int ressy = sqlite3_open("users.db", &db);

// 	if (ressy != SQLITE_OK)
// 	{
// 		printf("There was an issue connecting to SQLLite3\n");
// 		exit(-1);
// 	}

// 	// Otherwise, add them to the database
// 	char const *initial2 = "INSERT OR IGNORE INTO PERSON (USERNAME, PASSWORD, STATUS, SIGNATURE) VALUES('";
// 	char const *rest = "', 'ONLINE', '";
// 	char const *formatting = "', '";
// 	char const *formatting2 = "');";

// 	char *full_command;
// 	full_command = malloc(500 + strlen(initial2) + strlen(username) + strlen(username) + strlen(password) + strlen(rest) + 1 + 4);
// 	strcat(full_command, initial2);
// 	strcat(full_command, username);
// 	strcat(full_command, formatting);
// 	strcat(full_command, password);
// 	strcat(full_command, rest);
// 	strcat(full_command, signature);
// 	strcat(full_command, formatting2);

// 	ressy = sqlite3_exec(db, full_command, NULL, 0, NULL);
// 	querey_database_for_username(username, password);

// 	sqlite3_close(db);
// 	free(full_command);
// }

// // Determine if a user exists
// int authenticate_user(char *username, char *password)
// {
// 	sqlite3 *db;
// 	int ressy = sqlite3_open("users.db", &db);

// 	char user_table[500];
// 	sqlite3_stmt *stmt;

// 	// int bad_char_index = 0;
// 	if ((strchr(username, '\'') != NULL) || (strchr(password, '\'') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include single quote");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '<') != NULL) || (strchr(password, '<') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include < or >");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '>') != NULL) || (strchr(password, '>') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include < or >");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '\"') != NULL) || (strchr(password, '\"') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include &");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '\\') != NULL) || (strchr(password, '\\') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include \\");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '%') != NULL) || (strchr(password, '%') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include the percent symbol");
// 		exit(-1);
// 	}
// 	else if ((strchr(username, '#') != NULL) || (strchr(password, '#') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include #");
// 		exit(-1);
// 	}

// 	else if ((strchr(username, '?') != NULL) || (strchr(password, '?') != NULL))
// 	{
// 		printf("Bad characters in the username or password. Do not include ?");
// 		exit(-1);
// 	}

// 	else if ((sizeof(username) > 20) || sizeof(password) > 20)
// 	{
// 		printf("Length of username or password too long. Please type less than 20 characters");
// 		exit(-1);
// 	}

// 	/* build query */
// 	sprintf(user_table, "IF EXISTS (SELECT * FROM USERNAME WHERE USERNAME='%s' "
// 						"AND pwd='%s')",
// 			username, password);

// 	ressy = sqlite3_prepare_v2(db, user_table, -1, &stmt, NULL);
// 	ressy = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
// 	ressy = sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

// 	sqlite3_finalize(stmt);
// 	return ressy;
// }

// void login(int fd)
// {
// 	sqlite3 *db;
// 	int ressy = sqlite3_open("users.db", &db);
// 	// flag = 0;
// 	if (ressy != SQLITE_OK)
// 	{
// 		printf("There was an error connecting to SQLLite3");
// 		exit(-1);
// 	}

// 	ressy = sqlite3_open("users.db", &db);

// 	char *query_results;
// 	query_results = "SELECT * FROM USERNAME";
// 	ressy = sqlite3_exec(db, query_results, NULL, 0, NULL);

// 	sqlite3_close(db);

// 	// ressy = sqlite3_exec(db, usertable, login_callback_function, &fd, NULL);
// 	sqlite3_close(db);
// }

// int login_callback_function(int column_count, char **column_value, char **column_name)
// {
// 	sqlite3 *db;

// 	int ressy = sqlite3_open("users.db", &db);

// 	if (ressy != SQLITE_OK)
// 	{
// 		printf("There was an error connecting to SQLLite3");
// 		exit(-1);
// 	}
// 	if (column_value[0] != NULL && column_value[1] != NULL)
// 	{
// 		char user_table[128] = {0};
// 		ressy = sqlite3_exec(db, user_table, NULL, NULL, NULL);
// 	}

// 	sqlite3_close(db);
// 	return 0;
// }

// int querey_database_for_username(const char *username, const char *password)
// {
// 	// start up the database
// 	sqlite3 *db;
// 	int ressy;

// 	ressy = sqlite3_open(STDIN_FILENO, &db);

// 	if (ressy != SQLITE_OK)
// 	{

// 		fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
// 		sqlite3_close(db);
// 		return 1;
// 	}
// 	else
// 	{
// 		// prepare because you have to!
// 		sqlite3 *db;
// 		ressy = sqlite3_open("users.db", &db);

// 		char user_table[500];
// 		sqlite3_stmt *stmt;

// 		/* build query */
// 		sprintf(user_table, "IF EXISTS (SELECT * FROM USERNAME WHERE USERNAME='%s' "
// 							"AND pwd='%s')",
// 				username, password);

// 		ressy = sqlite3_prepare_v2(db, user_table, -1, &stmt, NULL);
// 		ressy = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
// 		ressy = sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

// 		sqlite3_finalize(stmt);

// 		return 1;
// 	}

// 	return 0;
// }
