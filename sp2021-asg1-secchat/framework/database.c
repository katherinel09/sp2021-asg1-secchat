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

struct client_info
{
    char *username;
    char *password;
};

// creates the database!
int main()
{
    sqlite3 *db;
    sqlite3_stmt *statement;

    // Create the data base
    sqlite3_open("SP_DB.db", &db);
}

void create_account_slot()
{
    sqlite3 *db;
    int ressy = sqlite3_open("users.db", &db);

    if (ressy != SQLITE_OK)
    {
        printf("There was an issue connecting to SQLLite3");
        exit(-1);
    }

    printf("Hi, please enter a user name and password less than 20 characters");

    char new_user[500] = {0};

    

    ressy = sqlite3_exec(db, *new_user, NULL, NULL, NULL);
    if (ressy != SQLITE_OK)
    {
        printf("There is an error creating your new user slot");
        exit(1);
    }
    sqlite3_close(db);
}

void login(int fd, struct client_info *client)
{
    sqlite3 *db;
    int ressy = sqlite3_open("users.db", &db);
    // flag = 0;
    if (ressy != SQLITE_OK)
    {
        printf("There was an error connecting to SQLLite3");
        exit(-1);
    }

    char usertable[500] = {0};

    char *usrnm = client->username;

    
    //db.username = username_from_db;
    //db.password = password_from_db;
    
    ressy = sqlite3_open("users.db", &db);

    char *query_results;
    query_results = "SELECT * FROM USERNAME";
    ressy = sqlite3_exec(db, query_results, NULL, 0, NULL);

    sqlite3_close(db);

    //ressy = sqlite3_exec(db, usertable, login_callback_function, &fd, NULL);    
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

void register_new_user(int fd, struct client_info *client)
{
    sqlite3 *db;
    int ressy = sqlite3_open("users.db", &db);

    if (ressy != SQLITE_OK)
    {
        printf("There was an error connecting to SQLLite3");
    }

    char usertable[128] = {0};

    sprintf(usertable, "Please enter a password!,'%s'", *client->password);
    ressy = sqlite3_exec(db, usertable, NULL, NULL, NULL);

    if (ressy != SQLITE_OK)
    {
        printf("There was an issue making your password");
    }

    sqlite3_close(db);
}



void register_new_user(int fd, struct client_info *client) {
    int fd2, r;
	fd_set readfds;

	// username
	char *username = (char *)malloc(20 * sizeof(char));

	// ask user for input username
	printf("Please enter a username to login or to register (less than 20 characters.)");

	/* wait for a file descriptor */
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	FD_SET(&client, &readfds);

	// intialize fd2
	fd2 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client ; 

	// handle the user input
	if(FD_ISSET(STDIN_FILENO, &readfds)){
		handle_user_input();
	}
	if(FD_ISSET(&client, &readfds)) {
		username = handle_socket_input(&client);
	}

	// check if the username is already in the database
	// prepare the database
	int ressy;
	ressy = query_database_for_username(username);

	int ressy2; 

	if (ressy) {
		ressy2 = ask_user_for_password(*username, &client);
	}
	else {
		ressy2 = set_new_user_password(*username, &client);
	}

	return fd;
}

static int querey_database_for_username(char *username, struct client_info *client){
	// start up the database
	sqlite3 *db;
    sqlite3_stmt *usrnm = *username;

	int new_q = sqlite3_open(STDIN_FILENO, &db);


	if (new_q != SQLITE_OK) {
        
        fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
        sqlite3_close(db);
        return 1;
    }
	else {
		// prepare because you have to!
		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);  
		
		if (new_q != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare data");
			sqlite3_close(db);
			return 1;
		}    
	}

	// now step with the username
	new_q = sqlite3_step(usrnm);
    
    if (new_q == SQLITE_ROW) {
        printf("Welcome! Please enter your passcode to continue.");

		sqlite3_finalize(usrnm);
		sqlite3_close(db);
		
		return 0;
    }
	else {
		printf("Welcome new user! Please enter your passcode to complete your registration.");

		sqlite3_finalize(usrnm);
		sqlite3_close(db);
		
		return 1;

	}
}

int ask_user_for_password(char *username, struct client_info *client) {
	// username
	char *password = (char *)malloc(20 * sizeof(password));
	fd_set readfds;
	int fd3;

	// ask user for input username
	printf("Please enter your password");

	/* wait for a file descriptor */
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	FD_SET(&client, &readfds);

	// start up the database
	sqlite3 *db;
    sqlite3_stmt *usrnm = *username;

	int new_q = sqlite3_open(STDIN_FILENO, &db);


	if (new_q != SQLITE_OK) {
        
        fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
        sqlite3_close(db);
        return 1;
    }
	else {
		// prepare because you have to!
		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);  
		
		if (new_q != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare data");
			sqlite3_close(db);
			return 1;
		}    
	}

	//now step with the username
	new_q = sqlite3_step(usrnm);
    
    if (new_q == SQLITE_ROW) {
        printf("Welcome! Please enter your passcode to continue.");

		// intialize fd3
		fd3 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client ; 

		// handle the user input
		if(FD_ISSET(STDIN_FILENO, &readfds)){
			handle_user_input();
		}
		if(FD_ISSET(&client, &readfds)) {
			password = handle_socket_input(&client);
		}

		sqlite3_finalize(usrnm);
		sqlite3_close(db);
    }

	// now step with the username
	new_q = sqlite3_step(password);

	if (new_q == SQLITE_ROW) {
        printf("Welcome! You have successfully logged in.");

		sqlite3_finalize(password);
		sqlite3_close(db);
		return 0;
    }
	else {
		printf("Incorrect password. Try again");
		return 1;
	}
}

static int set_new_user_password(char *username, struct client_info *client) {
	// username
	char *password = (char *)malloc(20 * sizeof(password));
	fd_set readfds;
	int fd3;

	// ask user for input username
	printf("Please enter your password");

	/* wait for a file descriptor */
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	FD_SET(&client, &readfds);

	// start up the database
	sqlite3 *db;
    sqlite3_stmt *usrnm = *username;

	int new_q = sqlite3_open(STDIN_FILENO, &db);


	if (new_q != SQLITE_OK) {
        
        fprintf(stderr, "Can not connect to the database. Are you sure it is working?\n");
        sqlite3_close(db);
        return 1;
    }
	else {
		// prepare because you have to!
		new_q = sqlite3_prepare(db, "", -1, &usrnm, 0);  
		
		if (new_q != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare data");
			sqlite3_close(db);
			return 1;
		}    
	}

	// now step with the username
	new_q = sqlite3_step(usrnm);
    
    if (new_q == SQLITE_ROW) {
        printf("Welcome! Please enter your passcode to continue.");

		// intialize fd3
		fd3 = (STDIN_FILENO > &client) ? STDIN_FILENO : &client ; 

		// handle the user input
		if(FD_ISSET(STDIN_FILENO, &readfds)){
			handle_user_input();
		}
		if(FD_ISSET(&client, &readfds)) {
			password = handle_socket_input(&client);
		}

		sqlite3_finalize(usrnm);
		sqlite3_close(db);
		return 0;
    }
	else {
		printf("Failed to assign you a password password. Try again");
		return 1;
	}

}
