#include "sqlite3.h"
 

int main(){
    sqlite3 *db;
    sqlite3_stmt *statement;

    // Create the data base
    sqlite3_open("SP_DB.db", &db);
}