sqlcmd -S SERVERNAME -d MYDATABASE -U USERNAME -P PASSWORD -i C:\path\mysqlfile.sql -o C:\path\results.txt


CREATE DATABASE usersSQL;

IF  NOT EXISTS (SELECT * FROM sys.objects 
WHERE object_id = OBJECT_ID(N'[dbo].[USERS]') AND type in (N'U'))

    BEGIN
    CREATE TABLE users (
        usrnme varchar(255),
        pswrd varchar(255),
        the_tatus varchar(255), 
        signat_num int, 
        PRIMARY KEY (ID)
    );

    CREATE TABLE message_logs (
        messages varchar(255),
    );

    CREATE TABLE sessions (
        time_msg_sent varchar(255),
    );

END