.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS= -lsqlite3 -DSQLITE_USER_AUTHENTICATION -lcrypto -lssl

all: client server # database

clean:
	rm -f sqlite3 server client database *.o users.db

clientkeys:
	mkdir clientkeys
	cd clientkeys 
	mkdir private
	mkdir public

serverkeys:
	mkdir serverkeys
	cd serverkeys
	mkdir private
	mkdir public

# database: database.o

sqlite3.o: sqlite3.c sqlite3.h

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h 

api.o: api.c api.h

util.o: util.c util.h

ssl_nonblock.o: ssl_nonblock.c ssl_nonblock.h

client: client.o api.o ui.o util.o ssl_nonblock.o

worker.o: worker.c util.h worker.h database.c ssl_nonblock.o

server: server.o api.o util.o worker.o ssl_nonblock.o

server.o: server.c util.h

.PHONY: all clean