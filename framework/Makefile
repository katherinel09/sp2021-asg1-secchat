.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -DSQLITE_USER_AUTHENTICATION #-lcrypto -lssl

all: client server # database

clean:
	rm -f server client database *.o users.db

# database: database.o

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h

api.o: api.c api.h

util.o: util.c util.h

client: client.o api.o ui.o util.o

worker.o: worker.c util.h worker.h database.c

server: server.o api.o util.o worker.o

server.o: server.c util.h

