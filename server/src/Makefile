CFLAGS  = -Wall -ggdb
LIBS    = -L ~/lib
INCLUDE = -I ~/include
CC      = gcc

all: bdmd udpproxy

bdmd: bdmd.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread -lsqlite3 $(INCLUDE) -o $@.real $@.c

udpproxy: udpproxy.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread $(INCLUDE) -o $@ $@.c

clean:
	rm bdmd.real udpproxy
