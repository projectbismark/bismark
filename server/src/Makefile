CFLAGS  = -Wall -ggdb
LIBS    = -L ~/lib
INCLUDE = -I ~/include
CC      = gcc

all: bdmd udpproxy

bdmd: bdmd.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread -lsqlite3 $(INCLUDE) -o $@ $@.c

udpproxy: udpproxy.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread $(INCLUDE) -o $@ $@.c


