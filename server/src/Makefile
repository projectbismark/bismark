CFLAGS  = -Wall
LIBS    = -L ~/lib
INCLUDE = -I ~/include
CC      = gcc

all: bdmd udpproxy

bdmd: bdmd.c
	$(CC) $(LIBS) -lpthread -lsqlite3 $(INCLUDE) -o $@ $@.c

udpproxy: udpproxy.c
	$(CC) $(LIBS) -lpthread $(INCLUDE) -o $@ $@.c


