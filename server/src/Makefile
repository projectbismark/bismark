CFLAGS  = -Wall -ggdb
#LIBS    = -L ~/lib
INCLUDE = -I /usr/include/postgresql  # for Debian
CC      = gcc

all: bdmd udpproxy

bdmd: bdmd.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread -lpq $(INCLUDE) -o $@.real $@.c

udpproxy: udpproxy.c
	$(CC) $(LIBS) $(CFLAGS) -lpthread $(INCLUDE) -o $@ $@.c

clean:
	rm bdmd.real udpproxy
