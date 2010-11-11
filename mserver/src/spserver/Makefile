
CC=gcc

CFLAGS=-c -Wall -O3 -m32
LFLAGS=-m32

all: clean probeserver

prober: prober.o 
	$(CC) $(LFLAGS) -lm prober.o wrappers.o tcp_client.o tcpserver.o tbdetect.o -o prober

prober.o: prober.c
	$(CC) $(CFLAGS) prober.c tcp_client.c tcpserver.c wrappers.c tbdetect.c

probeserver: probeserver.o
	$(CC) $(LFLAGS) -lm probeserver.o wrappers.o tcpserver.o tcp_client.o tbdetect.o measflow.o -o probeserver

probeserver.o: probeserver.c
	$(CC) $(CFLAGS) -DDSERVER probeserver.c wrappers.c tcpserver.c tcp_client.c tbdetect.c measflow.c
tbtest: tbtest.o 
	$(CC) $(LFLAGS) -lm tbtest.o wrappers.o tcp_client.o tcpserver.o tbdetect.o -o tbtest

tbtest.o: prober.c
	$(CC) $(CFLAGS) tbtest.c tcp_client.c tcpserver.c wrappers.c tbdetect.c

clean:
	rm -rf *.o prober probeserver 
