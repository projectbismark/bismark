#ifndef _TCPCLIENT_
#define _TCPCLIENT_

#include "packet.h"

int connect2server(unsigned int serverip, int fileid);
double estimateCapacity(int tcpsock, int udpsock, struct sockaddr_in *);
int udpclient();
int sendCapEst(int tcpsock);
int getDiscResult(int tcpsock);

#endif

