#ifndef _TCPSERVER_
#define _TCPSERVER_

#include "packet.h"

int create_server();
int preprocess_newclient(int conn_s, int udpsock0, int *version,
		double *upcap, double *downcap, struct sockaddr_in *from, char *tracefile, FILE *fp);
int postprocess_client(int tcpsock, const char *filename, const char *sndfilename, const int probedir, char **env);
int handle_clients(int list_s, int udpsock0);

double capacityEstimation(int tcpsock, int udpsock0, 
		struct sockaddr_in *from, FILE *fp);

int setfilename(int fileid, char *tracefile);

#endif

