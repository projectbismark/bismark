#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "packet.h"
#include "tcpserver.h"
#include "tcpclient.h"
#include "diffprobe.h"

extern unsigned int verbose;


int prober_bind_port(int port)
{
	int sock;
	struct sockaddr_in echoserver;
	int sndsize = 1024*1024, ret = 0;

	sock = socket(PF_INET, SOCK_DGRAM/*SOCK_STREAM*//*SOCK_RAW*/, IPPROTO_UDP);
	if(sock == -1)
	{
		fprintf(stderr, "couldn't creat socket");
		return -1;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, 
			(char *)&sndsize, sizeof(int));
	sndsize = 1024*1024;
	ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, 
			(char *)&sndsize, sizeof(int));

	memset(&echoserver, 0, sizeof(echoserver));
	echoserver.sin_family = AF_INET;
	echoserver.sin_addr.s_addr = htonl(INADDR_ANY);
	echoserver.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &echoserver,	sizeof(echoserver)) < 0)
	{
		fprintf(stderr, "Failed to bind the server socket");
		return -1;
	}
	//if (listen(sock, 10) < 0) {
	//	fprintf(stderr, "Failed to listen on server socket");
	//}

	return sock;
}

int create_server()
{
	int list_s;
	short int port = SERV_PORT;
	struct sockaddr_in servaddr;
	int optval = 1;
	int ret = 0;
	int sndsize = 1024*1024;

	if ( (list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) 
	{
		fprintf(stderr, "SERV: Error creating listening socket.\n");
		exit(-1);
	}

	optval = 1;
	setsockopt(list_s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	ret = setsockopt(list_s, SOL_SOCKET, SO_SNDBUF, 
			(char *)&sndsize, sizeof(int));
	sndsize = 1024*1024;
	ret = setsockopt(list_s, SOL_SOCKET, SO_RCVBUF, 
			(char *)&sndsize, sizeof(int));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) 
	{
		fprintf(stderr, "SERV: Error calling bind()\n");
		exit(-1);
	}

	if ( listen(list_s, LISTENQ) < 0 ) 
	{
		fprintf(stderr, "SERV: Error calling listen()\n");
		exit(-1);
	}

	return list_s;
}

int handle_newclient(int conn_s, int udpsock0);

int handle_clients(int list_s, int udpsock0)
{
	/*int conn_s;
	while ( 1 ) 
	{
		// Wait for a connection, then accept() it
		if ( (conn_s = accept(list_s, NULL, NULL) ) < 0 ) {
			fprintf(stderr, "SERV: Error calling accept()\n");
			exit(-1);
		}


		handle_newclient(conn_s, udpsock0);

		// Close the connected socket
		if ( close(conn_s) < 0 ) {
			fprintf(stderr, "SERV: Error calling close()\n");
			exit(-1);
		}
	}

	return 0;*/

	int conn_s;
	if ( (conn_s = accept(list_s, NULL, NULL) ) < 0 ) {
		fprintf(stderr, "SERV: Error calling accept()\n");
		return -1;
	}
	return conn_s;
}

int preprocess_newclient(int conn_s, int udpsock0, int *version, double *capacityup, 
			double *capacitydown, struct sockaddr_in *from, 
			char *tracefile, FILE *fp)
{
	int ret = 0;
	pheader hdr;
	pnewclientack pnewack;
	pcapestack pcapack;
	pnewclientpacket pnewclient;
	int szhdr = sizeof(struct _header);

	while(1)
	{
		ret = readwrapper(conn_s, (char *)&hdr, szhdr);
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error reading from client: %d\n", conn_s);
			close(conn_s);
			return -1;
		}

		switch(hdr.ptype)
		{
		case P_NEWCLIENT:
			ret = readwrapper(conn_s, 
				(char *)&pnewclient + szhdr, 
				sizeof(struct _newclientpkt) - szhdr);
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error reading from client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			//TB_RATE_AVG_INTERVAL = pnewclient.delta;
			*version = ntohl(pnewclient.version);
			pnewack.compatibilityFlag = 
				(ntohl(pnewclient.version) == VERSION /*|| 
				 ntohl(pnewclient.version) == 1*/) ? 1 : 0;
			pnewack.header.ptype = P_NEWCLIENT_ACK;
			pnewack.header.length = 0;
			ret = writewrapper(conn_s, (char *)&pnewack, 
					sizeof(struct _newclientack));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			if(pnewack.compatibilityFlag == 0)
			{
				close(conn_s);
				return -1;
			}
			break;
		case P_CAPEST_START:
			pcapack.header.ptype = P_CAP_ACK;
			pcapack.header.length = 0;
			pcapack.capacity = pcapack.finalflag = 0;
			pcapack.trainlength = htonl(TRAIN_LENGTH);
			ret = writewrapper(conn_s, (char *)&pcapack, 
					sizeof(struct _capestack));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			*capacityup = capacityEstimation(conn_s, udpsock0, from, fp);
			*capacitydown = estimateCapacity(conn_s, udpsock0, from);

			return 0;
			break;
		default:
			fprintf(stderr, "unknown packet type!\n");
			close(conn_s);
			return -1;
			break;
		}
	}

	return 0;
}

inline double timeval_diff(struct timeval x, struct timeval y)
{
	struct timeval result;

	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec) 
	{
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}
	if (x.tv_usec - y.tv_usec > 1000000) 
	{
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result.tv_sec = x.tv_sec - y.tv_sec;
	result.tv_usec = x.tv_usec - y.tv_usec;

	return result.tv_sec + result.tv_usec/1.0e6;
}

#ifdef _PAIRS_
double capacityEstimation_pairs(int tcpsock)
{
	extern int udpsock0;
	char buf[2000];
	int ret1 = 0, ret2 = 0;
	struct timeval t1, t2, tout;
	double gap = 0;
	double cap = -1, mindcap = -1;
	pcapestack pcapack;
	pcapack.header.ptype = P_CAP_ACK;
	pcapack.header.length = 4;
	int ret = 0;

	int niters = 0, nfound = 0;
	double mindelay1 = INT_MAX;
	double mindelay2 = INT_MAX;
	double mindelaysum = INT_MAX;
	double owd1 = 0, owd2 = 0;
	int mindflag1, mindflag2, mindsumflag;

	fd_set readset;
	int maxfd = (udpsock0 > tcpsock) ? udpsock0+1 : tcpsock+1;

	while(1)
	{
		niters++;
		mindflag1 = mindflag2 = mindsumflag = 0;
		cap = ret1 = ret2 = -1;

		FD_ZERO(&readset);
		FD_SET(udpsock0, &readset);
		tout.tv_sec = 1; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			return -1;
		}
		else if(ret == 0)
		{
			goto noudp;
		}
		if(FD_ISSET(udpsock0, &readset))
		{
			ret1 = recv(udpsock0, buf, 2000, 0);
			if(ret1 == -1)
			{
				fprintf(stderr, "recv error on UDP\n");
				return -1;
			}
#ifndef OSX
			if (ioctl(udpsock0, SIOCGSTAMP, &t1) < 0)
			{
				perror("ioctl-SIOCGSTAMP");
				gettimeofday(&t1,NULL);
			}
#else
			gettimeofday(&t1, NULL);
#endif
			owd1 = fabs(-1e3*(*(double *)buf - (t1.tv_sec + t1.tv_usec/1.0e6)));
			mindflag1 = (mindelay1 > owd1) ? 1 : 0;
			mindelay1 = (mindelay1 > owd1) ? owd1 : mindelay1;
		}

		FD_ZERO(&readset);
		FD_SET(udpsock0, &readset);
		tout.tv_sec = 10; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			return -1;
		}
		else if(ret == 0)
		{
			goto noudp;
		}
		if(FD_ISSET(udpsock0, &readset))
		{
			ret2 = recv(udpsock0, buf, 2000, 0);
			if(ret2 == -1)
			{
				fprintf(stderr, "recv error on UDP\n");
				return -1;
			}
#ifndef OSX
			if (ioctl(udpsock0, SIOCGSTAMP, &t2) < 0)
			{
				perror("ioctl-SIOCGSTAMP");
				gettimeofday(&t2,NULL);
			}
#else
			gettimeofday(&t2,NULL);
#endif
			owd2 = fabs(-1e3*(*(double *)buf - (t2.tv_sec + t2.tv_usec/1.0e6)));
			mindflag2 = (mindelay2 > owd2) ? 1 : 0;
			mindelay2 = (mindelay2 > owd2) ? owd2 : mindelay2;
		}

		if(ret1 != ret2 || ret1 == -1 || ret2 == -1)
		{
			fprintf(stderr, "sizes %d %d not same OR timeout\n", ret1, ret2);
		}
		else
		{
			//mindsumflag = (mindelaysum > owd1+owd2) ? 1 : 0;
			mindelaysum = (mindelaysum > owd1+owd2) ? owd1+owd2 : mindelaysum;
			mindsumflag = (fabs(owd1+owd2 - (mindelay1+mindelay2)) < 
					0.01/*0.01*(owd1+owd2)*/) ? 1 : 0; //TODO

			gap = timeval_diff(t2, t1); //s
			cap = 1.0e-3*ret1*8.0/gap; //Kbps
			if(mindsumflag) { mindcap = cap; printf("FOUND!\n"); nfound++; }
			printf("cap: %.2f Kbps d1:%f d2:%f sum:%f diff:%f\n", cap, owd1, 
					owd2, mindelaysum,fabs(owd1+owd2 - (mindelay1+mindelay2)));
		}

noudp:
		pcapack.capacity = htonl(cap);
		pcapack.finalflag = 0;
		if(niters % 100 == 0 && nfound > 1) { 
			pcapack.finalflag = htonl(1);
			pcapack.capacity = htonl(mindcap); 
		}
		ret = writewrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
			close(tcpsock);
			return -1;
		}
		pcapack.finalflag = ntonl(pcapack.finalflag);
		if(pcapack.finalflag == 1) break;
		if(niters > 1000) break;
	}

	return mindcap;
}
#else
double capacityEstimation(int tcpsock, int udpsock0, struct sockaddr_in *from, FILE *fp)
{
	char buf[2000];
	int ret1 = 0, sz = 0;
	struct timeval ts, tstart, tend, tout;
	struct timeval tsend[TRAIN_LENGTH], trecv[TRAIN_LENGTH];
	int seq[TRAIN_LENGTH];
	double gap = 0;
	double cap = -1, mediancap = -1;
	pcapestack pcapack;
	pcapack.header.ptype = P_CAP_ACK;
	pcapack.header.length = 0;
	int ret = 0, count = 0, niters = 0, nrecvd = 0;

	fd_set readset;
	int maxfd = (udpsock0 > tcpsock) ? udpsock0+1 : tcpsock+1;

	double caps[10*NITERATIONS], validcaps[10*NITERATIONS];
	memset(caps, 0, 10*NITERATIONS*sizeof(double));
	memset(validcaps, 0, 10*NITERATIONS*sizeof(double));
	int validsz = 0;
	int ULSZ = sizeof(unsigned long), UCSZ = sizeof(unsigned char);

	while(1)
	{
		niters++;
		cap = ret1 = sz = -1;
		tstart.tv_sec = tstart.tv_usec = tend.tv_sec = tend.tv_usec = -1;
		memset(tsend, 0, TRAIN_LENGTH*sizeof(struct timeval));
		memset(trecv, 0, TRAIN_LENGTH*sizeof(struct timeval));
		nrecvd = 0;

		for(count = 0; count < TRAIN_LENGTH; count++)
		{
			FD_ZERO(&readset);
			FD_SET(udpsock0, &readset);
			tout.tv_sec = 1; tout.tv_usec = 0;
			ret = select(maxfd, &readset, NULL, NULL, &tout);
			if(ret < 0)
			{
				fprintf(stderr, "select error\n");
				return -1;
			}
			else if(ret == 0)
			{
				break;
			}
			if(FD_ISSET(udpsock0, &readset))
			{
				unsigned int fromlen = sizeof(struct sockaddr_in);
				ret1 = recvfrom(udpsock0, buf, 2000, 0, 
						(struct sockaddr *)from, &fromlen);
				if(ret1 == -1)
				{
					fprintf(stderr, "recv error on UDP\n");
					return -1;
				}
#ifndef OSX
				if (ioctl(udpsock0, SIOCGSTAMP, &ts) < 0)
				{
					perror("ioctl-SIOCGSTAMP");
					gettimeofday(&ts,NULL);
				}
#else
				gettimeofday(&ts, NULL);
#endif
				if(tstart.tv_sec == -1) tstart = ts;
				tend = ts;
				sz = ret1;

				seq[count] = buf[0];
				trecv[count] = ts;
				tsend[count].tv_sec = ntohl(*(unsigned long *)((char *)buf
							+UCSZ));
				tsend[count].tv_usec = ntohl(*(unsigned long *)((char *)buf
							+UCSZ+ULSZ));
				nrecvd++;
			}
		}

		fprintf(fp, "### TRAIN ###\n");
		for(count = 0; count < TRAIN_LENGTH; count++)
		{
			fprintf(fp, "%f %f %d\n", 
					tsend[count].tv_sec+tsend[count].tv_usec*1e-6,
					trecv[count].tv_sec+trecv[count].tv_usec*1e-6,
					seq[count]);
		}
		fprintf(fp, "\n");

		gap = timeval_diff(tend, tstart); //s
		if(sz != -1 && gap != 0)
		{
			cap = 1.0e-3*(nrecvd-1)*(sz+UDPIPHEADERSZ)*8.0/gap; //Kbps
			//printf("cap: %.2f Kbps\n", cap);
			//printf("."); fflush(stdout);
		}
		caps[niters-1] = cap;

		pcapack.capacity = htonl(cap);
		pcapack.finalflag = 0;
		pcapack.trainlength = htonl(TRAIN_LENGTH);
		if(niters % NITERATIONS == 0) { 
			pcapack.finalflag = htonl(1);
			break;
		}
		if(niters > 10*NITERATIONS) break;

		ret = writewrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
			close(tcpsock);
			return -1;
		}
	}

	for(ret1=0; ret1<10*NITERATIONS; ret1++)
	{
		if(caps[ret1] == -1 || caps[ret1] == 0)
		continue;
		validcaps[validsz] = caps[ret1];
		validsz++;
	}
	int compd(const void *a, const void *b);
	qsort((void *)validcaps, validsz, sizeof(double), compd);
	mediancap = validcaps[(int)floor(validsz/2.0)];

	pcapack.finalflag = htonl(1);
	pcapack.capacity = htonl(mediancap);
	ret = writewrapper(tcpsock, (char *)&pcapack, 
			sizeof(struct _capestack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	return mediancap;
}

int compd(const void *a, const void *b)
{
	return ( *(double*)a - *(double*)b );
}
#endif

