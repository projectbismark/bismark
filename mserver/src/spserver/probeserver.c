/*
 * Packet capturer.
 * 
 * November 2008.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#define __FAVOR_BSD	/* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>

#include <time.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include <pcap.h>

#include "tcpserver.h"
#include "packet.h"
#include "diffprobe.h"

#define PROBESERVER_CONFIG "probeserver.conf"
#define PROBESERVER_MAX_CLIENTS 1024

/* Global parameters from config.  */

unsigned int serverip = 0;
unsigned int clientip = 0;
unsigned int A_targetport = 0;
unsigned int P_targetport = 0;

unsigned int verbose = 1;


/* Utility functions.  */

void swaittv(int wait_time)
{
	/* Wait for based on select(2). Wait time is given in microsecs.  */
	struct timeval tv;
	tv.tv_sec = 0;   
	tv.tv_usec = wait_time;  

#if DEBUG
	fprintf(stderr, "Waiting for %d microseconds.\n", wait_time);
#endif

	select(0,NULL,NULL,NULL,&tv);	
}

char * ip2str(bpf_u_int32 ip)
{
	struct in_addr ia;

	ia.s_addr = ip;

    return inet_ntoa(ia);
}

unsigned int str2ip(char *ip)
{
        struct in_addr ia;
        int r;
        r = inet_aton(ip, &ia);
        if (r) return ntohl(ia.s_addr);
        return 0;
}

void die(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(0);
}

int getLogName(char *dir, char *file, char *ip, int dirlen, int filelen, int iplen)
{
	char myname[128];
	char tfile[128];

	struct tm *now = NULL;
	time_t tval = 0;

	if(ip == NULL || file == NULL || dir == NULL)
		return -1;

	memset(myname, '\0', 128);
	memset(dir, '\0', dirlen);
	memset(file, '\0', filelen);
	memset(tfile, '\0', 128);

	tval = time(NULL);
	now = localtime(&tval);
	if(now == NULL)
		return -1;
	if(strftime(dir, dirlen, "dropbox/%Y/%2m/%2d/", now) == 0)
		return -1;

	if(gethostname(myname, 128) == -1)
	{
		struct utsname uts;
		if (uname(&uts) < 0)
			strcpy(myname, "UNKNOWN");
		else
			strcpy(myname, uts.nodename);
	}
	strcat(dir, myname);

	strftime(tfile, 128, "_%Y%2m%2dT%TZ.txt", now);
	strncpy(file, ip, iplen);
	strcat(file, tfile);

	return 0;
}

FILE *openLog(char *filename, char *tname, struct timeval tv)
{
	FILE *fp = NULL;
	char tdir[128], tfile[128], tchar[256];
	extern double TB_RATE_AVG_INTERVAL;
	int ret = 0;

	memset(filename, '\0', 256);

	if(getLogName(tdir, tfile, tname, 128, 128, strlen(tname)) != -1)
	{
		sprintf(filename, "%s/%s", tdir, tfile);
		sprintf(tchar, "/bin/mkdir -p %s", tdir);
		ret = system(tchar);
		fp = fopen(filename, "w");
	}

	if(fp == NULL) //revert back to old "flat" files
	{
		sprintf(filename, "%s_%d_%fdelta.txt", tname,
				(int)tv.tv_sec, TB_RATE_AVG_INTERVAL);
		fp = fopen(filename, "w");
	}

	return fp;
}

void catcher(int sig)
{
	struct itimerval value;
	int which = ITIMER_REAL;

	getitimer( which, &value );
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 0;
	setitimer( which, &value, NULL );

	printf("Exiting after 10mins.\n");
	exit(0);
}
int begintimer()
{
	int result = 0;
	struct itimerval value;
	struct sigaction sact;

	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	sact.sa_handler = catcher;
	sigaction(SIGALRM, &sact, NULL);

	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 0;
	value.it_value.tv_sec = 600; //10mins. max time.
	value.it_value.tv_usec = 0;

	result = setitimer(ITIMER_REAL, &value, NULL);

	return result;
}

int recvData(int tcpclientsock, FILE *fp, int direction /*0 up 1 down*/)
{
	prcvdata pkt;
	int ret = 0, len = 0, bytesleft = 0;
	char *buf;

	ret = readwrapper(tcpclientsock, (char *)&pkt, sizeof(struct _rcvdata));
	if(ret == -1)
	{
		perror("SERV: error reading from client.\n");
		close(tcpclientsock);
		return -1;
	}
	if(pkt.header.ptype != P_RECVDATA)
	{
		fprintf(stderr, "SERV: wrong packet type: %d\n", pkt.header.ptype);
		return -1;
	}

	len = ntohl(pkt.datalength);
	buf = (char *)malloc(len*sizeof(char));
	/*ret = readwrapper(tcpclientsock, (char *)&buf, len*sizeof(char));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client..\n");
		perror("");
		close(tcpclientsock);
		free(buf);
		return -1;
	}*/
	bytesleft = len;
	while(bytesleft > 0)
	{
		int torecv = (bytesleft > 1400) ? 1400 : bytesleft;
		ret = readwrapper(tcpclientsock, (char *)buf+(len-bytesleft), torecv);
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error reading data from client..\n");
			perror("");
			close(tcpclientsock);
			free(buf);
			return -1;
		}
		bytesleft -= ret;
	}
	
	if(direction == 1)
	fprintf(fp, "### DOWNSTREAM ###\n");
	ret = fwrite((void *)buf, sizeof(char), len, fp);
	free(buf);

	return 0;
}


int main(int argc, char *argv[], char **env)
{
	int tcpsock, tcpclientsock;
	int udpsockcap;
	double upcap = 0, downcap = 0;
	double measupcap = 0, measdowncap = 0;
	unsigned int tbresult = 0, tbabortflag = 0,
		tbmindepth = 0, tbmaxdepth = 0;
	double tbrate = 0, trueupcap = 0, truedowncap = 0;
	double sleepRes = 1;
	struct sockaddr_in saddr;
	unsigned int ssz = sizeof(saddr);
	char tracefile[256], filename[256];
	struct timeval tv;
	struct sockaddr_in from;
	FILE *fp=0;
	extern double TB_RATE_AVG_INTERVAL;
	int clientversion = 0;

	TB_RATE_AVG_INTERVAL = 0.3;
	memset(tracefile, 0, 256);

	tcpsock = create_server();
	sleepRes = prober_sleep_resolution();
	printf("sleep time resolution: %.2f ms.\n", sleepRes*1000);

while(1)
{
	printf("Waiting for new clients..\n");

	udpsockcap = prober_bind_port(SERV_PORT_UDP);
	CHKRET(udpsockcap);

	tcpclientsock = handle_clients(tcpsock, udpsockcap);
	CHKRET(tcpclientsock);
	//close(tcpsock);

	begintimer();

	if(getpeername(tcpclientsock, (struct sockaddr *)&saddr, &ssz) == -1)
	fprintf(stderr, "cannot get peer address\n");
	gettimeofday(&tv, NULL);
	memset(filename, 0, 256);
	printf("Probing from %s\n", inet_ntoa(saddr.sin_addr));

	printf("\nEstimating capacity:\n");

	//fp = openLog(filename, inet_ntoa(saddr.sin_addr), tv); //assume this opens a fp
	//fprintf(fp, "sleep time resolution: %.2f ms.\n", sleepRes*1000);

	CHKRET(preprocess_newclient(tcpclientsock, udpsockcap, &clientversion,
				&upcap, &downcap, &from, tracefile, fp));
	trueupcap = upcap; truedowncap = downcap;

	if(upcap > 100000) { upcap = 95000; }
	if(downcap > 100000) { downcap = 95000; }

	mflowReceiver(tcpclientsock, udpsockcap, &measupcap, fp);
	mflowSender(tcpclientsock, udpsockcap, &from, downcap, sleepRes, &measdowncap);
	printf("recvrates: up %f, down %f Kbps\n", measupcap, measdowncap);
	upcap = measupcap; downcap = measdowncap;

	//fprintf(fp, "upstream capacity: %.2f Kbps.\n", upcap);
	//fprintf(fp, "downstream capacity: %.2f Kbps.\n", downcap);
	//fprintf(fp, "### UPSTREAM ###\n");
	printf("upstream capacity: %.2f Kbps.\n", upcap);
	printf("downstream capacity: %.2f Kbps.\n", downcap);
	if(upcap > 100000) { upcap = 95000; } //else { upcap *= 0.95; }
	if(downcap > 100000) { downcap = 95000; } //else { downcap *= 0.95; }

	printf("Checking for traffic shapers:\n");
	CHKRET(tbdetectReceiver(tcpclientsock, udpsockcap, upcap, sleepRes,
		&tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag, fp));
	if(tbresult == 1) trueupcap = tbrate;
//	if(clientversion > 1) //backwards-compatibility
//	mflowReceiver(tcpclientsock, udpsockcap, fp);
	printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, 0, fp);

	CHKRET(tbdetectSender(tcpclientsock, udpsockcap, &from, downcap, sleepRes,
		&tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag, fp));
	if(tbresult == 1) truedowncap = tbrate;
//	if(clientversion > 1) //backwards-compatibility
//	mflowSender(tcpclientsock, udpsockcap, &from, (tbresult == 1) ? tbrate : downcap/2.0, sleepRes);
	printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, 1, fp);
//	recvData(tcpclientsock, fp, 1 /*0 up 1 down*/);

	//fclose(fp);
	close(udpsockcap);
	close(tcpclientsock);

//	break;
}

//	execl("/bin/bzip2", "/bin/bzip2", filename, NULL);

	return(0);
}

