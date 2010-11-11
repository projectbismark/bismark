#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *sprobetypes[10] = 
{
	"BLP_P",
	"LIP_P",
	"LDP_P",
	"BLP_A",
	"LIP_A",
	"LDP_A",
	"BLP_AP",
	"LIP_AP",
	"LDP_AP",
	"UNKNOWN"
};
char *sflowtypes[2] = { "P", "A" };

int readwrapper(int sock, char *buf, size_t size)
{
	int ret = 0;
	int curread = 0;
	fd_set rfds;
	struct timeval tv;
	int retval;

	while(curread < size)
	{
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		tv.tv_sec = 300;
		tv.tv_usec = 0;
		retval = select(sock+1, &rfds, NULL, NULL, &tv);
		if(retval == -1)
		{
			perror("error reading");
			return -1;
		}
		else if(retval == 0)
		{
			return -1;
		}

		ret = recv(sock, buf + curread, size - curread, 0);
		if(ret == -1)
		return ret;
		if(ret == 0)
		return ret;

		curread += ret;
	}

	return curread;
}
int writewrapper(int sock, char *buf, size_t size)
{
	int ret = 0;
	int curwrite = 0;

	while(curwrite < size)
	{
		ret = send(sock, buf + curwrite, size - curwrite, 0);
		if(ret == -1)
		return ret;

		curwrite += ret;
	}

	return curwrite;
}

