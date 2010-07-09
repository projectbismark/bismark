/*
 * DNS Measurements for Bismark project
 *
 * Created on: 09/07/2010
 * Author: walter.dedonato@unina.it
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>

#define HOSTS_LIST "conf/hosts.list"
#define MAX_PATH_LEN 50

int main(int argn, char **argv) 
{
	struct addrinfo hints;
	struct addrinfo *result;
	char hostname[NI_MAXHOST];
	char list[MAX_PATH_LEN];
	struct timeval t_start, t_end;
	FILE *fp;
	int failures = 0;
	int ret, i;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	snprintf(list, MAX_PATH_LEN, "%s/%s", getenv("HOME"), HOSTS_LIST);

	fp = fopen(list, "r");

	while (fscanf(fp, "%s\n", hostname) != EOF) {
		gettimeofday(&t_start, NULL);
		ret = getaddrinfo(hostname, NULL, &hints, &result);
		gettimeofday(&t_end, NULL);
		if (!ret)
			freeaddrinfo(result);
		else
			failures++;

		if (t_end.tv_usec > t_start.tv_usec)
			printf("%lu.%06lu\n", t_end.tv_sec - t_start.tv_sec, t_end.tv_usec - t_start.tv_usec);
		else
			printf("%lu.%06lu\n", t_end.tv_sec - t_start.tv_sec - 1, 1000000 - (t_start.tv_usec - t_end.tv_usec));
	}

	fclose(fp);
	fprintf(stderr, "%d\n", failures);
}

