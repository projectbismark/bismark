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

int main(int argn, char **argv) 
{
	struct addrinfo hints;
	struct addrinfo *result;
	char hostname[NI_MAXHOST];
	struct timeval t_start, t_end;
	int ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	gettimeofday(&t_start, NULL);
	ret = getaddrinfo(argv[1], NULL, &hints, &result);
	gettimeofday(&t_end, NULL);
	if (!ret)
		freeaddrinfo(result);

	if (t_end.tv_usec > t_start.tv_usec)
		printf("%u.%06u\n", t_end.tv_sec - t_start.tv_sec, t_end.tv_usec - t_start.tv_usec);
	else
		printf("%u.%06u\n", t_end.tv_sec - t_start.tv_sec - 1, 1000000 - (t_start.tv_usec - t_end.tv_usec));
}
