// Payload generator

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

int interrupted = 0;

/*
 * Catch SIG_PIPE
 */
void sig(int signo)
{
	interrupted = 1;
}


/*
 * Associate an incoming signal (e.g. HUP) to a specific function
 */
int catch_sig(int signo, void(*handler)())
{
        struct sigaction action;

        action.sa_handler = handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;

        if (sigaction(signo, &action, NULL) == -1) {
                return (-1);
        } else {
                return (1);
        }
}


int main(int argc, char **argv)
{
	unsigned int i, chunk_size = 1460;
	char *payload;
	char pattern[] = "dummyload_";
	int pat_len = strlen(pattern);
	long unsigned int size, bytes = 0;

	if (argc < 2) {
		printf("syntax: %s <length>\n", basename(argv[0]));
		return 1;
	}

	size = atol(argv[1]);

	catch_sig(SIGPIPE, sig);
	catch_sig(SIGINT, sig);

	payload = malloc(chunk_size);

	for(i=0; i<chunk_size; i++) 
		payload[i] = pattern[i % pat_len]; 

	for(i=0; i<size/chunk_size; i++) {
		bytes += write(1, payload, chunk_size);
		fflush(stdout);
 
		if (interrupted)
			break;
	}

	fprintf(stderr,"%lu\n", bytes);

	return 0;
}
