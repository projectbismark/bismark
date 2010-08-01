// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// UDP Proxy Server multi-thread
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

// Librerie
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>	// gethostbyname()
#include <sys/time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h> 	// atoi()
#include <unistd.h> 	// close()

#include <pthread.h>	// posix threads

// Costanti
#define QLEN 6
#define MAX_NUM_THREAD 20

// Variabili globali (condivise da tutti i thread)
int num_thread;			// numero di thread attivi
char gbuf[1000];		// buffer in cui memorizzare la stringa
struct sockaddr_in pad;		// PROXY SERVER
struct sockaddr_in sad;		// SERVER
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;	
int gsd;

// Thread per la gestione di una singola connessione
void *doit(void *vncad)
{
	char lbuf[1000];			// buffer per la stringa modificata
	int i, sd;
	struct sockaddr_in lcad;
	struct timeval timeout = {2,0};
	
	pthread_mutex_lock(&mutex);
	struct sockaddr_in ncad = *((struct sockaddr_in *)vncad);	// copia locale del descrittore della socket
	int thread_id = num_thread++;					// identificativo logico del thread
	strncpy(lbuf, gbuf, 1000);
	pthread_mutex_unlock(&mutex);

	printf("Client %d: %s", thread_id, lbuf);

	// Inizializzazione della struttura lcad (Client)
	memset((char *)&lcad, 0, sizeof(lcad));
	lcad.sin_family = AF_INET;

	// Creazione di una socket di tipo SOCK_DGRAM - UDP
	if ((sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "socket creation failed\n");
		exit(1);
	}
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));
	
	// Configurazione dell'endpoint locale della socket utilizzando 
	// i parametri della struttura sockaddr_in cad
	if (bind(sd, (struct sockaddr *)&lcad, sizeof(lcad)) < 0) {
		fprintf(stderr, "bind failed\n");
		exit(2);
	}
	
	// Invio della stringa al server
	sendto(sd, lbuf, strlen(lbuf),0,(struct sockaddr*)&sad, sizeof(sad));
	
	// Ricezione della risposta dal server
	memset(lbuf, 0, sizeof(lbuf));
	if (recv(sd, lbuf, sizeof(lbuf), 0) < 0) {
		printf("Timeout %d\n", thread_id);
	} else {
		printf("Server %d: %s", thread_id, lbuf);

		// Invio della risposta del server al client
		sendto(gsd, lbuf, strlen(lbuf),0,(struct sockaddr*) &ncad, sizeof(ncad));
	}
	close(sd);
	
	pthread_mutex_lock(&mutex);
	num_thread--;
	pthread_mutex_unlock(&mutex);
	
	return NULL;
}


int main(int argc, char *argv[])
{
	unsigned short proxy_port;	// numero di port del proxy
	unsigned short server_port;	// numero di port del servizio
	struct hostent *ptrh;		// struttura per memorizzare la risoluzione del nome del server
	pthread_t hThr[MAX_NUM_THREAD];
	int i = 0;

	// Lettura delle opzioni a riga di comando
	if (argc != 4) {
		fprintf(stderr, "usage: %s <proxy_port> <server> <port>\n", argv[0]);
		return 0;
	}

	// Acquisizione port del proxy
	proxy_port = atoi(argv[1]);
	if (proxy_port == 0) {
		fprintf(stderr, "invalid port number: %s\n", argv[1]);
		return 1;
	}

	// Conversione del nome in indirizzo IP
	if ((ptrh = gethostbyname(argv[2])) == NULL) {
		fprintf(stderr, "invalid host address: %s\n", argv[2]);
		return 1;
	}

	// Acquisizione port del server
	server_port = atoi(argv[3]);
	if (proxy_port == 0) {
		fprintf(stderr, "invalid port number: %s\n", argv[3]);
		return 1;
	}

	// Inzializzazione della struttura sad (Server)
	memset((char *)&sad, 0, sizeof(sad));
	sad.sin_family = AF_INET;
	memcpy(&sad.sin_addr, ptrh->h_addr, ptrh->h_length);	// copia dell'indirizzo nel campo sin_addr della struttura sad
	sad.sin_port = htons(server_port);

	// Inzializzazione della struttura pad (Proxy)
	memset((char *)&pad, 0, sizeof(sad));
	pad.sin_family = AF_INET;
	pad.sin_addr.s_addr = INADDR_ANY;
	pad.sin_port = htons(proxy_port);		// conversione di port da "host byte order" a "TCP/IP network order"
	
	// Creazione di una socket di tipo SOCK_DGRAM - UDP
	if ((gsd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "error creating socket\n");
		return 1;
	}

	// Configurazione dell'endpoint locale della socket utilizzando 
	// i parametri della struttura sockaddr_in sad
	if (bind(gsd, (struct sockaddr *)&pad, sizeof(pad)) < 0) {
		fprintf(stderr, "bind fallito\n");
		return 1;
	}

	printf("Proxy listening on port %d -> Redirecting to %s:%d\n", proxy_port, argv[2], server_port);

	// Ciclo infinito
	while (1) {
		char buf[1000];					// buffer in cui memorizzare la stringa
		struct sockaddr_in cad;				// CLIENT
		socklen_t cadlen = sizeof(struct sockaddr_in);	// dimensione della struttura cad
		
		// Ricezione della stringa inviata dal client
		memset(buf, 0, sizeof(buf));
		recvfrom(gsd, buf, sizeof(buf), 0, (struct sockaddr*)&cad, &cadlen);
		strncpy(gbuf, buf, 1000);
		
		// Controllo sul numero massimo di socket gestibili
		if (num_thread >= MAX_NUM_THREAD) {
			fprintf(stderr, "max connections reached: refusing %s\n", buf);
		} else {
			// Creazione di un thread per gestire la nuova connessione
			if (pthread_create(&hThr[i], NULL, doit, &cad) < 0) {
				fprintf(stderr, "error creating thread\n");
			} else {
                                pthread_detach(hThr[i]);
                        }

		}
	}
	
	// Chiusura della socket in ascolto
 	close(gsd);
}
