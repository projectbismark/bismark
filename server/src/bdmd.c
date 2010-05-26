// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// UDP Proxy Server multi-thread
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

// Librerie
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>	// gethostbyname()
#include <sys/time.h>
#include <time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h> 	// atoi()
#include <unistd.h> 	// close()

#include <pthread.h>	// posix threads
#include <sqlite3.h>

// Costanti
#define QLEN 6
#define MAX_NUM_THREAD 50

// Variabili globali (condivise da tutti i thread)
int num_thread;			// numero di thread attivi
char gbuf[1000];		// buffer in cui memorizzare la stringa
struct sockaddr_in sad;		// SERVER
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_db = PTHREAD_MUTEX_INITIALIZER;
int gsd;

static int callback(void *out, int argc, char **argv, char **azColName)
{
	if (argc == 1)
		strncpy(out, argv[0], strlen(argv[0]));
	else if (argc > 1) {
		int i, p = 0;

		for (i=0; i<argc-1; i++) {
			snprintf(&((char *)out)[p], 64 - p, "%s ", argv[i]);
			p = strlen(out);
		}
		snprintf(&((char *)out)[p], 64 - p, "%s", argv[i]);
	} else
		((char *)out)[0] = '\0';
	return 0;
}

char *query_exec(sqlite3 *db, const char *query, const int cb)
{
	char *out = calloc(1, 64);
	char *zErrMsg = 0;

	pthread_mutex_lock(&mutex_db);
	printf("query = %s\n", query);
	if (sqlite3_exec(db, query, cb ? callback : NULL, out, &zErrMsg) != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	printf("out = %s\n", out);
	pthread_mutex_unlock(&mutex_db);


	return out;
}

// Thread per la gestione di una singola connessione
void *doit(void *vncad)
{
	char lbuf[1000];			// buffer per la stringa modificata
	char query[1000];
	int i;
	struct timeval timeout = {2,0};
	time_t ts;
	char *tmp;
	char id[10], cmd[15], param[50], ip[16];
	sqlite3 *db;
	
	pthread_mutex_lock(&mutex);
	struct sockaddr_in ncad = *((struct sockaddr_in *)vncad);	// copia locale del descrittore della socket
	int thread_id = num_thread++;					// identificativo logico del thread
	strncpy(lbuf, gbuf, 1000);
	tmp = (char *)inet_ntoa(ncad.sin_addr);
	strncpy(ip, tmp, 16);
	pthread_mutex_unlock(&mutex);

	// Get time
	ts = time(NULL);

	// Parse probe packet payload
	sscanf(lbuf,"%s %s %s", id, cmd, param);

	// Set default reply
	sprintf(lbuf,"pong %s\n", ip);

	// Exec command
	if (!strncmp(cmd, "ping", 4)) {
		// Ping
		char *val = NULL;

		// Open sqlite db
		if (sqlite3_open("/var/tmp/bdm.db", &db)) {
			fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			return NULL;
		}

		// Check device presence in db
		snprintf(query, 1000, "SELECT id FROM devices WHERE id='%s';", id);
		val = query_exec(db, query, 1);

		// Update db
		printf ("Th %d: ", thread_id);
		if (*val) {
			free(val);
			snprintf(query, 1000, "UPDATE devices SET ip='%s',ts=%lu,version=%s WHERE id='%s';", ip, ts, param, id);
			query_exec(db, query, 0);
		} else {
			snprintf(query, 1000, "INSERT INTO devices (id, ip, ts, version) VALUES('%s','%s',%lu,'%s');", id, ip, ts, param);
			query_exec(db, query, 0);
		}

		// Check messages
		printf ("Th %d: ", thread_id);
		snprintf(query, 1000, "SELECT rowid,* FROM messages WHERE \"to\"='%s' LIMIT 1;", id);
		val = query_exec(db, query, 1);
		if (*val) {
			char mid[5], from[10], to[10], msg[10];

			// Parse query result
			sscanf(val,"%s %s %s %s", mid, from, to, msg);

			// Set reply message
			sprintf(lbuf,"%s\n", msg);

			printf ("Th %d: ", thread_id);
			snprintf(query, 1000, "DELETE FROM messages WHERE rowid='%s';", mid);
			query_exec(db, query, 0);
		}

		sqlite3_close(db);
	} else if (!strncmp(cmd, "log", 3)) {
		// Log
		snprintf(query, 1000, "INSERT INTO messages ('from', 'to', msg) VALUES('%s','BDM','%s');", id, param);
		printf("%s\n",query);
	}

	// Invio della risposta del server al client
	sendto(gsd, lbuf, strlen(lbuf),0,(struct sockaddr*) &ncad, sizeof(ncad));
	
	pthread_mutex_lock(&mutex);
	num_thread--;
	pthread_mutex_unlock(&mutex);
	
	return NULL;
}


int main(int argc, char *argv[])
{
	unsigned short server_port;	// numero di port del servizio
	struct hostent *ptrh;		// struttura per memorizzare la risoluzione del nome del server
	pthread_t hThr[MAX_NUM_THREAD];
	int i = 0;

	// Lettura delle opzioni a riga di comando
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		return 0;
	}

	// Acquisizione port del server
	server_port = atoi(argv[1]);
	if (server_port == 0) {
		fprintf(stderr, "invalid port number: %s\n", argv[1]);
		return 1;
	}

	// Inzializzazione della struttura sad (Server)
	memset((char *)&sad, 0, sizeof(sad));
	sad.sin_family = AF_INET;
	sad.sin_addr.s_addr = htonl(INADDR_ANY);
	sad.sin_port = htons(server_port);

	// Creazione di una socket di tipo SOCK_DGRAM - UDP
	if ((gsd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "error creating socket\n");
		return 1;
	}

	// Configurazione dell'endpoint locale della socket utilizzando 
	// i parametri della struttura sockaddr_in sad
	if (bind(gsd, (struct sockaddr *)&sad, sizeof(sad)) < 0) {
		fprintf(stderr, "bind fallito\n");
		return 1;
	}

	printf("Bdmd listening on port %d\n", server_port);

	// Ciclo infinito
	while (1) {
		char buf[1000];					// buffer in cui memorizzare la stringa
		struct sockaddr_in cad;				// CLIENT
		socklen_t cadlen = sizeof(struct sockaddr_in);	// dimensione della struttura cad
		
		// Ricezione della stringa ricevuta dal client
		memset(buf, 0, sizeof(buf));
		recvfrom(gsd, buf, sizeof(buf), 0, (struct sockaddr*)&cad, &cadlen);
		pthread_mutex_lock(&mutex);
		strncpy(gbuf, buf, 1000);
		pthread_mutex_unlock(&mutex);
		
		// Controllo sul numero massimo di socket gestibili
		if (num_thread >= MAX_NUM_THREAD) {
			fprintf(stderr, "max connections reached: refusing %s\n", buf);
		} else {
			// Creazione di un thread per gestire la nuova connessione
			if (pthread_create(&hThr[i], NULL, doit, &cad) < 0) {
				fprintf(stderr, "error creating thread\n");
			}
		}
	}
	
	// Chiusura della socket in ascolto
 	close(gsd);
}
