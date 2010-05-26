/*
 * Bismark Device Manager Daemon
 *
 * Created on: 25/05/2010
 * Author: walter.dedonato@unina.it
 */

/*
 * Dependencies
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sqlite3.h>

/*
 * Types
 */
/* Thread parameter */
typedef struct {
	struct sockaddr_in cad; /* Client-side socket info */
	char *payload; 		/* Received payload */
} thp;

/* Probe format */
typedef struct {
	char *id; 	/* Device id */
	char *cmd; 	/* Command string */
	char *param; 	/* Parameter string */
} pf;

/* Message row */
typedef struct {
	char *mid; 	/* Message id */
	char *from; 	/* Sender id */
	char *to; 	/* Receiver id */
	char *msg; 	/* Message string */
} mrowf;

/*
 * Constants
 */
#define BDM_DB "/var/tmp/bismark/db/bdm.db"
#define LOG_DIR "/var/tmp/bismark/log/devices/"

#define MAX_NUM_THREAD 50
#define MAX_UDP_PSIZE 1472
#define MAX_QUERY_LEN 1000
#define MAX_IP_LEN 16
#define MAX_FILENAME_LEN 50

/*
 * Globals
 */
int num_thread; 	/* Threads counter */
struct sockaddr_in sad; /* Server-side socket info */
int ssd; 		/* Server socket descriptor */

/* Mutex */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_db = PTHREAD_MUTEX_INITIALIZER;

/*
 * Query callback function
 */
static int callback(void *out, int argc, char **argv, char **azColName)
{
	char *tmp;

	/* Parse row */
	if (argc == 1) {
		/* One column */
		tmp = calloc(1, strlen(argv[0]) + 1);
		strncpy(tmp, argv[0], strlen(argv[0]));
	} else if (argc > 1) {
		/* More columns */
		int i, p, len;

		/* Compute row len */
		for (i = 0, len = 0; i < argc; i++) {
			len += strlen(argv[i]) + 1;
		}

		/* Create output string */
		tmp = calloc(1, len);
		for (i = 0, p = 0; i < argc - 1; i++) {
			snprintf(&tmp[p], (len - p), "%s ", argv[i]);
			p = strlen(tmp);
		}
		snprintf(&tmp[p], (len - p), "%s", argv[i]);
	} else {
		/* No result */
		tmp = NULL;
	}

	/* Set output */
	*(char **)out = tmp;

	return 0;
}

/*
 * Execute a query (thread safe)
 */
char *do_query(sqlite3 *db, const char *query, const int cb)
{
	char *out = NULL, *err = 0;

	pthread_mutex_lock(&mutex_db);
	if (sqlite3_exec(db, query, cb ? callback : NULL, &out, &err) != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
	}
	pthread_mutex_unlock(&mutex_db);

	return out;
}

/*
 * Probe handler thread
 */
void *doit(void *param)
{
	thp *tp = (thp *) param; 	/* Thread parameters */
	char query[MAX_QUERY_LEN]; 	/* Query string buffer */
	time_t ts; 			/* Current timestamp */
	pf probe; 			/* Probe dissection */
	char ip[MAX_IP_LEN]; 		/* Client IP address */
	sqlite3 *db; 			/* DB handler */
	int thread_id; 			/* Thread identifier */
	char *reply = NULL; 		/* Reply message */
	char date[25]; 			/* Date string */
	int i;

	/* Get thread identifier */
	pthread_mutex_lock(&mutex);
	thread_id = num_thread++;
	pthread_mutex_unlock(&mutex);

	/* Get client IP address */
	strncpy(ip, (const char *) inet_ntoa(tp->cad.sin_addr), 16);

	/* Get timestamp */
	ts = time(NULL);
	strftime(date, sizeof(date), "%Y/%m/%d %H:%M:%S", localtime(&ts));

	/* Parse probe packet payload */
	probe.id = tp->payload;
	for (i = 0; tp->payload[i] != ' '; i++)	;
	probe.cmd = &tp->payload[i + 1];
	for (tp->payload[i] = 0; tp->payload[i] != ' '; i++);
	probe.param = &tp->payload[i + 1];
	for (tp->payload[i] = 0; tp->payload[i] != '\n'; i++);
	tp->payload[i] = 0;

	/* Output log entry */
	printf("%s - \"%s %s\" from %s [%s]\n", date, probe.cmd, probe.param, probe.id, ip);

	/* Open db */
	if (sqlite3_open(BDM_DB, &db)) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}

	/* Parse command */
	if (!strncmp(probe.cmd, "ping", 4)) {
		/* Ping */
		char *row; 	/* Query result row */

		/* Check device presence in db */
		snprintf(query, MAX_QUERY_LEN, "SELECT id FROM devices WHERE id='%s';", probe.id);
		if (do_query(db, query, 1)) {
			/* Update db entry */
			snprintf(query, MAX_QUERY_LEN, "UPDATE devices SET ip='%s',ts=%lu,version=%s WHERE id='%s';", ip, ts, probe.param,
				probe.id);
			do_query(db, query, 0);
		} else {
			/* Insert new db entry */
			snprintf(query, MAX_QUERY_LEN, "INSERT INTO devices (id, ip, ts, version) VALUES('%s','%s',%lu,'%s');", probe.id,
				ip, ts, probe.param);
			do_query(db, query, 0);
		}

		/* Check messages */
		snprintf(query, MAX_QUERY_LEN, "SELECT rowid,* FROM messages WHERE \"to\"='%s' LIMIT 1;", probe.id);
		if ((row = do_query(db, query, 1))) {
			mrowf msg; 	/* Message row fields */

			/* Parse query result */
			msg.mid = row;
			for (i = 0; row[i] != ' '; i++);
			msg.from = &row[i + 1];
			for (row[i] = 0; row[i] != ' '; i++);
			msg.to = &row[i + 1];
			for (row[i] = 0; row[i] != ' '; i++);
			msg.msg = &row[i + 1];
			row[i] = 0;

			/* Set reply message */
			reply = malloc(strlen(msg.msg) + 2);
			sprintf(reply, "%s\n", msg.msg);

			/* Output log entry */
			printf("%s - Delivered message from %s to %s: %s\n", date, msg.from, msg.to, msg.msg);

			/* Remove message from db */
			snprintf(query, MAX_QUERY_LEN, "DELETE FROM messages WHERE rowid='%s';", msg.mid);
			do_query(db, query, 0);
			free(row);
		} else {
			/* Set pong reply */
			reply = malloc(MAX_IP_LEN + 7);
			sprintf(reply, "pong %s\n", ip);
		}
	} else if (!strncmp(probe.cmd, "log", 3)) {
		/* Log */
		FILE *lfp;			/* Log file pointer */
		char logfile[MAX_FILENAME_LEN];	/* Log file name */
		char *log = &tp->payload[i + 1];	/* Log data in current packet */

		/* Append log to logfile */
		snprintf(logfile, MAX_FILENAME_LEN, "%s/%s.log", LOG_DIR, probe.id);
		lfp = fopen(logfile, "a");
		fprintf(lfp, "%s - %s\n%s\n", date, probe.param, log);
		fclose(lfp);

		/* Send message to bdm client */
		snprintf(query, MAX_QUERY_LEN, "INSERT INTO messages ('from', 'to', msg) VALUES('%s','BDM','%s');", probe.id, probe.param);
		do_query(db, query, 0);
	}

	/* Close db */
	sqlite3_close(db);

	/* Send reply to client */
	if (reply) {
		sendto(ssd, reply, strlen(reply), 0, (struct sockaddr*) &tp->cad, sizeof(tp->cad));
		free(reply);
	}
	free(tp->payload);
	free(tp);

	/* Update threads counter */
	pthread_mutex_lock(&mutex);
	num_thread--;
	pthread_mutex_unlock(&mutex);

	return NULL;
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	unsigned short server_port; 	/* Server port number */
	pthread_t hThr[MAX_NUM_THREAD]; /* Threads handlers */
	int i = 0;

	/* Command-line check */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		return 0;
	}

	/* Port number parsing */
	server_port = atoi(argv[1]);
	if (server_port < 0 || server_port > 65534) {
		fprintf(stderr, "invalid port number: %s\n", argv[1]);
		return 1;
	}

	/* Server-side socket info initialization */
	memset((char *) &sad, 0, sizeof(sad));
	sad.sin_family = AF_INET;
	sad.sin_addr.s_addr = htonl(INADDR_ANY);
	sad.sin_port = htons(server_port);

	/* Socket creation */
	if ((ssd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "error creating socket\n");
		return 1;
	}

	/* Socket binding */
	if (bind(ssd, (struct sockaddr *) &sad, sizeof(sad)) < 0) {
		fprintf(stderr, "bind fallito\n");
		return 1;
	}

	printf("Bdmd listening on port %d\n", server_port);

	/* Infinite loop */
	while (1) {
		char payload[MAX_UDP_PSIZE];	/* Temporary buffer to store payload */
		struct sockaddr_in cad;		/* Temporary Client-side socket info */
		socklen_t cadlen;		/* Client-side socket info length */
		thp *ntp;			/* New thread parameters */
		int bytes;

		/* Listen for probe packets */
		cadlen = sizeof(struct sockaddr_in);
		bytes = recvfrom(ssd, payload, MAX_UDP_PSIZE, 0, (struct sockaddr*) &cad, &cadlen);
		if (bytes <= 0) {
			fprintf(stderr, "error receiving probe packet\n");
			continue;
		}

		/* Prepare thread parameters */
		ntp = malloc(sizeof(thp));
		ntp->cad = cad;
		ntp->payload = calloc(1, bytes + 1);
		strncpy(ntp->payload, payload, bytes);

		/* Check max thread number */
		if (num_thread >= MAX_NUM_THREAD) {
			fprintf(stderr, "max connections reached: refusing connection from %s\n", (char *) inet_ntoa(cad.sin_addr));
		} else {
			/* Create thread to handle the connection */
			if (pthread_create(&hThr[i], NULL, doit, ntp) < 0) {
				fprintf(stderr, "error creating thread\n");
			}
		}
	}

	/* Close socket */
	close(ssd);
}
