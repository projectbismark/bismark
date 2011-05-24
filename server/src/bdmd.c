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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sqlite3.h>

/*
 * Types
 */
/* Thread parameter */
typedef struct {
	struct sockaddr_in cad; /* Client-side socket info */
	char *payload; 		/* Received payload */
	unsigned int ssd_idx;	/* Listening socket index */
} thp;

/* Config */
typedef struct {
	char *var_dir;
	char *msr_db;
	char *bdm_db;
	char *msg_db;
	char *log_dir;
} config_t;

/* Probe format */
typedef struct {
	char *id; 	/* Device id */
	char *cmd; 	/* Command string */
	char *param; 	/* Parameter string */
} pf;

/* Message format */
typedef struct {
	char *mid; 	/* Message id */
	char *from; 	/* Sender id */
	char *to; 	/* Receiver id */
	char *msg; 	/* Message string */
} mf;

/* Measure request format */
typedef struct {
	char *cat; 	/* Target category */
	char *type; 	/* Measurement type */
	char *zone;	/* Client location */
	char *duration; /* Measurement duration */
} mrf;

/* Measure target format */
typedef struct {
	char *ip; 	/* IP address */
	char *info; 	/* Additional info */
	char *free_ts; 	/* Free timestamp */
	char *curr_cli; /* Current clients count */
	char *max_cli;	/* Max clients count */
} mtf;

/*
 * Constants
 */
#define BDM_DB "db/bdm.db"
#define MSG_DB "db/msg.db"
#define MSR_DB "db/msr.db"
#define LOG_DIR "log/devices"

#define MAX_NUM_THREAD 250
#define MAX_PORTS 10
#define MAX_UDP_PSIZE 1472
#define MAX_QUERY_LEN 1000
#define MAX_IP_LEN 16
#define MAX_TS_LEN 10
#define MAX_INFO_LEN 30
#define MAX_WAIT_LEN 5
#define MAX_FILENAME_LEN 50

#define RCV_BUFF_SIZE 300000

/*
 * Globals
 */
int num_thread; 	/* Threads counter */
struct sockaddr_in sad; /* Server-side socket info */
int ssd[MAX_PORTS]; 	/* Server socket descriptors */
config_t config;	/* Config variables */

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

int blacklisted(sqlite3 *db, const char *device)
{
	char query[MAX_QUERY_LEN]; 		/* Query string buffer */
	char *row; 				/* Query resulting row */

	/* Check if device is blacklisted */
	snprintf(query, MAX_QUERY_LEN, "SELECT id FROM blacklist WHERE id='%s';", device);
	if ((row = do_query(db, query, 1))) {
		free(row);
		return 1;
	} else
		return 0; 
}

/*
 * Probe handler thread
 */
void *doit(void *param)
{
	thp *tp = (thp *) param; 		/* Thread parameters */
	char query[MAX_QUERY_LEN]; 		/* Query string buffer */
	time_t ts; 				/* Current timestamp */
	pf probe; 				/* Probe dissection */
	char ip[MAX_IP_LEN]; 			/* Client IP address */
	sqlite3 *bdm_db, *msg_db, *msr_db;	/* DB handlers */
	int thread_id; 				/* Thread identifier */
	char *reply = NULL; 			/* Reply message */
	char date[25]; 				/* Date string */
	char *row; 				/* Query resulting row */
	int i;

	/* Get thread identifier */
	pthread_mutex_lock(&mutex);
	thread_id = num_thread++;
	pthread_mutex_unlock(&mutex);

	/* Get client IP address */
	strncpy(ip, inet_ntoa(tp->cad.sin_addr), 16);

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

#ifdef DEBUG
	/* Output log entry */
	printf("%s - \"%s %s\" from %s [%s]\n", date, probe.cmd, probe.param, probe.id, ip);
	fflush(stdout);
#endif
	/* Open bdm db */
	if (sqlite3_open(config.bdm_db, &bdm_db)) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(bdm_db));
		sqlite3_close(bdm_db);
		free(tp);
		pthread_exit(NULL);
	}

	/* Parse command */
	if (!strncmp(probe.cmd, "ping", 4)) {
		/* Ping */

		/* Check device presence in db */
		snprintf(query, MAX_QUERY_LEN, "SELECT id FROM devices WHERE id='%s';", probe.id);
		if ((row = do_query(bdm_db, query, 1))) {
			/* Update db entry */
			snprintf(query, MAX_QUERY_LEN, "UPDATE devices SET ip='%s',ts=%lu,version=%s WHERE id='%s';", ip, ts, probe.param,
				probe.id);
			do_query(bdm_db, query, 0);
			free(row);
		} else {
			/* Insert new db entry */
			snprintf(query, MAX_QUERY_LEN, "INSERT INTO devices (id, ip, ts, version) VALUES('%s','%s',%lu,'%s');", probe.id,
				ip, ts, probe.param);
			do_query(bdm_db, query, 0);
		}

		/* Check messages */
		sqlite3_open(config.msg_db, &msg_db);
		snprintf(query, MAX_QUERY_LEN, "SELECT rowid,* FROM messages WHERE \"to\"='%s' LIMIT 1;", probe.id);
		if ((row = do_query(msg_db, query, 1))) {
			mf msg; 	/* Message row fields */

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
			fflush(stdout);

			/* Remove message from db */
			snprintf(query, MAX_QUERY_LEN, "DELETE FROM messages WHERE rowid='%s';", msg.mid);
			do_query(msg_db, query, 0);

			/* Remove row */
			free(row);
		} else {
			if (!blacklisted(bdm_db, probe.id)) {
				/* Set pong reply */
				reply = malloc(MAX_IP_LEN + MAX_TS_LEN + 7);
				sprintf(reply, "pong %s %lu\n", ip, ts);
			} 
		}
		sqlite3_close(msg_db);	
	} else if (!strncmp(probe.cmd, "log", 3)) {
		/* Log */
		FILE *lfp;				/* Log file pointer */
		char logfile[MAX_FILENAME_LEN];		/* Log file name */
		char *log = &tp->payload[i + 1];	/* Log data in current packet */

		/* Append log to logfile */
		snprintf(logfile, MAX_FILENAME_LEN, "%s/%s.log", config.log_dir, probe.id);
		lfp = fopen(logfile, "a");
		fprintf(lfp, "%s - %s\n%s\nEND - %s\n", date, probe.param, log, probe.param);
		fclose(lfp);

		/* Send message to bdm client */
		sqlite3_open(config.msg_db, &msg_db);
		snprintf(query, MAX_QUERY_LEN, "INSERT INTO messages ('from', 'to', msg) VALUES('%s','BDM','%s');", probe.id, probe.param);
		do_query(msg_db, query, 0);
		sqlite3_close(msg_db);

		/* Output log entry */
		printf("%s - Received log from %s: %s\n", date, probe.id, probe.param);
		fflush(stdout);
	} else if (!strncmp(probe.cmd, "measure", 7)) {
		/* Measure */
		mrf request;
		mtf target;
		char *exclusive;

		/* Parse request */
		request.cat = probe.param;
		for (i = 0; probe.param[i] != ' '; i++);
		request.type = &probe.param[i + 1];
		for (probe.param[i] = 0; probe.param[i] != ' '; i++);
		request.zone = &probe.param[i + 1];
		for (probe.param[i] = 0; probe.param[i] != ' '; i++);
		request.duration = &probe.param[i + 1];
		probe.param[i] = 0;

		/* Query target (prefer target with less clients and closest free timestamp) */
		sqlite3_open(config.msr_db, &msr_db);
		snprintf(query, MAX_QUERY_LEN, "SELECT t.ip,info,free_ts,curr_cli,max_cli FROM targets AS t, capabilities AS c "
					       "WHERE t.ip=c.ip AND service='%s' AND cat='%s' AND zone='%s' ORDER BY curr_cli,free_ts ASC LIMIT 1;",
					       request.type, request.cat, request.zone);
		if (!(row = do_query(msr_db, query, 1))) {
			/* Repeat query without zone */
			snprintf(query, MAX_QUERY_LEN, "SELECT t.ip,info,free_ts,curr_cli,max_cli FROM targets AS t, capabilities AS c "
						       "WHERE t.ip=c.ip AND service='%s' AND cat='%s' ORDER BY curr_cli,free_ts ASC LIMIT 1;",
						       request.type, request.cat);
			row = do_query(msr_db, query, 1);
		}

		/* Parse query result */
		target.ip = row;
		for (i = 0; row[i] != ' '; i++);
		target.info = &row[i + 1];
		for (row[i] = 0; row[i] != ' '; i++);
		target.free_ts = &row[i + 1];
		for (row[i] = 0; row[i] != ' '; i++);
		target.curr_cli = &row[i + 1];
		for (row[i] = 0; row[i] != ' '; i++);
		target.max_cli = &row[i + 1];
		row[i] = 0;

		/* Get measure type mode */
		snprintf(query, MAX_QUERY_LEN, "SELECT exclusive FROM mtypes WHERE type='%s';", request.type);
		exclusive = do_query(msr_db, query, 1);

		/* Process request */
		reply = malloc(MAX_IP_LEN + MAX_INFO_LEN + MAX_WAIT_LEN + 4);
		if (*exclusive == '1') {
			/* Exclusive request (only mutual exclusion for now) */
			if (ts > atoi(target.free_ts)) {
				/* Set reply */
				sprintf(reply, "%s %s %d\n", target.ip, target.info, 0);

				/* Update target entry */
				snprintf(query, MAX_QUERY_LEN, "UPDATE targets SET free_ts=%lu WHERE ip='%s';",
					ts + atoi(request.duration) + 2, target.ip);
				do_query(msr_db, query, 0);

				/* Output log entry */
				printf("%s - Scheduled %s measure from %s to %s at %lu for %s seconds\n", date, request.type, probe.id, target.ip, ts, request.duration);
				fflush(stdout);
			} else {
				unsigned int delay = atoi(target.free_ts) - ts + 2;
				if (delay > 300) delay = 300;

				/* Set reply */
				sprintf(reply, "%s %s %u\n", target.ip, target.info, delay);

				/* Update target entry */
				snprintf(query, MAX_QUERY_LEN, "UPDATE targets SET free_ts=%lu WHERE ip='%s';",
					atol(target.free_ts) + atoi(request.duration) + 2, target.ip);
				do_query(msr_db, query, 0);

				/* Output log entry */
				printf("%s - Scheduled %s measure from %s to %s at %s for %s seconds\n", date, request.type, probe.id, target.ip, target.free_ts, request.duration);
				fflush(stdout);
			}
		} else {
			/* Set reply */
			sprintf(reply, "%s %s %d\n", target.ip, target.info, 0);

			/* Output log entry */
			printf("%s - Scheduled %s measure from %s to %s at %lu for %s seconds\n", date, request.type, probe.id, target.ip, ts, request.duration);
			fflush(stdout);
		}
		sqlite3_close(msr_db);

		/* Free memory */
		free(exclusive);
		free(row);
	}

	/* Send reply to client */
	if (reply) {
		sendto(ssd[tp->ssd_idx], reply, strlen(reply), 0, (struct sockaddr*) &tp->cad, sizeof(tp->cad));

		/* Post delivery actions */
		if (!strncmp(reply, "fwd", 3)) {
			reply[strlen(reply) - 1] = 0;
			reply[3] = 0;
			snprintf(query, MAX_QUERY_LEN, "INSERT INTO tunnels VALUES('%s',%d,%lu);", probe.id, atoi(&reply[4]), ts + 15);
			do_query(bdm_db, query, 0);
		}

		free(reply);
	}
	free(tp->payload);
	free(tp);

	/* Close db */
	sqlite3_close(bdm_db);

	/* Update threads counter */
	pthread_mutex_lock(&mutex);
	num_thread--;
	pthread_mutex_unlock(&mutex);

	pthread_exit(NULL);
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	unsigned short server_ports[MAX_PORTS]; /* Server port numbers */
	unsigned short num_ports = 0;		/* Number of listening ports */
        int max_sd = 0;              		/* Biggest socket descriptor */
        fd_set lset;          			/* Socket descriptors listening set */
        fd_set rset;            		/* Socket descriptors returned by select */
	pthread_t hThr; 			/* Thread handler */
	time_t ts; 				/* Current timestamp */
	char date[25]; 				/* Date string */
	unsigned int rcv_buff_size = RCV_BUFF_SIZE;
	int i = 0, j = 0;

	/* Command-line check */
	if (argc < 2) {
		fprintf(stderr, "usage: %s <port> [ [port] ... ]\n", argv[0]);
		return 0;
	}

	/* Get port numbers */
	for (i=1; i<argc; i++) {
		server_ports[i-1] = atoi(argv[i]);
		num_ports++;
	}

	/* Set config variables */
	config.var_dir = getenv("VAR_DIR");
	if (!config.var_dir) config.var_dir = strdup("/var");
	config.msr_db = malloc(strlen(config.var_dir) + sizeof(MSR_DB) + 3);
	sprintf(config.msr_db, "%s/%s", config.var_dir, MSR_DB);
	config.msg_db = malloc(strlen(config.var_dir) + sizeof(MSG_DB) + 3);
	sprintf(config.msg_db, "%s/%s", config.var_dir, MSG_DB);
	config.bdm_db = malloc(strlen(config.var_dir) + sizeof(BDM_DB) + 3);
	sprintf(config.bdm_db, "%s/%s", config.var_dir, BDM_DB);
	config.log_dir = malloc(strlen(config.var_dir) + sizeof(LOG_DIR) + 3);
	sprintf(config.log_dir, "%s/%s", config.var_dir, LOG_DIR);

	/* Get timestamp */
	ts = time(NULL);
	strftime(date, sizeof(date), "%Y/%m/%d %H:%M:%S", localtime(&ts));

	/* Output log entry */
	printf("%s - Listening to probe packets on ports: ", date);
	fflush(stdout);
	
	/* Prepare set of listening sockets */
        FD_ZERO(&lset);
	for (j=0; j<num_ports; j++) {
		/* Check port number */
		if (server_ports[j] < 0 || server_ports[j] > 65534) {
			fprintf(stderr, "warning: invalid port %u\n", server_ports[j]);
			continue;
		}
		if (server_ports[j] < 1024 && getuid() > 0) {
			fprintf(stderr, "warning: skipping port %u - root priviledges needed\n", server_ports[j]);
			continue;
		}

		/* Server-side socket info initialization */
		memset((char *) &sad, 0, sizeof(sad));
		sad.sin_family = AF_INET;
		sad.sin_addr.s_addr = htonl(INADDR_ANY);
		sad.sin_port = htons(server_ports[j]);

		/* Socket creation */
		if ((ssd[j] = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			fprintf(stderr, "warning: unable to create socket %u\n", j);
			continue;
		}

		/* Set the receive buffer length */
		setsockopt(ssd[j], SOL_SOCKET, SO_RCVBUF, &rcv_buff_size, sizeof(rcv_buff_size));

		/* Socket binding */
		if (bind(ssd[j], (struct sockaddr *) &sad, sizeof(sad)) < 0) {
			fprintf(stderr, "warning: bind fallito\n");
			continue;
		}
		
		/* Add socket to the set */
		if (ssd[j] > max_sd) 
			max_sd = ssd[j];
		FD_SET(ssd[j], &lset);

		/* Output log entry */
		printf("%u ", server_ports[j]);
		fflush(stdout);
	}

	/* Output log entry */
	printf("\n");
	fflush(stdout);

	/* Infinite loop */
	while (1) {
		char payload[MAX_UDP_PSIZE];	/* Temporary buffer to store payload */
		struct sockaddr_in cad;		/* Temporary Client-side socket info */
		socklen_t cadlen;		/* Client-side socket info length */
		thp *ntp;			/* New thread parameters */
		struct timeval time_out;	/* Select timeout value */
		int ready_sds;			/* Number of detected events */
		int bytes;

                /* Update select parameters */
                rset = lset;
                time_out.tv_sec = 5;
                time_out.tv_usec = 0;

		/* Wait for events on the socket descriptors set */
                if ((ready_sds = select(max_sd + 1, &rset, NULL, NULL, &time_out)) < 0) {
                        perror("warning: select failed");
                        continue;
                }

                /* Timeout expired */
                if (ready_sds == 0)
                        continue;

		/* Check all sockets for events */
		for (j=0; j<num_ports; j++) {
	                if (FD_ISSET(ssd[j], &rset)) {
				/* Read packet from socket */
				cadlen = sizeof(struct sockaddr_in);
				bytes = recvfrom(ssd[j], payload, MAX_UDP_PSIZE, 0, (struct sockaddr*) &cad, &cadlen);
				if (bytes <= 0) {
					fprintf(stderr, "error receiving probe packet\n");
					continue;
				}

				/* Prepare thread parameters */
				ntp = malloc(sizeof(thp));
				ntp->cad = cad;
				ntp->payload = calloc(1, bytes + 1);
				strncpy(ntp->payload, payload, bytes);
				ntp->ssd_idx = j;

				/* Check max thread number */
				if (num_thread >= MAX_NUM_THREAD) {
					char reply[MAX_QUERY_LEN];
					
					sprintf(reply, "pong %s %lu\n", inet_ntoa(cad.sin_addr), time(NULL));
					sendto(ssd[j], reply, strlen(reply), 0, (struct sockaddr*) &cad, sizeof(cad));
					fprintf(stderr, "max threads reached: quick reply to %s\n", (char *) inet_ntoa(cad.sin_addr));
					free(ntp);
				} else {
					/* Create thread to handle the connection */
					if (pthread_create(&hThr, NULL, doit, ntp) < 0) {
						fprintf(stderr, "warning: unable to create thread\n");
					} else {
						pthread_detach(hThr);
					}
				}
			}
		}
	}

	/* Close socket */
	for (j=0; j<num_ports; j++) {
		close(ssd[j]);
	}
}
