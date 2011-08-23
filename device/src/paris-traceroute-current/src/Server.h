#ifndef __SERVER_H__
#define __SERVER_H__

#include "Reply.h"
#include "Tracert.h"

#include <pthread.h>
#ifdef USEPCAP
#include <pcap.h>
#endif
/**
 * This class implements a thread which will capture all traffic from one 
 * protocol (tcp or icmp).
 */
class Server {
	private:
		Tracert**	client;
		int*				client_id;
		Options*	opts;
		int		sock_server;
		pthread_t	thread;
		pthread_mutex_t	lock;
		bool		stop_thread;
#ifdef USEPCAP
		pcap_t *handle;
		int pcap_fd;
#endif		
	public:
		Server (Options* opts, const char* protocol);
		~Server ();
		void runThread   ();
		void startThread ();
		void stopThread  ();
		void setClient (Tracert* client);
		void addClient (Tracert* client, int i);
};

#endif // __SERVER_H__

