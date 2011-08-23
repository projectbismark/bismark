#include "Server.h"
#include "common.h"
#include "TrException.h"
#include "Reply.h"
#include "Util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef USEPCAP
#include <pcap.h>
#endif

/**
 * C callback function used to start the Server thread
 */
void*
server_run_thread (void* arg) {
  Server* server = (Server*)arg;
  server->runThread();
  return NULL;
}

/**
 * Create a new <i>Server</i> to listen incoming message.
 *
 * @param client The class to notify when a message arrives.
 * @param addr The server will listen for incoming messages from this address
 *             (in network endianess).
 * @param port The server will listen for incoming messages on this port.
 * @param protocol The protocol to listen ("icmp", "tcp").
 *
 * @throw TrException An error occured.
 */
Server::Server (Options* opts, const char* protocol) {
	int res;
	
  // Initialisation
  this->client   = new Tracert*[opts->threads_count];
  this->client[0]   = NULL;
  this->client_id =  new int[opts->threads_count];
  this->opts     = opts;

  stop_thread    = true;

#ifdef USEPCAP
	//pcap_t *handle;
	char *dev;
	bpf_u_int32 mask;		/* Our netmask */	bpf_u_int32 net;		/* Our IP */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */	char filter_exp[] = "tcp or icmp";	/* The filter expression */
		
	/* Define the device */	dev = pcap_lookupdev(errbuf);	if (dev == NULL) {		throw TrException(str_log(ERROR, "Couldn't find default device: %s\n", errbuf));	}	/* Find the properties for the device */	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);		net = 0;		mask = 0;	}	handle = pcap_open_live(dev, BUFSIZ, 0, 10, errbuf);	if (handle == NULL) {		throw TrException(str_log(ERROR, "Couldn't open device %s: %s\n", dev, errbuf));
	}
	
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		throw TrException(str_log(ERROR, "%s is not an Ethernet\n", dev));
	}
		/* Compile and apply the filter */	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {		throw TrException(str_log(ERROR, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)));	}

	if (pcap_setfilter(handle, &fp) == -1) {		throw TrException(str_log(ERROR, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)));	}
	
	pcap_fd = pcap_fileno(handle);
	if (fcntl(pcap_fd, F_SETFL, O_NONBLOCK) < 0)
		throw TrException(str_log(ERROR, "fcntl(F_SETFL, O_NONBLOCK) failed"));
	
	printf("pcap on %s\n", dev);
	
#else

  // Create the socket
  sock_server = socket(AF_INET, SOCK_RAW, Util::protocol2int(protocol));
  if (sock_server < 0) throw TrException(str_log(ERROR,
			"Cannot create the server : %s", strerror(errno)));

// WHAT FOR ???
#if 0
  // Set timeout on the socket : 5000 usec
  struct timeval tv;
  tv.tv_sec  = 0;
  tv.tv_usec = 5000;
  int res = setsockopt(sock_server,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(timeval));
  if (res < 0) throw TrException(str_log(ERROR, "Set timeout failed : %s",
                                                strerror(errno)));
#endif

  // Bind it
  sockaddr_in saddr;
  memset(&saddr, 0, sizeof(sockaddr_in));
  saddr.sin_family      = AF_INET;
  saddr.sin_port        = htons(opts->src_port);
  //printf("NO BIND\n");
  
  res = bind(sock_server, (sockaddr*)&saddr, sizeof(sockaddr_in));
  if (res < 0) throw TrException(str_log(ERROR,		"Cannot bind the server : %s", strerror(errno)));

#endif // USEPCAP

  // Create a mutex
  res = pthread_mutex_init(&lock, NULL);
  if (res != 0) throw TrException(str_log(ERROR, "Create a mutex"));
}

/**
 * Stop the server.
 */
Server::~Server () {
  log(INFO, "delete server");
  stopThread();
  log(INFO, "stop thread done");
  //close(sock_server);
  log(INFO, "close socket done");
// STRANGE: uder linux, the recvfrom wont unblock when we  
// close the socket if there is no timeour on the socket. 
#if 0  
  pthread_join(thread, NULL);
  log(INFO, "join done");
#endif  
  pthread_mutex_destroy(&lock);
  log(INFO, "destroy mutex done");
}

/**
 * Start the thread.
 */
void
Server::startThread () {
  // Create and execute the listening thread
  stop_thread = false;
  int res = pthread_create(&thread, NULL, server_run_thread, this);
  if (res != 0) throw TrException(str_log(ERROR, "Create a thread"));
}

/**
 * Stop the thread.
 */
void
Server::stopThread () {
  pthread_mutex_lock(&lock);
  stop_thread = true;
  //fprintf(stderr, "[13]\n");
  pthread_mutex_unlock(&lock);
}

/**
 * Set/change the client to notify.
 */
void
Server::setClient (Tracert* client) {
  pthread_mutex_lock(&lock);
  this->client[0] = client;
  //fprintf(stderr, "[14]\n");
  pthread_mutex_unlock(&lock);
}

void
Server::addClient (Tracert* client, int i) {
  pthread_mutex_lock(&lock);
  //if (opts->debug)
  //	printf("addClient: %x\n", client); 
  this->client[i] = client;
  //fprintf(stderr, "[15]\n");
  pthread_mutex_unlock(&lock);
}

/**
 * Capture all messages and notify the client.
 * 
 * In the constructor of this class, we have specified one protocol. This
 * thread will listen and capture all messages from this protocol. It
 * will then wrap the message into a reply (ICMPReply for the ICMP protocol
 * and TCPReply for the TCP protocol). Finally, it will notify the client that
 * a new probable reply has arrived. It is up to the client to distinguish
 * between a reply of a probe or junk traffic.
 */
void
Server::runThread () {
  uint8 *data;
  int data_len;
  struct timeval *tv = NULL;
  int packet_count = 0;
  fd_set sfd;
  
  log(INFO, "waiting for the first packet..\n");
  while (1) {
  	
  	pthread_mutex_lock(&lock);	
  	if (stop_thread)
  		break;
  	//fprintf(stderr, "[16]\n");
    pthread_mutex_unlock(&lock);

#ifdef USEPCAP
		
		FD_ZERO(&sfd);
		FD_SET(pcap_fd, &sfd);

		int ret = select(pcap_fd + 1, &sfd, NULL, NULL, NULL);

		if (ret < 0)
		{
			log(WARN, "select failed\n");
			exit(1);
		}
		else if (ret == 0)
		{
			log(WARN, "select timeout\n");
			continue;
		}

		
		struct pcap_pkthdr header;
			
		data = (uint8 *)pcap_next(this->handle, &header);
		// go to the IP header
		data_len = header.len;

		if (data == NULL)
			data_len = 0;
		data += 14;
		
		tv = &header.ts;
		
		//printf("pcap %d bytes\n", data_len);
#else
    // Wait a message, TODO: don't limit the reply size to 1024
    sockaddr_in from;
    
    from.sin_family = AF_INET;
    from.sin_port = htons(33456);
		from.sin_addr.s_addr = INADDR_ANY;

    int         from_len = sizeof(sockaddr_in);
    uint8	buffer[1024];
    data = buffer;
    //printf("runThread, recvfrom\n");
    data_len = recvfrom(sock_server, buffer, 1024, 0,		(sockaddr*)&from, (socklen_t*)&from_len);
    //int data_len = read(sock_server, data, 1024);
    //printf("runThread, recvfom done\n");
#endif

		if (data_len > 0) {
			if (packet_count == 0)
				log(INFO, "Captured first packet!\n");
			
			packet_count++;
			
			log(DUMP, "Incoming message :");
		  log(DUMP, "parsing.. %x %d", data, data_len);
		  dumpRawData(DUMP, data, data_len);
			
			Reply* reply = Reply::replyFactory(data, data_len);
			log(DUMP, "Incoming message parsed :");
			reply->dump();
			//printf("server locking...\n");
			pthread_mutex_lock(&lock);
			//printf("server locked\n");
			// XXX temp for UDP
			//reply->proc_id = opts->proc_id;
			
			// validate the reply
			uint16 id = reply->getProcId();
			
			#ifdef DEVANOMALIES
			// source port
			id = reply->getID3();
			#else  
			id = reply->getID();
			#endif
			//id = reply->getIPId();
			//printf("server, id %d\n", id);
			//      
			//      if (id > 20000) {
			//      	printf("dumpraw\n");
			//      	reply->dumpRaw();
			//      }
			//id = (id & 0xffff) >> (16 - 5);
			
			//printf("id = 0x%x %d\n", id, id);
			
			#ifdef DEVANOMALIES
			id = (id - 32000) / (32000 / opts->threads_count);
			#else
			id = id / (65536 / opts->threads_count);
			#endif
			
			//printf("client id = %d\n", id);
			
			if (id < 0 || id >= 32)
				log(FATAL, "bug, id can't be greater than 31");
			reply->proc_id = opts->proc_id;
			
			//if (opts->debug)
			//printf("runthread, locked, notifyrelply %d %x\n", id, client[id]);
			// DEVANOMALIES: the single client will recive all responses
			if (client[id] != NULL) client[id]->notifyReply(reply, tv);
			//printf("runthread, unlocked notifyreply done\n");
			delete(reply);
			
			//fprintf(stderr, "[10]\n");
			pthread_mutex_unlock(&lock);
  	}
    //pthread_mutex_lock(&lock);
  }
  // Otherwise NetBSD will cry
  //fprintf(stderr, "[11]\n");
  pthread_mutex_unlock(&lock);
}

