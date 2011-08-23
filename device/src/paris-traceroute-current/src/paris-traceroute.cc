#include "common.h"
#include "Options.h"
#include "Util.h"
#include "Server.h"
#include "Tracert.h"
#include "Output.h"
#include "MtTracert.h"
#include "Bandwidth.h"

#include <stdio.h>
#include <unistd.h>

#include <pthread.h>

int main (int argc, char** argv) {
#ifdef DEVANOMALIES	
	printf("device anomalies\n");
#endif	

	//printf("check bad flow id\n");	

  // Check CAP_NET_RAW capabilities
  if (getuid() != 0) {
    //log(FATAL, "You must be root to run this program");
    //exit(-1);
  }
  
  int i = 0xfeff;
  uint16 u = (uint16)i;
  uint16 sw_id1 = (u << 8) | (u >> 8);
  
  //printf("test %x\n", sw_id1);
  //return 0;
  
  Time* currt = new Time ();

  // Initialisation
  Options* opts        = new Options(argc, argv);
  Tracert* traceroute  = NULL;
  Server*  icmp_server = NULL;
  Server*  tcp_server  = NULL;
  opts->dump();

  // Select an algorithm
  int algo = NULL_TRACERT;
  if (strncmp(opts->algo, "hopbyhop", strlen(opts->algo)) == 0) {
    algo = HOPBYHOP_TRACERT;
  } else if (strncmp(opts->algo, "packetbypacket", strlen(opts->algo)) == 0) {
    algo = PACKBYPACK_TRACERT;
  } else if (strncmp(opts->algo, "test", strlen(opts->algo)) == 0) {
    algo = TEST_TRACERT;
  } else if (strncmp(opts->algo, "concurrent", strlen(opts->algo)) == 0) {
    algo = CONCURRENT_TRACERT;
  } else if (strncmp(opts->algo, "scout", strlen(opts->algo)) == 0) {
    if (strncmp(opts->protocol, "udp", 5) != 0) {
      log(WARN, "Scout algo is only usable with udp => hopbyhopalgo");
      algo = HOPBYHOP_TRACERT;
    } else { 
    	algo = SCOUT_TRACERT;
    	//printf("SCOUT\n");
    }
  } else if (strncmp(opts->algo, "new_exhaustive", strlen(opts->algo)) == 0) {
    algo = EXHAUSTIVE_TRACERT;
  } else if (strncmp(opts->algo, "exhaustive", strlen(opts->algo)) == 0) {
    algo = EXHAUSTIVE_OLD_TRACERT;
  } else if (strncmp(opts->algo, "mt", strlen(opts->algo)) == 0) {
    algo = MT_TRACERT;
  } else {
    strcpy(opts->algo, "null");
    // warn user.
    // maybe he made a mistake when typing the so-long-algo-names !
    log(WARN, "Unknown algo (--algo=help for more help)");
  }

	opts->algo_id = algo;

	if (1 || algo == MT_TRACERT) {
		
		FILE *targets = NULL;
		if (opts->targets[0] != 0x00) {
			if ((targets = fopen(opts->targets, "r")) == NULL) {
				log(FATAL, "can't open file\n");
			}
		}
		
		pthread_mutex_t targets_lock;
		pthread_mutex_t output_lock;
		// Create a mutex
  	if (pthread_mutex_init(&targets_lock, NULL) != 0)
  		throw TrException(str_log(ERROR, "Create a mutex"));
  	if (pthread_mutex_init(&output_lock, NULL) != 0)
  		throw TrException(str_log(ERROR, "Create a mutex"));
  	// Create and start servers
  	icmp_server = new Server(opts, "icmp");
  	icmp_server->startThread();	
  	
  	Bandwidth* bw = NULL;
  	//if (opts->bandwidth > 0) {

  	 	bw = new Bandwidth(opts);
  		bw->startThread();
  	//}

  	MtTracert** mt = new MtTracert*[opts->threads_count];
  	bool* terminated = new bool[opts->threads_count];
  	for (int i = 0; i < opts->threads_count; i++) {
  		terminated[i] = false;
  		mt[i] = new MtTracert(opts, i, icmp_server, targets, &targets_lock, &output_lock, bw);
  		//icmp_server->addClient(traceroute, i);
  		mt[i]->startThread();
  	}

		for (int i = 0; i < opts->threads_count; i++)
	  	mt[i]->wait(true);
	  if (opts->targets[0] != 0x00)
	  	printf("Round duration: %d seconds\n", currt->getCurrentSeconds ());
#ifdef UPDATE_STATUS  
  	if (opts->targets[0] != 0x00) {
	  	int count;
	  	do {
	  		count = 0;
	  		int total = 0;
	  		
	  		
	  			sleep(60);
	  		fprintf(stderr, "Terminated ?\n");
	  		for (int i = 0; i < opts->threads_count; i++) {
	  			if (! terminated[i])
	  				terminated[i] = mt[i]->wait(false);
	  			
	  			if (terminated[i])
	  				count++;
	  			
	  			int addr_count = mt[i]->stats();
	  			
	  			total += addr_count;
	  			
	  			fprintf(stderr, " %d %d addresses treated T%d\n", i, addr_count, terminated[i]);
	  		}
	  			
	  		fprintf(stderr, "Total %d addresses\n", total);
	  			
	  	} while (count < opts->threads_count);
	  	
	  	printf("Round duration: %d seconds\n", currt->getCurrentSeconds ());
  	} else {
  		for (int i = 0; i < opts->threads_count; i++)
	  		mt[i]->wait(true);
  	}
#endif
	} else {

		// Create and start servers
	  icmp_server = new Server(opts, "icmp");
	  icmp_server->setClient(traceroute);
	  icmp_server->startThread();
	  if (strncmp(opts->protocol, "tcp", 4) == 0) {
	    tcp_server = new Server(opts, "tcp");
	    tcp_server->setClient(traceroute);
	    tcp_server->startThread();
	  }
	
	  // Main part
	  bool possible = traceroute->trace();
	
	  if (algo == SCOUT_TRACERT) {
	    icmp_server->setClient(NULL);
	    if (strncmp(opts->protocol, "tcp", 4) == 0)
	       tcp_server->setClient(NULL);
	    
	    if (possible) {
	      // Execute concurrent traceroute
	      int reply_ttl = traceroute->getHopInfo(0, 0)->reply_ttl;
	      int ttl_dest  = opts->ttl_max - reply_ttl + 1;
	      log(WARN, "ttl of the destination is %d (%d)", ttl_dest, reply_ttl);
	      delete traceroute;
	      traceroute = new ConcurrentTracert(opts, ttl_dest);
	    } else {
	      // Execute hop-by-hop traceroute
	      log(INFO, "Concurrent algo is not usable => use hopbyhop algo");
	      delete traceroute;
	      traceroute = new HopByHopTracert(opts);
	    }
	
	    icmp_server->setClient(traceroute);
	    if (strncmp(opts->protocol, "tcp", 4) == 0)
	      tcp_server->setClient(traceroute);
	    traceroute->trace();
	  }
	
	  // Output
	  if (opts->raw_output)
	  	Output::raw(stdout, traceroute, opts);
	 	else
	  	Output::text(stdout, traceroute, opts);
	}
	
	//printf("deleting things..\n");
	delete currt;
	
  // Free ressources
  delete icmp_server;
  //printf("done\n");
  if (tcp_server != NULL) delete tcp_server;
  delete traceroute;
  delete opts;

  return 0;
}

