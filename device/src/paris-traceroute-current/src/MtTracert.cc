#include "Tracert.h"
#include "Bandwidth.h"
#include "MtTracert.h"

#include "common.h"
#include "TrException.h"
#include "Reply.h"
#include "Time.h"
#include "Output.h"
#include "Server.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

MtTracert::MtTracert (Options* opts, int id, Server* icmp_server, FILE* targets, pthread_mutex_t* targets_lock, pthread_mutex_t* output_lock, Bandwidth* bw) {
  // Initialisation
  //printf("Mt algo %d\n", id);
  
  this->opts = opts;
  this->server = icmp_server;
  this->id = id;
  this->targets = targets;
  this->targets_lock = targets_lock;
  this->output_lock = output_lock;
  this->bw = bw;
}

MtTracert::~MtTracert () {
	
}

/**
 * C callback function used to start the Server thread
 */
void*
run_thread (void* arg) {
  MtTracert* mt = (MtTracert*)arg;
  mt->runThread();
  return NULL;
}

void
MtTracert::startThread () {
  // Create and execute the listening thread
  //stop_thread = false;
  if (pthread_create(&thread, NULL, run_thread, this) != 0)
  	throw TrException(str_log(ERROR, "Create a thread"));
}

bool
MtTracert::wait(bool block) {
	if (block) {
		pthread_join(thread, NULL);
		return true;
	}
	pthread_mutex_lock(output_lock);
	if (terminated) {
		//fprintf(stderr, "[6]\n");
		pthread_mutex_unlock(output_lock);
		pthread_join(thread, NULL);
		return terminated;
	}
	//fprintf(stderr, "[7]\n");
	pthread_mutex_unlock(output_lock);
	
	return terminated;
}

int
MtTracert::stats() {
	//fprintf(stderr, " stats %d addresses treated\n", addr_count);
	return addr_count;
}

void
MtTracert::trace(char *dest_addr, int id_initial, int id_max, bool per_dest) {
	Tracert *t;
	
	// Create algo structures
  switch (opts->algo_id) {
    case HOPBYHOP_TRACERT:
      t = new HopByHopTracert(opts);
      break;
    case PACKBYPACK_TRACERT:
      t = new PackByPackTracert(opts);
      break;
    case CONCURRENT_TRACERT:
      t = new ConcurrentTracert(opts, opts->ttl_max);
      break;
    case SCOUT_TRACERT:
      t = new ScoutTracert(opts, opts->ttl_max);
      break;
    case EXHAUSTIVE_TRACERT:
    	t = new ExhaustiveTracert(opts, per_dest);
    	break;
    case EXHAUSTIVE_OLD_TRACERT:
    	t = new ExhaustiveOldTracert(opts, per_dest);
			break;
    default:
    	// Bus error on Mac OS X
      //traceroute = new NULLTracert();
      printf("no algo\n");
      return;
      break;
  }
	//printf("neww\n");
	//t = new HopByHopTracert(opts);
	
	t->setBandwidth(bw);
	//printf("set bw\n");
	server->addClient(t, id);
	
	t->trace(dest_addr, id_initial, id_max);
	
	server->addClient(NULL, id);
	// XXX server->removeClient();

	pthread_mutex_lock(output_lock);
#ifndef DEVANOMALIES
	opts->dst_addr = dest_addr;
	//printf("%d output\n", id);
	if (opts->raw_output)
  	Output::raw(stdout, t, opts);
 	else
  	Output::text(stdout, t, opts);
	if (fprintf(stdout, "\n") <= 0)
	{
		fprintf(stderr, "fprintf failed %d", errno);
		perror("fprintf");
	}
	opts->dst_addr = NULL;
#endif

	int fd;
	if ((fd = open("stop", O_RDONLY)) >= 0) {
		printf("Exit before end..\n");
		close(fd);
		unlink("stop");
		exit(0);
	}

	//fprintf(stderr, "[8]\n");
	pthread_mutex_unlock(output_lock);
	
	switch (opts->algo_id) {
    case HOPBYHOP_TRACERT:
      delete ((HopByHopTracert*)t);
      break;
    case PACKBYPACK_TRACERT:
      t = new PackByPackTracert(opts);
      break;
    case CONCURRENT_TRACERT:
      t = new ConcurrentTracert(opts, opts->ttl_max);
      break;
    case SCOUT_TRACERT:
      t = new ScoutTracert(opts, opts->ttl_max);
      break;
    case EXHAUSTIVE_TRACERT:
    	delete ((ExhaustiveTracert*)t);
    	break;
    case EXHAUSTIVE_OLD_TRACERT:
    	delete ((ExhaustiveOldTracert*)t);
			break;
    default:
    	// Bus error on Mac OS X
      //traceroute = new NULLTracert();
      printf("no algo\n");
      return;
      break;
  }
}

void
MtTracert::runThread () {
  char target_host[128];
  char* dest_addr;
  addr_count = 0;
  
  terminated = 0;
  
#ifdef DEVANOMALIES
	int id_initial = 32000 / opts->threads_count * id + 32000; 
	//int id_max = ((id + 1) << (16 - 5)) - 1;
	int id_max = id_initial + 32000 / opts->threads_count - 1;
#else  
  int id_initial = 65536 / opts->threads_count * id; 
	//int id_max = ((id + 1) << (16 - 5)) - 1;
	int id_max = id_initial + 65536 / opts->threads_count - 1;
#endif 
  
	//fprintf(stderr, "thread %d debute, %d - %d\n", id, id_initial, id_max);
	
	//return;
	if (targets == NULL)
		dest_addr = opts->dst_addr;
	
	pthread_mutex_lock(targets_lock);
	// targets NULL means we trace a single address (opts->dest)
	while (targets == NULL || fgets(target_host, 128, targets) != NULL) {
		//fprintf(stderr, "[9]\n");
		pthread_mutex_unlock(targets_lock);
	
		//remove the \n !
		char *p;
		if ((p = strchr(target_host, '\n')) != NULL) {
			*p = 0x00;
			p--;
			if (*p == '\r')
				*p = 0x00;
		}
		
		/*pthread_mutex_lock(output_lock);
		if (targets != NULL) {
			dest_addr = Util::my_gethostbyname(target_host);
			if (targets != NULL && dest_addr == NULL)
				continue;
		}
		pthread_mutex_unlock(output_lock);*/
		if (targets != NULL)
			dest_addr = target_host;
		
#ifndef DEVANOMALIES		
		pthread_mutex_lock(output_lock);
		//fprintf(stderr, "# thread %d, addr %s\n", id, dest_addr);
		pthread_mutex_unlock(output_lock);
#endif
	
		switch (opts->detection_type) {
			case ALL:
				trace(dest_addr, id_initial, id_max, true);
			case FLOW:
				trace(dest_addr, id_initial, id_max, false);
				break;
			case DEST:
				trace(dest_addr, id_initial, id_max, true);
		}
				
		addr_count++;
		//fprintf(stderr, " incr %d addresses treated\n", addr_count);
		
		pthread_mutex_lock(targets_lock);
		
		if (targets == NULL)
			break;			
	} // for each target
	
	//fprintf(stderr, "[4]\n");
	pthread_mutex_unlock(targets_lock);
	
	pthread_mutex_lock(output_lock);
	terminated = 1;
	//fprintf(stderr, "[5]\n");
	pthread_mutex_unlock(output_lock);
	//printf("# thread %d fini\n", id);
}
