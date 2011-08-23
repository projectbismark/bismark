#include "Tracert.h"

#include "common.h"
#include "TrException.h"
#include "Reply.h"
#include "Time.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>

ConcurrentTracert::ConcurrentTracert (Options* opts, int ttl) : TracertImpl(opts) {
  // Initialisation

  ttl_max = ttl;
  
  log(INFO, "Concurrent algo");
}

ConcurrentTracert::~ConcurrentTracert () {
}

bool
ConcurrentTracert::trace () {
	trace(opts->dst_addr, id_current, id_current+2000);
}

bool
ConcurrentTracert::trace (char* target, int id, int id_max) {
	
	id++;
	
	this->target = Util::my_inet_aton(target);
  this->id_current = id;
  this->id_initial = id;
  this->id_max 		= id_max;
	
	// number of probes sent and received for a given ttl
  nbr_probes_sent      = 0;
  nbr_replies_received = 0;
  all_probes_sent      = false;

  // Iterate on ttl from ttl_initial to ttl_max
  for (int i = opts->ttl_initial; i <= ttl_max; i++) {
    pthread_mutex_lock(&lock);
    
    // Create a new list of probes with the same ttl
    probes_by_ttl[i]           = new ListProbes();
    ListProbes* lprobes        = probes_by_ttl[i];
    lprobes->ttl               = i;
    
    // In this list, create "max_try" timed probes and send them
    lprobes->probes            = new TimedProbe*[opts->max_try];
    
    pthread_mutex_unlock(&lock);
    
    for (int j = 0; j < opts->max_try; j++) {
      
      lprobes->probes[j] = sendProbe(id_current++);

      // Wait "delay_between_probes" before sending the next one
      usleep(opts->delay_between_probes * 1000);
    }
    
    ttl_current++;
  }

  pthread_mutex_lock(&lock);
  // All probes for this ttl have been sent
  all_probes_sent = true;

  waitProbes();
  
  pthread_mutex_unlock(&lock);

	last_resp_ttl = 0;
	for (int i = opts->ttl_initial; i < ttl_max; i++) {
		ListProbes* lprobes = probes_by_ttl[i];
	  
	  if (lprobes == NULL)
	    continue;
	  	
		int nb_replies = 0;
		int dest_reached = 0;
		for (int j = 0; j < opts->max_try; j++) {
	  	TimedProbe *t = lprobes->probes[j];
			if (t->arrival_time != 0) {
				nb_replies++;
				
				if (t->reply_type != Reply::TIME_EXPIRED && t->reply_type != Reply::SOURCE_QUENCH)
					dest_reached++;
			}
		}
		//printf("conc %d %d\n", i, nb_replies);
		if (nb_replies > 0)
			last_resp_ttl = i;
			
		if (dest_reached > 0) {
			last_resp_ttl = i;
			break;
		}
	}
	
  // Indicates the success of the traceroute
  return true;
}

uint8
ConcurrentTracert::getMaxTTL () {
  return last_resp_ttl;
}

uint8
ConcurrentTracert::getNbrReplies(uint8 ttl) {
  log(WARN, "TODO");
  return 0;
}
