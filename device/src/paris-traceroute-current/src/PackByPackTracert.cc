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

PackByPackTracert::PackByPackTracert (Options* opts) : TracertImpl(opts){
  // Initialisation
  log(INFO, "PackByPack algo");
}

PackByPackTracert::~PackByPackTracert () {
}

bool
PackByPackTracert::trace () {
	trace(opts->dst_addr, id_current, id_current+2000);
}

bool
PackByPackTracert::trace (char* target, int id, int id_max) {
  
  id++;
  
  this->target = Util::my_inet_aton(target);
  this->id_current = id;
  this->id_initial = id;
  this->id_max 		= id_max;
  
  // Number of sequential hops wich arn't replying
  int missing = 0;

  // Indicates if the destination has been reached
  stop_algo = false;
  dest_reached = false;
  
  // Iterate on ttl from ttl_initial to ttl_max
  while (ttl_current <= opts->ttl_max) {
    
    pthread_mutex_lock(&lock);
    
    // number of probes sent and received for a given ttl
    nbr_probes_sent      = 0;
    nbr_replies_received = 0;
    all_probes_sent      = false;

    // Create a new list of probes with the same ttl
    probes_by_ttl[ttl_current] = new ListProbes();
    ListProbes* lprobes        = probes_by_ttl[ttl_current];
    lprobes->ttl               = ttl_current;
    
    // In this list, create "max_try" timed probes and send them
    lprobes->probes            = new TimedProbe*[opts->max_try];
    
    pthread_mutex_unlock(&lock);
    
    for (int i = 0; i < opts->max_try; i++) {
      lprobes->probes[i] = sendProbe(id_current++);
      
      // notifyReply will wakeup us
      all_probes_sent = true;
      
      // XXX NetBSD va peut etre gueuler parceque
      // waitProbes deverouille mutex alors qu'il est deja libre
      
      pthread_mutex_lock(&lock);
      
      waitProbes();
      
      pthread_mutex_unlock(&lock);
    }

    pthread_mutex_lock(&lock);
    
    // Check if the hops was missing
    bool hop_reached = false;
    for (int i = 0; i < opts->max_try; i++) {
      if (lprobes->probes[i]->arrival_time != 0)
        hop_reached = true;
    }
    if (! hop_reached)
      missing++;
    else
      missing = 0;
    
    if (missing > opts->max_missing) {
      log(INFO, "Too many down hops -> stop algo");
      //pthread_mutex_unlock(&lock);
      stop_algo = true;
    }
      
    ttl_current++;

    pthread_mutex_unlock(&lock);
    
    // Stop if destination has been reached
    if (dest_reached || stop_algo)
    {
      break;
    }
  }

  // Indicates the success of the traceroute
  return true;
}

uint8
PackByPackTracert::getNbrReplies(uint8 ttl) {
  log(WARN, "TODO");
  return 0;
}
