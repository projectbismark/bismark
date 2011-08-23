#include "Tracert.h"

#include "TrException.h"
#include "Time.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * Constructor
 *
 * Create a new instance of a traceroute test algorithm.
 * It sends only one probe and wait a reply then stop.
 *
 * @param opts Options to create and send the probe.
 * @param ttl The ttl to use for the probe.
 */
ScoutTracert::ScoutTracert (Options* opts, uint8 ttl) : TracertImpl(opts) {
  printf("ScoutTracert\n");
}

/**
 * Free memory used by this algorithm.
 */
ScoutTracert::~ScoutTracert () {

}

bool
ScoutTracert::trace () {
	trace(opts->dst_addr, id_current, id_current+2000);
}

/**
 * Execute the algorithm.
 *
 * Send one probe then wait a timeout or a reply from a server.
 *
 * @see Server
 */
bool
ScoutTracert::trace (char* target, int id, int id_max) {

	id++;
	
  this->target = Util::my_inet_aton(target);
  this->id_current = id;
  this->id_initial = id;
  this->id_max 		= id_max;

  
  probes_by_ttl[ttl_current] = new ListProbes();
  ListProbes* lprobes        = probes_by_ttl[ttl_current];
  lprobes->probes            = new TimedProbe*[1];
  
  lprobes->probes[0] = sendProbe(opts->id_initial);

  // XXX NetBSD va peut etre gueuler parceque
  // waitProbes deverouille mutex alors qu'il est deja libre
  pthread_mutex_lock(&lock);
  waitProbes();
  pthread_mutex_unlock(&lock);
  
  return (lprobes->probes[0]->arrival_time != 0);
}

uint8
ScoutTracert::getNbrReplies(uint8 ttl) {
  log(WARN, "TODO");
  return 0;
}
