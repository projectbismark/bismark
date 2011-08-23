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

TracertImpl::TracertImpl () {
	
}

/**
 * Constructor - creation of the listening socket.
 *
 * @param opts List of options
 */
TracertImpl::TracertImpl (Options* opts) {
  //printf("tracert impl 1\n");	
  //if (opts->debug)
  //  log(WARN, "TracertImpl::TracertImpl(opts)");
  
  // Initialisation
  this->opts = opts;
  
  time = new Time();
  
  id_current = opts->id_initial;
  
  int res = pthread_mutex_init(&lock, NULL);
  if (res != 0)
    throw TrException(str_log(ERROR, "Create a mutex"));
    
  res = pthread_cond_init(&cond_wait, NULL);
  if (res != 0)
    throw TrException(str_log(ERROR, "Create a thread condition"));
  
  ttl_current = opts->ttl_initial;
  
  log(INFO, "HopByHop algo");
}

/**
 * Destructor
 */
TracertImpl::~TracertImpl () {
  //fprintf(stderr, "destruction destruction TracertImpl !\n");
  //return;
  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&cond_wait);
  
  delete time;
  
  for (int i = getMinTTL(); i <= getMaxTTL(); i++) {
    
    ListProbes* lprobes = probes_by_ttl[i];
    //printf("lprobes is %x\n", lprobes);	
    if (lprobes == NULL) {
    	//printf("lprobes is null\n");	
    	continue;
    }	
    for (int j = 0; j < opts->max_try; j++) {
    	deleteTimedProbe(lprobes->probes[j]);
//      TimedProbe* tprobe = lprobes->probes[j];
//      
//      if (tprobe->host_name != NULL)
//        delete tprobe->host_name;
//      
//      if (tprobe->host_address != NULL)
//        delete tprobe->host_address;
//      
//      delete tprobe->probe;
//      delete tprobe;
    }
    delete lprobes;
  }
  
  probes_by_id.clear();
  probes_by_ttl.clear();
}

long
TracertImpl::duration () {
	return time->getCurrentTime();
}

void
TracertImpl::deleteTimedProbe (TimedProbe *tprobe) {
	if (tprobe->host_name != NULL)
    delete tprobe->host_name;
  //fprintf(stderr, "de\n");
  if (tprobe->host_address != NULL)
    delete tprobe->host_address;
  if (tprobe->mpls_stack != NULL)
  	delete tprobe->mpls_stack;
  //fprintf(stderr, "tr\n");
  //tprobe->probe->free();
  delete tprobe->probe;
  //fprintf(stderr, "qu\n");
  delete tprobe;
}

void
TracertImpl::free () {
}

/**
 * Start traceroute
 */
bool
TracertImpl::trace (char* dst_addr, int id, int id_max) {
  // Indicates the success of the traceroute
  printf("TracertImpl::trace\n");
  return true;
}

bool
TracertImpl::trace () {
  // Indicates the success of the traceroute
  printf("TracertImpl::trace\n");
  return true;
}

TimedProbe*
TracertImpl::sendProbe (int id) {
  //printf("TracertImpl::sendProbe\n");
  return sendProbe2(id, opts->dst_port);
}

TimedProbe*
TracertImpl::sendProbe2 (int id, int xtuple) {
	return sendProbe3(id, xtuple, NULL, 0);
}

TimedProbe*
TracertImpl::sendProbe3 (int id, int xtuple, Interface* interf, uint32 addr) {
	
	if (bw)
		bw->wait();
	
  //printf("TracertImpl::sendProbe 2\n");
  // Init a TimedProbe...
  Probe* probe = Probe::probeFactory(opts->protocol,
                          opts->src_addr, opts->src_port/*id+1*/,
                          target, /*XXX*/xtuple,
                          ttl_current, opts->tos, opts->probe_length,
                          opts->proc_id, id, opts->return_flow_id, false);
  
  pthread_mutex_lock(&lock);
  
  TimedProbe* tprobe   = new TimedProbe();
  tprobe->probe        = probe;
  //tprobe->send_time    = time->getCurrentTime();
  tprobe->arrival_time = 0;
  //tprobe->timeout_time = tprobe->send_time + (opts->timeout * 1000);
  tprobe->host_address = 0;
  tprobe->host_name    = NULL;
  // Init the MPLS infos
  tprobe->nbrLabels    = 0;
  tprobe->mpls_stack   = NULL;
  tprobe->mpls_ttl     = 0;
  // IP identifier of the returned packet
  tprobe->ip_id        = 0;
  // XXX
  //inet_aton(target, (struct in_addr *)&tprobe->destination_address);
	tprobe->destination_address = target;

	tprobe->classif_interf = interf;
	//printf("expected addr = %x\n", addr);
	tprobe->classif_expected_addr = addr;

  probes_by_id[probe->getID()] = tprobe;

  // ... and send it
  log(INFO, "Send probe, ttl=%d, id=%x", ttl_current, probe->getID());
  tprobe->probe->dump();
  tprobe->send_time    = time->getCurrentTime();
  tprobe->timeout_time = tprobe->send_time + (opts->timeout * 1000);
  //if (xtuple != 0)
    tprobe->probe->send();
  //else
  //  printf("sendProbe2 WARNING !! remove this if !\n");
  nbr_probes_sent++;
  
  //fprintf(stderr, "[22]\n");	
  pthread_mutex_unlock(&lock);
  
  return tprobe;
}

void
TracertImpl::reSendProbe(TimedProbe * tprobe) {
  //pthread_mutex_lock(&lock);
  
  tprobe->send_time    = time->getCurrentTime();
  tprobe->timeout_time = tprobe->send_time + (opts->timeout * 1000);
  
  tprobe->probe->dump();
  tprobe->probe->send();
  
  //pthread_mutex_unlock(&lock);
}

void
TracertImpl::waitProbes () {
  //if (opts->debug)
  //log(WARN, "TracertImpl::waitProbes sent=%d recv=%d", nbr_probes_sent, nbr_replies_received);

  // Wait all replies for this TTL
  struct timeval  now;
  struct timespec timeout;
  
  gettimeofday(&now, NULL);
  timeout.tv_sec  = now.tv_sec + (opts->timeout / 1000);
  timeout.tv_nsec = (now.tv_usec + ((opts->timeout * 1000) % 1000000)) * 1000;
  
  if (nbr_probes_sent != nbr_replies_received) {
    int res = pthread_cond_timedwait(&cond_wait, &lock, &timeout);
    
    if (res == ETIMEDOUT) {
      // Timeout
      log(DUMP, "Timeout");
    }
  }
}

void
TracertImpl::setBandwidth(Bandwidth* bw) {
	this->bw = bw;
}

TimedProbe*
TracertImpl::validateReply(Reply *reply, struct timeval *tv) {

	long arrival_time = time->getCurrentTime();

#ifdef USEPCAP
	arrival_time = time->getNormalizedTime(tv);
#endif

  if (reply->IPOptions()) {
    struct in_addr host_addr;
    
    host_addr.s_addr         = reply->getSourceAddress();
    
    log(WARN, "IP Options in this reply, from %s !", inet_ntoa(host_addr));
    reply->dumpRaw();
  }

  if (reply->getOriginalProtocol() != opts->protocole) {
    log(DUMP, "Bad protocol %d %d", opts->protocole, reply->getOriginalProtocol());
    
    //reply->dumpRaw();
    
    return NULL;
  }

	if (reply->getProcId() != opts->proc_id) {
  //if (reply->getProcId() != opts->src_port) {
    log(DUMP, "Bad ProcId : %d %d", reply->getProcId(), opts->src_port);
    
    return NULL;
  }

  // Get the timed probe associated to this reply
  int id = reply->getID();
#ifdef DEVANOMALIES
	id = reply->getID3();
	  
  uint16 udpchk = (uint16)reply->getID2();
  uint16 ipid = (uint16)reply->getID();;
  uint16 dstport = (uint16)reply->getID3();
  
  if (ipid != dstport || udpchk != dstport) {
  	
  	TimedProbe* tprobe = probes_by_id[id];
		if (tprobe == NULL)
			printf("Wow. WOW. dstport 0x%x does't match any probe\n", dstport);
		else
			printf("traceroute to %s\n", Util::my_inet_ntoa(tprobe->destination_address));
  	
  	printf("Original Destination address: %s\n", Util::my_inet_ntoa(reply->getOriginalDestAddress()));
		
		if (reply->getType() == Reply::TIME_EXPIRED)
			printf("Time Exceeded"); 
		else
			printf("Response");
		
		printf(" from %s\n", Util::my_inet_ntoa(reply->getSourceAddress()));
			
		printf("ipid=0x%x udpchk=0x%x dstport=0x%x\n", ipid, udpchk, dstport);
  
	  if (ipid != dstport) {
	  	uint16 sw_ipid = (ipid << 8) | (ipid >> 8);
			if (sw_ipid == dstport)
	  		printf("Found a NAT swapper\n");
	  	else
	  		printf("Found a strange ipid\n");
	  }
	  
	  if (udpchk != dstport) {
	 		if (udpchk == 0) {
	  		printf("Found a lazy host ipid=0x%x udpchk=0x%x\n", ipid, udpchk);
	  	} else {
	  		printf("Found a leak NAT ipid=0x%x udpchk=0x%x\n", ipid, udpchk);
	  	}
	  }
	  
	  reply->dumpRaw();
	}
  
#endif  
  
  int ret_flow_id = reply->getReturnFlowId();
  
  //log(WARN, "Return Flow id : 0x%x", ret_flow_id);
  if (opts->return_flow_id != -1 && ret_flow_id != opts->return_flow_id) {
  	log(WARN, "Bad return flow id 0x%x from %s", ret_flow_id, Util::my_inet_ntoa(reply->getSourceAddress()));
  	
  	uint32 resw = reply->getReservedWords();
  	unsigned char *p = (unsigned char *)&resw;
  	
  	log(WARN, "ICMP reserved words %x %d %d %d %d", resw, p[3], p[2], p[1], p[0]);
  	
  	//reply->dumpRaw();
	}
	
  TimedProbe* tprobe = probes_by_id[id];

  // If this reply is not associated to a probe, don't handle it
  if (tprobe == NULL) {
    log(DUMP, "Can't find the probe associated to this reply to target %s", target);
    //printf("ID=0x%x, initial=0x%x\n", id, id_initial);
    //reply->dumpRaw();
    return NULL;
  }

  // If the reply is a duplicate, don't handle it
  if (tprobe->arrival_time != 0) {
    log(DUMP, "Duplicated reply received");
    
    return NULL;
  }

  // If the reply has timed out, don't handle it
  //long arrival_time = time->getCurrentTime();
  if (arrival_time > tprobe->timeout_time) {
    log(DUMP, "A reply received which has timed out %d", arrival_time - tprobe->timeout_time);
    return NULL;
  }

  // XXX If we didn't reach the destination, and the original 
  // destination address doesn't match, don't handle it

#ifndef DEVANOMALIES  
  if (reply->getType() == Reply::TIME_EXPIRED 
        && reply->getOriginalDestAddress() != tprobe->destination_address)
  {
  	char *dest = strdup(Util::my_inet_ntoa(tprobe->destination_address));
    log(WARN, "A reply received with bad original destination address %s, should be %s", Util::my_inet_ntoa(reply->getOriginalDestAddress()), dest);
    delete dest;
    
    //return NULL;
  }
#endif
  
  //printf("%d %d\n", reply->getProcId(), reply->getID());
  
    // XXX If we reached the destination, but the source address
  // doesn't match, don't handle it
  
  tprobe->arrival_time     = arrival_time;
  
  return tprobe;
}

void
TracertImpl::updateInfos(TimedProbe* tprobe, Reply *reply) {
  
  if (bw)
		bw->newResponse();
  
  tprobe->reply_type       = reply->getType();
  
  //if (tprobe->reply_type == 5) {
  //	reply->dumpRaw();
  //}
  
  tprobe->reply_ttl        = reply->getOriginalTTL();
  tprobe->fabien_ttl       = reply->getTTL();
  tprobe->host_address_raw = reply->getSourceAddress();
  // Update the MPLS infos
  tprobe->nbrLabels        = reply->getMPLSNbrLabels();
  tprobe->mpls_stack       = reply->getMPLSLabelStack();
  tprobe->mpls_ttl         = reply->getMPLSTTL();
  // Update the IP Identifier
  tprobe->ip_id            = reply->getIPId();
  
  struct in_addr host_addr;
  host_addr.s_addr         = tprobe->host_address_raw;
  tprobe->host_address     = strdup(inet_ntoa(host_addr));
  if (opts->resolve_hostname) {
    struct hostent* phost
	= gethostbyaddr((char *)&host_addr, sizeof(host_addr), PF_INET);
    if (phost != NULL && phost->h_name != NULL)
      tprobe->host_name = strdup(phost->h_name);
  }
}

void
TracertImpl::wakeup(Reply* reply) {

  // Check if a connection reset is required
  if (reply->resetRequired()) {
    log(INFO, "Reset, id=%x", reply->getID());
    Probe* probe = Probe::probeFactory(opts->protocol,
        opts->src_addr, opts->src_port,
        target, opts->dst_port,
        opts->ttl_max, opts->tos, 0, 0,
        reply->getResetID(), opts->return_flow_id, true);
    log(DUMP, "Send message :");
    probe->dump();
    probe->send();
  }

  // Check if we have reached the destination
  if (reply->getType() != Reply::TIME_EXPIRED) {
  	if (opts->debug) {
  		printf("stop algo %d\n", reply->getType());
  		reply->dumpRaw();
  	}
  	//stop_algo = true;
  	
  	// Indicate that the destination has been reached
  	// The exhaustive algorithm has to check 
  	// whether the destination is the single interface 
  	// that responded. otherwise it must go on probing 
  	// the next hops
  	dest_reached = true;
  }
  // Check if all replies for this ttl have been received
  nbr_replies_received++;
  if (all_probes_sent && nbr_probes_sent == nbr_replies_received) {
    log(INFO, "All probes have been acknowledged");
    pthread_cond_signal(&cond_wait);
  }
}

void
TracertImpl::notifyReply (Reply* reply, struct timeval *tv) {
  //printf("notif, lock\n");
  pthread_mutex_lock(&lock);
  //printf("notif, locked\n");
  TimedProbe* tprobe = validateReply(reply, tv);
  //printf("validated\n");
  if (tprobe == NULL) {
  	//fprintf(stderr, "[20]\n");	
    pthread_mutex_unlock(&lock);
    //fprintf(stderr, "[20] unlock\n");
    return;
  }

  // The reply is OK, update the timed probe associated to it
  log(DUMP, "Valid reply, id=%x", reply->getID());
	//printf(".\n");
	//printf("update\n");
  updateInfos(tprobe, reply);
  //printf("update done\n");
  if (reply->IPOptions())
    log(WARN, "IP Options in this reply, from %s !", tprobe->host_address);
  
  //printf("wakeup\n");
  wakeup(reply);
	//printf("wakeup done\n");

	//fprintf(stderr, "[21]\n");	
  pthread_mutex_unlock(&lock);
  
  //printf("notifyreply done\n");
}

uint8
TracertImpl::getMinTTL () {
  return opts->ttl_initial;
}

uint8
TracertImpl::getMaxTTL () {
  return ttl_current - 1;
}

uint8
TracertImpl::getNbrProbes(uint8 ttl) {
  return opts->max_try;
}

uint8
TracertImpl::getNbrReplies(uint8 ttl) {
  log(WARN, "TODO");
  return 0;
}

uint8
TracertImpl::getNbrInterfaces(uint8 ttl) {
  return 0;
}

uint8
TracertImpl::getLoadBalancingType(uint8 ttl, int nprobe) {
  return 0;
}

const TimedProbe*
TracertImpl::getHopInfo (uint8 ttl, int nprobe) {
  //printf("TracertImpl::getHopInfo\n");
  ListProbes* lprobes = probes_by_ttl[ttl];
  
  if (lprobes == NULL)
    return NULL;
    
  if (nprobe < 0 || nprobe >= opts->max_try)
    return NULL;

  return lprobes->probes[nprobe];
}

