#include "Tracert.h"

#include "common.h"
#include "TrException.h"
#include "Reply.h"
#include "Time.h"
#include "RandomPort.h"
#include "Util.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>

/**
 * Constructor - creation of the listening socket.
 *
 * @param opts List of options
 */
ExhaustiveTracert::ExhaustiveTracert (Options* opts, bool	per_dest) : TracertImpl(opts) {
  log(INFO, "Exhaustive algo");
  this->per_dest = per_dest;
}

/**
 * Destructor
 */
ExhaustiveTracert::~ExhaustiveTracert () {
	//fprintf(stderr, "destruction destruction\n");
	free();
}

void
ExhaustiveTracert::free () {
	//fprintf(stderr, "destruction destruction\n");
  //pthread_mutex_destroy(&lock);
  //pthread_cond_destroy(&cond_wait);
  //fprintf(stderr, "Debut %x\n", time);
  //delete time;
  //fprintf(stderr, "un\n");
  for (int i = getMinTTL(); i <= getMaxTTL(); i++) {
    
    MapProbes* mprobes = probes_by_ttl2[i];
    //printf("%d\n", mprobes->nbr_probes);
    for (int j = 0; j < mprobes->nbr_probes; j++) {
      //TimedProbe* tprobe = mprobes->probes[j];
      //printf("delete timed probe\n");
      deleteTimedProbe(mprobes->probes[j]);
    }
    
    for (int j = 0; j < mprobes->nbr_interfaces; j++) {
    	Interface* interf = mprobes->interfaces[j];
    	//printf("delete [%d]\n",  j);
    	delete[] interf->next_hops;
    	//printf("apres next hops\n");
    	delete mprobes->interfaces[j];
    }
    
    //fprintf(stderr, "ci\n");
    //printf("%d %d\n", mprobes->probes.size(), mprobes->interfaces.size());
    mprobes->probes.clear();
    mprobes->interfaces.clear();
    delete mprobes;
  }
  
  probes_by_ttl2.clear();
}

int n2m[] = {6, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90, 96};

/**
 * 
 */
int
ExhaustiveTracert::ProbesToSend(int nbr_interfaces) {
    
    if (nbr_interfaces >= sizeof(n2m) / sizeof(int))
      return -1;
      
    return n2m[nbr_interfaces];
}

bool
ExhaustiveTracert::trace () {
	trace(opts->dst_addr, id_current, 0/*XXX*/);
}

void 
ExhaustiveTracert::send_probes_and_wait(MapProbes* mprobes, int count) {
	send_probes_and_wait(mprobes, count, 0, NULL, 0);
}

void 
ExhaustiveTracert::send_probes_and_wait(MapProbes* mprobes, int count, int constant, Interface* interf, uint32 addr) {
	current_mprobes = mprobes;
	//printf("spaw\n");
	int prev_nbr_probes = mprobes->nbr_probes;
	
	if (constant)
		count += mprobes->nbr_probes;
	
	if (opts->debug)
		fprintf(stderr, "%d.[%d] already sent %d, total %d\n", id_initial, ttl_current, mprobes->nbr_probes, count);
	
	for (int i = mprobes->nbr_probes; i < count; i++) {
	  // Init a TimedProbe...
	  if (! constant)	
	  	flow_identifier = i;
	  
	  // find a free id 
	  // XXX improvement : ssi deja fait le tour
	  pthread_mutex_lock(&lock);
	  
	  while (probes_by_id[id_current])
	  	id_current++;
	  	
	  pthread_mutex_unlock(&lock);
	  
	  uint16 port = ports[flow_identifier];
	  
	  if (this->per_dest) {
	  	target = target_prefix | (((uint32)flow_identifier & 0xff) << 24);
	  	printf("to %s\n", Util::my_inet_ntoa(target));
	  	port = opts->dst_port;
	  }
	  
	  mprobes->probes[i] = sendProbe3(id_current, port, interf, addr);
	  
	  id_current++;
	  if (id_current > id_max)
	  	id_current = id_initial; 
	  
		//TimedProbe* tp = mprobes->probes[i];
		
	  pthread_mutex_lock(&lock);
		
		// We don't know the interface associated to this probe yet
		mprobes->probes[i]->interf = NULL;
		//mprobes->probes[i]->classif_expected_addr = 0;
	
		if (! constant) {
			// assume we have already probed previous hop
			// classif_interf will be NULL if the prev probe timed out 
			// or if we did not send the probe (single interface, or stared hop)
			// in that case we won't be able to compute probestosend for each 
			// previous interface.
			// mprobes_prev->nbr_probes is 0 when we enumerate the first hop
			if (mprobes_prev->nbr_probes != 0) {
				if (ttl_current > opts->ttl_initial && i < mprobes_prev->nbr_probes)
					mprobes->probes[i]->classif_interf = mprobes_prev->probes[i]->interf;
				else
					mprobes->probes[i]->classif_interf = mprobes_prev->probes[0]->interf;
			}
		}

	  mprobes->nbr_probes++;
	
	  mprobes->probes[i]->flow_identifier = flow_identifier;
	  // XXX can remove that
	  mprobes->probes[i]->dest_port = ports[flow_identifier];
	  
	  
	  
	  if (!constant)
	  	flow_identifier++;

	  pthread_mutex_unlock(&lock);
	
	  // Wait "delay_between_probes" before sending the next one
	  usleep(opts->delay_between_probes * 1000);
	}
	
	pthread_mutex_lock(&lock);
	// All probes for this ttl have been sent
	all_probes_sent = true;
	//printf("waitprobes\n");
	// Wait all replies
	if (opts->debug)
		fprintf(stderr, "%d waiting for responses...\n", id_initial);
	waitProbes();

  int last_nbr_replies_received = 0;
  
  // re-send probes, stop when all probes have been acked
  // or no new reply was caught in one round
  while (nbr_replies_received != nbr_probes_sent
          && nbr_replies_received > last_nbr_replies_received) {
    if (opts->debug)
      fprintf(stderr, "%d.[%d] lost probes sent=%d recv=%d", id_initial,
        ttl_current, nbr_probes_sent, nbr_replies_received);
        
    last_nbr_replies_received = nbr_replies_received;
    all_probes_sent = false;
    
    for (int i = prev_nbr_probes; i < count; i++) {
      if (mprobes->probes[i]->arrival_time == 0) {
        if (opts->debug)
          fprintf(stderr, "%d.[%d] need to re-send probe #%d", id_initial, ttl_current, i);
        
        // reSendProbe assumes lock already done
        reSendProbe(mprobes->probes[i]);
        
        // XXX unlock, wait delay, lock
      }
    }
    
    all_probes_sent = true;
    
    waitProbes();
    
    if (opts->debug)
      fprintf(stderr, "%d.[%d] sent=%d recv=%d", id_initial,  
        ttl_current, nbr_probes_sent, nbr_replies_received);
  } // while
  
  // If we sent classif probes, delete them as they are now useless
  // and might interfere with consecutive hops probe matching
  if (constant) {
  	for (int i = prev_nbr_probes; i < count; i++) {
  		//TimedProbe* tp = mprobes->probes[i];
  		//delete tp;
  		deleteTimedProbe(mprobes->probes[i]);
  		//printf("delete tp for classify %d\n", i);
  	}
  	mprobes->nbr_probes = prev_nbr_probes;
  }
  
  pthread_mutex_unlock(&lock);
}

/**
 * Start traceroute
 */
bool
ExhaustiveTracert::trace (char* target, int id, int id_max) {

	// XXX avoid id=0 (IPID=0 means that kernel must fill this field
	// with its own value 
	id++;

	printf("starting algo with range %d - %d\n", id, id_max);
	
	this->target = Util::my_inet_aton(target);
	
	this->target_prefix = this->target & 0xffffff;
	printf("%s\n", Util::my_inet_ntoa(this->target_prefix));
	
  this->id_current = id;
  this->id_initial = id;
  this->id_max 		= id_max;
  // Number of sequential hops wich arn't replying
  int missing = 0;

  int max_probes_to_send = 0;
  
  int ttl_save;
  
  int probes_to_send_prev = 0;
  
  // Indicates if the destination has been reached
  stop_algo = false;
	dest_reached = false;
	
	// Add a fake first hop
	//printf("un\n");
	mprobes_prev = NULL;
	
	mprobes_prev = new MapProbes();
	mprobes_prev->nbr_probes        = 0;
  mprobes_prev->nbr_interfaces    = 0;
  mprobes_prev->nbr_replies				= 0;
	//Interface* interf = add_interface(mprobes_prev, 0);
	//interf->expected_interf_count = 0;
	//interf->next_hops_count = 0;
	//mprobes_prev->interfaces[0]->flow_fract = 1;
	//TimedProbe* t = new TimedProbe();
	//t->interf = interf;
	//mprobes_prev->probes[0] = t;
	//probes_by_ttl2[ttl_current] = mprobes_prev;

  // Iterate on ttl from ttl_initial to ttl_max
  while (ttl_current <= opts->ttl_max) {
    pthread_mutex_lock(&lock);
    if (opts->debug)
    	fprintf(stderr, "%d TTL %d\n", id_initial, ttl_current);
    // number of probes sent and received for a given ttl
    nbr_probes_sent      = 0;
    nbr_replies_received = 0;
    all_probes_sent      = false;
    //
    //classify_balancer    = false;
    //
    //first_interface      = 0;
    //
    //first_xtuple         = 0;
    // The first port for the x-tuple
    uint16 dst_port      = opts->dst_port;
    flow_identifier = 0;
    // 
    int expected_interf_count = 0;
    
    // Create a new list of probes with the same ttl
    probes_by_ttl2[ttl_current] = new MapProbes();
    current_mprobes            = probes_by_ttl2[ttl_current];
    MapProbes* mprobes         = probes_by_ttl2[ttl_current];
    mprobes->ttl               = ttl_current;
    // The number of probes sent for this hop
    mprobes->nbr_probes        = 0;
    //
    mprobes->nbr_replies       = 0;
    // The number of interfaces found for this hop
    mprobes->nbr_interfaces    = 0;
    //
    //mprobes->load_bal          = 0;
    // In this list, create "max_try" timed probes and send them
    //lprobes->probes            = new TimedProbe*[opts->max_try];
    pthread_mutex_unlock(&lock);
    
    // The number of probes we have to send
    int probes_to_send         = 6;
    expected_interf_count      = 1;
    
    int stop_probing;
    int iteration = 0;
    do {
	    stop_probing = 1;
	    
	    // first compute the number of probes to send according to 
	    // the number of interfaces already found at this hop
	    int probes_count = ProbesToSend(mprobes->nbr_interfaces);
      
      // stop_probing = 0 si 
      // mprobes->nbr_interfaces >= expected_interf_count 
      // ou si premiere iteration
      if ((iteration == 0) || 
      	 (mprobes->nbr_interfaces >= expected_interf_count))
      		stop_probing = 0;
      
      if (probes_count == -1) {
        expected_interf_count = 1000;
      } else {
        probes_to_send = probes_count;
        
        expected_interf_count = mprobes->nbr_interfaces + 1;
      }
      
	    // For each interface at hop h - 1
	    //printf("%d\n", mprobes_prev->nbr_interfaces);
	    for (int i = 0; i < mprobes_prev->nbr_interfaces; i++) {
	    	Interface* interf = mprobes_prev->interfaces[i];
	    	
	    	// Keep on enumerating while we find more (or the same number of) interfaces 
	    	// than expected. 
	    	//if (opts->debug)
	    	//	printf("[%d] enumerate loop, deg=%d, exp=%d\n", ttl_current, interf->next_hops_count, interf->expected_interf_count);
	    	
	    	if (interf->next_hops_count >= interf->expected_interf_count) {
		    	// Compute the number of probes that must traverse this 
		    	// interface for the next hop.
		    	int probes_count = ProbesToSend(interf->next_hops_count);
		    	//printf("hop\n");
		    	if (probes_count == -1) {
		        interf->expected_interf_count = 1000;
		     	} else {
		      	// Only interf->flow_fract of the probes will traverse i.
		        int count = probes_count / interf->flow_fract;
		        
		        // Keep the max number of probes that we compute
		        if (count > probes_to_send)
		        	probes_to_send = count;
		        
		        interf->expected_interf_count = interf->next_hops_count + 1;
		        if (interf->expected_interf_count == 1)
		        	interf->expected_interf_count = 2;
		        // keep on probing
		        stop_probing = 0;
		      }
	    	}
	    } // for each interface
	    
	    iteration++;
	    
	    //printf("hop %d\n", stop_probing);
	    if (stop_probing)
	    	break;
	    
	    if (probes_to_send > 100) {
	    	if (opts->debug)
	    		fprintf(stderr, "%d.[%d] MORE THAN 100\n", id_initial, ttl_current);
	    	//exit(0);
	    }
	    
	    if (probes_to_send_prev > probes_to_send)
	    	probes_to_send = probes_to_send_prev;
	    
	    // Here we have to send probes_to_send probes to hops h and h + 1
	    // TTL h - 1
	    // probe the previous hop only if it has more than 1 interface
	    // otherwise we already know which interface each probe traverse :)
	    if (mprobes_prev->nbr_interfaces > 1 /*&& ttl_current > opts->ttl_initial*/) {
	    	ttl_current--;
	    	if (opts->debug)
	    		fprintf(stderr, "%d.[%d] prev_ttl sending %d probes\n", id_initial, ttl_current+1, probes_to_send);
	    	mprobes_prev->backward_update = false;
	    	send_probes_and_wait(mprobes_prev, probes_to_send);
	    	// TTL h
	    	ttl_current++;
	    }
	    if (opts->debug)
	    	fprintf(stderr, "%d.[%d] current_ttl sending %d probes\n", id_initial, ttl_current, probes_to_send);
	    mprobes->backward_update = true;
	    send_probes_and_wait(mprobes, probes_to_send);
	    
    } while (! stop_probing);
    
    
    //printf("[%d] probes_to_send = %d\n", ttl_current, probes_to_send);
    
    probes_to_send_prev = probes_to_send;
    
    // prev hop did not respond. Fake an equal flow distrib.
    if (mprobes_prev->nbr_interfaces == 0) {
	    for (int j = 0; j < mprobes->nbr_interfaces; j++) {
	    		Interface* interf2 = mprobes->interfaces[j];
	    		
	    		// XXX init 0
	    		interf2->flow_fract = 1.0 / mprobes->nbr_interfaces;
	    }
    }
    // propagate the flow_fract to the next hop
    for (int i = 0; i < mprobes_prev->nbr_interfaces; i++) {
    	Interface* interf1 = mprobes_prev->interfaces[i];
    	
    	if (opts->debug)
    		fprintf(stderr, "%d.[%d] Next hops of %s:\n", id_initial, ttl_current, Util::my_inet_ntoa(interf1->address));
    	
    	for (int j = 0; j < interf1->next_hops_count; j++) {
    		Interface* interf2 = interf1->next_hops[j];
    		
    		// XXX init 0
    		interf2->flow_fract += interf1->flow_fract / interf1->next_hops_count;
    		if (opts->debug) {
    			//struct in_addr host_addr;
  				//host_addr.s_addr         = interf2->address;
  				//char* host_address     = strdup(inet_ntoa(host_addr));
    			fprintf(stderr, "  %s %f\n", Util::my_inet_ntoa(interf2->address), interf2->flow_fract);
    		}
    	}
    }
    
    // XXX debug: verif that sum(interf_current_hop.flow_fact) == 1
    // pas forcement en fait, si on a des etoiles
    
    if (ttl_current > opts->ttl_initial && !this->per_dest) {
	    // Classify each interface of previous hop
	    Interface* classif_interf;
	    // The expected address if per-flow load balancing
	    uint32 expected_addr = 0;
	    // for each interface at the previous hop
	    for (int i = 0; i < mprobes_prev->nbr_interfaces; i++) {
	    	// remember the interface address
	    	classif_interf = mprobes_prev->interfaces[i];
	    	
	    	// if the interface has an outdegree > 1, classify it
	    	if (classif_interf->next_hops_count > 1) {
	    		// suppose per-flow
	    		classif_interf->load_bal = 1;
	    		
	    		if (opts->debug)
	    			fprintf(stderr, "%d.[%d] classif %s\n", id_initial, ttl_current, Util::my_inet_ntoa(classif_interf->address));
	    		
	    		// find a probe that traverses this interface
	    		for (int j = 0; j < mprobes_prev->nbr_probes; j++) {
	    			if (mprobes_prev->probes[j]->host_address_raw == classif_interf->address) {
	    				flow_identifier = mprobes_prev->probes[j]->flow_identifier;
	    				expected_addr = mprobes->probes[j]->host_address_raw;
	    				break;
	    			}
	    		}
	    		if (opts->debug)
	    			fprintf(stderr, "expected addr: %s\n", Util::my_inet_ntoa(expected_addr));
	    		// send 5 probes using the same flow identifier
    			send_probes_and_wait(mprobes, 5, 1, classif_interf, expected_addr);
	    	}
    	}
    }
    
    pthread_mutex_lock(&lock);
    
    missing = (nbr_replies_received == 0) ? (missing + 1) : 0;

    if (missing >= opts->max_missing) {
      log(INFO, "Too many down hops -> stop algo");
      //pthread_mutex_unlock(&lock);
      stop_algo = true;
    }
    
    // delete the fake mapprobes created at the beginning
    if (ttl_current == opts->ttl_initial)
    	delete mprobes_prev;
    
    mprobes_prev = mprobes;
    
    ttl_current++;

    pthread_mutex_unlock(&lock);
    
    if (dest_reached && mprobes->nbr_interfaces == 1)
    	stop_algo = true;
    // Stop if destination has been reached
    if (stop_algo)
    {
      break;
    }
  } // for each TTL
  //printf("End of Algo, ttl %d\n", ttl_current);
  // Indicates the success of the traceroute
  return true;
}

/**
 * 
 */
Interface*
ExhaustiveTracert::findInterface(MapProbes *mprobes, uint32 interf) {
	//printf("findInterface among %d\n", mprobes->nbr_interfaces);
  for (int i = 0; i < mprobes->nbr_interfaces; i++)
  	if (mprobes->interfaces[i]->address == interf)
  		return mprobes->interfaces[i];
 	return NULL;
  
//  for (int i = 0; i < mprobes->nbr_probes; i++) {
//    TimedProbe *tprobe = mprobes->probes[i];
//    if (tprobe->arrival_time != 0 && tprobe->host_address_raw == interf)
//      return false;
//  }
//  return true;
}

Interface*
ExhaustiveTracert::add_interface(MapProbes* mp, uint32 addr) {
	//printf("debut\n");
	Interface* interf = findInterface(mp, addr);
	if (interf != NULL)
		return interf;
	//printf("alloc\n");
	interf = new Interface();
	
	interf->load_bal = 0;
	interf->flow_fract = 0;
	interf->next_hops_count = 0;
	interf->expected_interf_count = 0;
	interf->address = addr;
	interf->max_next_hops = 0;
	interf->next_hops = NULL;
	//printf("set\n");
	mp->interfaces[mp->nbr_interfaces] = interf;
	mp->nbr_interfaces++;
	if (opts->debug)
		fprintf(stderr, "%d.[%d] add_interface %d %s\n", id_initial, mp->ttl, mp->nbr_interfaces, Util::my_inet_ntoa(addr));
	
	return interf;
}

void
ExhaustiveTracert::addNextHopInterface(Interface* interf1, Interface*interf2) {
	if (opts->debug)
		fprintf(stderr, "searching interface among %d\n", interf1->next_hops_count);
	for (int i = 0; i < interf1->next_hops_count; i++)
		if (interf1->next_hops[i]->address == interf2->address)
			return;
	if (opts->debug)
		fprintf(stderr, "not found. add it %d %d\n", interf1->max_next_hops, interf1->next_hops_count);
	// need to resize
	if (interf1->max_next_hops <= interf1->next_hops_count) {
		
		int size = interf1->max_next_hops * 2;
		if (size == 0)
			size = 1;
		
		//printf("size = %d\n", size);
		
		Interface** list = new Interface*[size];
		
		//printf("list = %x\n", list);
		
		for (int i = 0; i < interf1->next_hops_count; i++)
			list[i] = interf1->next_hops[i];

		interf1->max_next_hops = size;
		if (interf1->next_hops != NULL)
			delete[] interf1->next_hops;
		interf1->next_hops = list;
	}
	
	interf1->next_hops[interf1->next_hops_count] = interf2;
	interf1->next_hops_count++;
	
	return;
}

void
ExhaustiveTracert::notifyReply (Reply* reply, struct timeval *tv) {
	//if (opts->debug)
	//	printf("notifyReply\n");
  pthread_mutex_lock(&lock);
  
  //if (reply->getProcId
  
  TimedProbe* tprobe = validateReply(reply, tv);
  
  if (tprobe == NULL) {
    pthread_mutex_unlock(&lock);
    return;
  }

	//printf("avant %x\n", probes_by_id[reply->getID()]);

	probes_by_id.erase(reply->getID());

	//printf("apres %x\n", probes_by_id[reply->getID()]);

  //printf("valide!\n");
  // The reply is OK, update the timed probe associated to it
  log(INFO, "Valid reply, id=%x", reply->getID());
  
  updateInfos(tprobe, reply);
  
  // XXX temp
  //long arrival_time = tprobe->arrival_time;
  //tprobe->arrival_time = 0;
  
  // An "enumerating" probe
  if (tprobe->classif_expected_addr == 0) {
  	Interface* interf = add_interface(current_mprobes, tprobe->host_address_raw);
    //if (opts->debug)
    //  log(WARN, "[%d] new interface : %s", ttl_current, tprobe->host_address);
  	
  	tprobe->interf = interf;
  	//printf("current_mprobes->backward_update %d\n", current_mprobes->backward_update);
  	// update the "next_hops" list of the interface at the previous hop
  	if (current_mprobes->backward_update) {
	  	//uint16 ident = tprobe->
	  	bool add = true;
	  	//printf("true\n");
	  	Interface* prev_interf = tprobe->classif_interf;
	  	//printf("%x %d %d\n", prev_interf, prev_interf->next_hops_count, prev_interf->expected_interf_count);
	  	//printf("before %x\n", prev_interf);
	  	// NULL if the probe at the previous hop timed out
	  	if (prev_interf != NULL)
	  		addNextHopInterface(prev_interf, interf);
	  	//printf("added\n");
	  }
  }
	// A "classifying" probe
	else {
		//printf("classif %s", my_inet_ntoa(tprobe->host_address_raw));
		//printf(" %s\n", my_inet_ntoa(tprobe->classif_expected_addr));
	 	if (tprobe->host_address_raw != tprobe->classif_expected_addr) {
			tprobe->classif_interf->load_bal = 2;
  		if (opts->debug) {
        //struct in_addr host_addr;
 				//host_addr.s_addr         = tprobe->classif_expected_addr;
 				//char* host_address     = inet_ntoa(host_addr);
        log(WARN, "[%d] %s NOT per-flow, expected %s", ttl_current, tprobe->host_address, Util::my_inet_ntoa(tprobe->classif_expected_addr));
  		}
  	}/* else {
  		log(WARN, "[%d] %s per-flow, expected %s", ttl_current, tprobe->host_address, my_inet_ntoa(tprobe->classif_expected_addr));
  	}*/
  }
  
  // XXX a la fin car arrival_time utilisé par NewInterface
  //tprobe->arrival_time     = arrival_time;
  
  current_mprobes->nbr_replies++;
  
  wakeup(reply);

  pthread_mutex_unlock(&lock);
}

uint8
ExhaustiveTracert::getMinTTL () {
  return opts->ttl_initial;
}

uint8
ExhaustiveTracert::getMaxTTL () {
  return ttl_current - 1;
}

uint8
ExhaustiveTracert::getNbrProbes(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_probes;
}

uint8
ExhaustiveTracert::getNbrReplies(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_replies;
}

uint8
ExhaustiveTracert::getNbrInterfaces(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_interfaces;
}

uint8
ExhaustiveTracert::getLoadBalancingType(uint8 ttl, int nprobe) {
	MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  if (nprobe < 0 || nprobe >= mprobes->nbr_probes) return 0;
  
  Interface* interf = mprobes->probes[nprobe]->interf;
  if (interf == NULL) return 0;
  
  return interf->load_bal;
}

const TimedProbe*
ExhaustiveTracert::getHopInfo (uint8 ttl, int nprobe) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return NULL;
  if (nprobe < 0 || nprobe >= mprobes->nbr_probes) return NULL;
  return mprobes->probes[nprobe];
}
