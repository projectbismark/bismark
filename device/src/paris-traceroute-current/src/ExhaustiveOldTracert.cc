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

/**
 * Constructor - creation of the listening socket.
 *
 * @param opts List of options
 */
ExhaustiveOldTracert::ExhaustiveOldTracert (Options* opts, bool per_dest) : TracertImpl(opts) {
  log(INFO, "Exhaustive algo");
  this->per_dest = per_dest;
}

/**
 * Destructor
 */
ExhaustiveOldTracert::~ExhaustiveOldTracert () {
	//fprintf(stderr, "destruction old tracert\n");
	
	for (int i = getMinTTL(); i <= getMaxTTL(); i++) {
    
    MapProbes* mprobes = probes_by_ttl2[i];
    for (int j = 0; j < mprobes->nbr_probes; j++) {
      deleteTimedProbe(mprobes->probes[j]);
    }
    
    mprobes->probes.clear();
    
    delete mprobes;
  }
  
  probes_by_ttl2.clear();
}

void
ExhaustiveOldTracert::free () {
	//fprintf(stderr, "destruction destruction old tracert\n");
}

/**
 * 
 */
bool
ExhaustiveOldTracert::NewInterface(MapProbes *mprobes, uint32 interf) {
  for (int i = 0; i < mprobes->nbr_probes; i++) {
    TimedProbe *tprobe = mprobes->probes[i];
    if (tprobe->arrival_time != 0 && tprobe->host_address_raw == interf)
      return false;
  }
  return true;
}

int n2m_old[] = {6, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90, 96};

// int ports_old[] = {
//   62866, 62026, 20542, 52582,
//   30466, 12152, 15848, 11826,
//   27344, 43020, 36013, 20125,
//   65187, 37065, 64393, 31741,
//   63056, 63470, 29414, 29933,
//   42338, 46887, 32851, 46412,
//   12036, 61489, 46276, 43968,
//   65290, 35050, 12263, 36979,
//   49885, 23138, 38677, 62892,
//   21748, 64498, 56151, 44414,
//   23715, 38381, 54906, 23896,
//   49808, 65355, 62938, 16249,
//   30634, 43816, 38410, 54699,
//   27795, 23268, 11575, 40810,
//   21554, 27363, 56286, 26106,
//   43287, 44283, 20960, 28037,
//   45726, 12330, 37821, 49067,
//   28222, 18089, 28822, 52275,
//   55573, 27264, 63302, 23653,
//   21770, 46217, 51914, 12989,
//   13663, 62488, 21375, 53334,
//   20181, 16438, 56252, 39616,
//   57901, 46359, 40804, 58447,
//   27725, 12127, 38173, 11315,
//   17378, 33075, 65388, 21643
// };

int ports_old[] = {
47485, 59641, 59636, 59814,
23611, 24011, 24763, 63590,
44783, 36350, 23048, 21862,
22390, 35853, 32285, 27013,
40630, 57726, 64680, 35276,
61823, 33612, 43377, 62109,
62647, 21362, 40351, 30905,
39930, 65105, 64025, 10451,
53500, 40931, 56155, 38023,
44366, 25553, 50878, 39562,
51740, 26910, 30285, 23196,
51888, 34531, 53831, 42176,
59203, 64103, 29638, 29803,
39094, 38088, 45801, 33501,
43723, 30103, 36960, 60135,
17854, 64411, 20306, 50570,
27569, 47643, 60544, 13979,
13830, 22346, 41505, 47566,
13688, 34730, 17193, 11123,
62243, 42876, 43048, 52564,
47583, 18453, 38243, 25176,
12635, 22307, 13967, 13919,
59912, 24539, 51469, 48554,
34217, 55905, 62396, 38044,
58741, 11926, 60163, 56968,
62866, 62026, 20542, 52582,
30466, 12152, 15848, 11826,
27344, 43020, 36013, 20125,
65187, 37065, 64393, 31741,
63056, 63470, 29414, 29933,
42338, 46887, 32851, 46412,
12036, 61489, 46276, 43968,
65290, 35050, 12263, 36979,
49885, 23138, 38677, 62892,
21748, 64498, 56151, 44414,
23715, 38381, 54906, 23896,
49808, 65355, 62938, 16249,
30634, 43816, 38410, 54699,
27795, 23268, 11575, 40810,
21554, 27363, 56286, 26106,
43287, 44283, 20960, 28037,
45726, 12330, 37821, 49067,
28222, 18089, 28822, 52275,
55573, 27264, 63302, 23653,
21770, 46217, 51914, 12989,
13663, 62488, 21375, 53334,
20181, 16438, 56252, 39616,
57901, 46359, 40804, 58447,
27725, 12127, 38173, 11315,
17378, 33075, 65388, 21643
};


/**
 * 
 */
int
ExhaustiveOldTracert::ProbesToSend(int nbr_interfaces) {
    
    if (nbr_interfaces >= sizeof(n2m_old) / sizeof(int))
      return -1;
      
    return n2m_old[nbr_interfaces] * opts->factor;
}

bool
ExhaustiveOldTracert::trace () {
	trace(opts->dst_addr, id_current, id_current + 2000);
}


/**
 * Start traceroute
 */
bool
ExhaustiveOldTracert::trace (char* target, int id, int id_max) {
	id++;
	
	this->target = Util::my_inet_aton(target);
	
	/* prefix, if detection of per-destination load balancing */
	this->target_prefix = this->target & (0xffffffff >> (32 - opts->prefix_len));
	//printf("Target prefix: %s/%d\n", Util::my_inet_ntoa(this->target_prefix), opts->prefix_len);
	
  this->id_current = id;
  this->id_initial = id;
  this->id_max 		= id_max;
  // Number of sequential hops wich arn't replying
  int missing = 0;

  int max_probes_to_send = 0;
  
  // Indicates if the destination has been reached
  stop_algo = false;

  // Iterate on ttl from ttl_initial to ttl_max
  while (ttl_current <= opts->ttl_max) {
    pthread_mutex_lock(&lock);
    
    dest_reached = false;
    
    // number of probes sent and received for a given ttl
    nbr_probes_sent      = 0;
    nbr_replies_received = 0;
    all_probes_sent      = false;
    //
    classify_balancer    = false;
    //
    first_interface      = 0;
    //
    first_xtuple         = 0;
    // The first port for the x-tuple
    uint16 dst_port      = opts->dst_port;
    uint16 flow_identifier = 0;
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
    mprobes->per_flow          = true;
    // In this list, create "max_try" timed probes and send them
    //lprobes->probes            = new TimedProbe*[opts->max_try];
    pthread_mutex_unlock(&lock);
    
    // The number of probes we have to send
    int probes_to_send         = 6;
    expected_interf_count      = 1;
    
    do {
    
      int probes_count = ProbesToSend(mprobes->nbr_interfaces);
      
      if (probes_count == -1) {
        expected_interf_count = 1000;
      } else {
        probes_to_send = probes_count;
        
        if (probes_to_send > max_probes_to_send)
          max_probes_to_send = probes_to_send;
        
        expected_interf_count = mprobes->nbr_interfaces + 1;
      }
      
      if (opts->debug)
        fprintf(stderr, "[%d] sending %d probes, %d already sent\n", 
            ttl_current, probes_to_send, mprobes->nbr_probes);
      
      int last_nbr_probes = mprobes->nbr_probes;

      for (int i = mprobes->nbr_probes; i < probes_to_send; i++) {
      	
      	uint16 port = ports_old[flow_identifier];
      	
      	if (this->per_dest) {
      		uint32 host = ((uint32)flow_identifier & (0xffffffff >> opts->prefix_len));
      		this->target = target_prefix | (host << opts->prefix_len);
      		
	  			//this->target = target_prefix | (((uint32)flow_identifier & 0xff) << 24);
	  			//printf("to %s\n", Util::my_inet_ntoa(this->target));
	  			port = opts->dst_port;
	  		}
	  			  		
        // Init a TimedProbe...
        mprobes->probes[i] = sendProbe2(id_current++, port);

        pthread_mutex_lock(&lock);

        mprobes->nbr_probes++;

        mprobes->probes[i]->flow_identifier = flow_identifier;
        // XXX can remove that
        mprobes->probes[i]->dest_port = port/*s_old[flow_identifier]*/;
        
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
      waitProbes();
//printf("done\n");

/******************************************
* Re send the lost probes
****/
      int last_nbr_replies_received = 0;
      
      // re-send probes, stop when all probes have been acked
      // or no new reply was caught in one round
      while (nbr_replies_received != nbr_probes_sent
              && nbr_replies_received > last_nbr_replies_received) {
        if (opts->debug)
          fprintf(stderr, "[%d] lost probes sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
            
        last_nbr_replies_received = nbr_replies_received;
        all_probes_sent = false;
        
        for (int i = last_nbr_probes; i < probes_to_send; i++) {
          if (mprobes->probes[i]->arrival_time == 0) {
            if (opts->debug)
              fprintf(stderr, "need to re-send %d\n", i);
            
            // reSendProbe assumes lock already done
            reSendProbe(mprobes->probes[i]);
            
            // XXX unlock, wait delay, lock
          }
        }
        
        all_probes_sent = true;
        waitProbes();
        
        if (opts->debug)
          fprintf(stderr, "[%d] sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
      }
/******************************************
*
****/
 
      pthread_mutex_unlock(&lock);
      
      if (opts->debug)
        fprintf(stderr, "[%d] %d expected, %d found\n", ttl_current,
          expected_interf_count, mprobes->nbr_interfaces);
      
      if (opts->debug)
      	printf("reached ? %d\n", dest_reached);
      if (dest_reached) {
      	// XXX dest_reached is true if we have 
      	// received a response with type != TIMEXCEED.
      	// we also check that there is a single responding interface 
      	// to go on probing if we have traversed an asymmetric diamond. 
      	// but the problem is that at the end of the path we 
      	// may receive !N or !H from multiple router, combined  
      	// with the real destination responses.
      	// in that case we continuously probe incrementing the TTL
      	// until we reach max_ttl...
      	// provisional solution: stop even if more than a single responding 
      	// interface
      	//if (mprobes->nbr_interfaces == 1)
      		stop_algo = true;
      	// stop if per-destination detection
      	// pb in case of asym diamonds.
      	// stop only if received responses from the 
      	// destination prefix.
      	if (this->per_dest)
      		stop_algo = true;
      }
          
      if (stop_algo)
        break;
      
    } while (expected_interf_count < mprobes->nbr_interfaces);
    
    // UNLOCKED
    
    // We found all the interfaces. Now classify the load balancer
    if (mprobes->nbr_interfaces > 1 /* && !this->per_dest*/) {
      if (opts->debug)
        fprintf(stderr, "[%d] classifying balancer\n", ttl_current);

      all_probes_sent = false;
      nbr_probes_sent      = 0;
      nbr_replies_received = 0;
      
      classify_balancer = true;
      if (this->per_dest) {
      	uint32 host = ((uint32)first_xtuple & (0xffffffff >> opts->prefix_len));
      	this->target = target_prefix | (host << opts->prefix_len);
      		
	  		//this->target = target_prefix | (((uint32)flow_identifier & 0xff) << 24);
	  		//printf("to %s\n", Util::my_inet_ntoa(this->target));
	  		dst_port = opts->dst_port;
      } else {
      	dst_port = ports_old[first_xtuple];
      }
      probes_to_send += 5;

      int last_nbr_probes = mprobes->nbr_probes;
      
      for (int i = mprobes->nbr_probes; i < probes_to_send; i++) {
        //if (i != probes_to_send - 1)
          //dst_port = first_xtuple;
        //else
        //  dst_port = 0;
        mprobes->probes[i] = sendProbe2(id_current++, dst_port);

        pthread_mutex_lock(&lock);

        mprobes->nbr_probes++;
        mprobes->probes[i]->flow_identifier = first_xtuple;
        mprobes->probes[i]->dest_port = dst_port;

        pthread_mutex_unlock(&lock);

        // Wait "delay_between_probes" before sending the next one
        usleep(opts->delay_between_probes * 1000);
      }
      
      pthread_mutex_lock(&lock);
    
      all_probes_sent = true;
      //printf("waitprobes\n");
      // Wait all replies
      waitProbes();
      //printf("done\n");
      
/******************************************
*
****/      
      int last_nbr_replies_received = 0;
      
      // re-send probes, stop when all probes have been acked
      // or no new reply was caught in one round
      while (nbr_replies_received != nbr_probes_sent
              && nbr_replies_received > last_nbr_replies_received) {
        if (opts->debug)
          fprintf(stderr, "[%d] classify, lost probes sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
            
        last_nbr_replies_received = nbr_replies_received;
        all_probes_sent = false;
        
        for (int i = last_nbr_probes; i < probes_to_send; i++) {
          if (mprobes->probes[i]->arrival_time == 0) {
            if (opts->debug)
              fprintf(stderr, "need to re-send %d\n", i);
            
            // reSendProbe assumes lock already done
            reSendProbe(mprobes->probes[i]);
            
            // XXX unlock, wait delay, lock
          }
        }
        
        all_probes_sent = true;
        waitProbes();
        
        if (opts->debug)
          fprintf(stderr, "[%d] classify, sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
      }
/******************************************
*
****/

      pthread_mutex_unlock(&lock);
    } // classify 
    
    pthread_mutex_lock(&lock);
    
    missing = (nbr_replies_received == 0) ? (missing + 1) : 0;

    if (missing >= opts->max_missing) {
      log(INFO, "Too many down hops -> stop algo");
      //pthread_mutex_unlock(&lock);
      stop_algo = true;
    }
    
    ttl_current++;

    pthread_mutex_unlock(&lock);
    
    // Stop if destination has been reached
    if (stop_algo)
    {
      break;
    }
  } // for each TTL

  classify_balancer = false;
  
  int ttl_current_save = ttl_current;
  
  for (ttl_current = opts->ttl_initial; ttl_current < ttl_current_save; ttl_current++) {
    MapProbes* mprobes = probes_by_ttl2[ttl_current];
    
    current_mprobes = mprobes;
    
    if (mprobes->nbr_probes > 6 * opts->factor
        && mprobes->nbr_probes < max_probes_to_send + 5) {
        
      int last_nbr_probes = mprobes->nbr_probes;
      
      int probes_to_send = max_probes_to_send + 5;
        
      all_probes_sent = false;
      nbr_probes_sent      = 0;
      nbr_replies_received = 0;
      
      if (opts->debug)
        fprintf(stderr, "[%d] need to resend %d probes\n",
          ttl_current, probes_to_send);
      
      uint16 flow_identifier = mprobes->nbr_probes - 5;
          
      for (int i = mprobes->nbr_probes; i < probes_to_send; i++) {
        
        uint16 port = ports_old[flow_identifier];
      	
      	if (this->per_dest) {
      		uint32 host = ((uint32)flow_identifier & (0xffffffff >> opts->prefix_len));
      		this->target = target_prefix | (host << opts->prefix_len);
      		
	  			//this->target = target_prefix | (((uint32)flow_identifier & 0xff) << 24);
	  			//printf("to %s\n", Util::my_inet_ntoa(this->target));
	  			port = opts->dst_port;
	  		}
        
        mprobes->probes[i] = sendProbe2(id_current++, port/*s_old[flow_identifier]*/);

        pthread_mutex_lock(&lock);

        mprobes->nbr_probes++;

        mprobes->probes[i]->flow_identifier = flow_identifier;
        mprobes->probes[i]->dest_port = port/*s_old[flow_identifier]*/;
        
        flow_identifier++;

        pthread_mutex_unlock(&lock);

        // Wait "delay_between_probes" before sending the next one
        usleep(opts->delay_between_probes * 1000);
      }
      
      pthread_mutex_lock(&lock);
    
      all_probes_sent = true;
      //printf("waitprobes\n");
      // Wait all replies
      waitProbes();
      //printf("done\n");
      
/******************************************
*
****/      
      int last_nbr_replies_received = 0;
      
      // re-send probes, stop when all probes have been acked
      // or no new reply was caught in one round
      while (nbr_replies_received != nbr_probes_sent
              && nbr_replies_received > last_nbr_replies_received) {
        if (opts->debug)
          fprintf(stderr, "[%d] classify, lost probes sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
            
        last_nbr_replies_received = nbr_replies_received;
        all_probes_sent = false;
        
        for (int i = last_nbr_probes; i < probes_to_send; i++) {
          if (mprobes->probes[i]->arrival_time == 0) {
            if (opts->debug)
              fprintf(stderr, "need to re-send %d\n", i);
            
            // reSendProbe assumes lock already done
            reSendProbe(mprobes->probes[i]);
            
            // XXX unlock, wait delay, lock
          }
        }
        
        all_probes_sent = true;
        waitProbes();
        
        if (opts->debug)
          fprintf(stderr, "[%d] sent=%d recv=%d\n", 
            ttl_current, nbr_probes_sent, nbr_replies_received);
      }
/******************************************
*
****/
      
      pthread_mutex_unlock(&lock);
    }
  }
  
  // Indicates the success of the traceroute
  return true;
}

void
ExhaustiveOldTracert::notifyReply (Reply* reply, struct timeval *tv) {
  pthread_mutex_lock(&lock);
  
  TimedProbe* tprobe = validateReply(reply, tv);
  
  if (tprobe == NULL) {
    pthread_mutex_unlock(&lock);
    return;
  }

  //printf("valide!\n");
  // The reply is OK, update the timed probe associated to it
  log(INFO, "Valid reply, id=%x", reply->getID());
  
  updateInfos(tprobe, reply);
  
  // XXX temp
  long arrival_time = tprobe->arrival_time;
  tprobe->arrival_time = 0;
  
  if (current_mprobes->nbr_interfaces == 0) {
    first_interface = tprobe->host_address_raw;
    first_xtuple = tprobe->flow_identifier;
    
    if (opts->debug)
      fprintf(stderr, "[%d] first interface %s, xtuple %d\n", ttl_current, 
        tprobe->host_address, tprobe->flow_identifier);
  }
  //printf("notifyreply\n");
  if (classify_balancer) {
    if (opts->debug)
      fprintf(stderr, "[%d] classify %s\n", ttl_current, tprobe->host_address);
    if (tprobe->host_address_raw != first_interface) {
      current_mprobes->per_flow = false;
      if (opts->debug)
        fprintf(stderr, "[%d] NOT per-flow\n", ttl_current);
    }
  } else {
    if (NewInterface(current_mprobes, tprobe->host_address_raw)) {
      if (opts->debug)
        fprintf(stderr, "[%d] new interface : %s\n", ttl_current, tprobe->host_address);
      current_mprobes->nbr_interfaces++;
    } /*else
      printf("not new %s\n", tprobe->host_address);*/
  }
  
  // Per-destination load balancing detection
  if (this->per_dest) {
  	// If we reached the target prefix
  	if (opts->debug)
  		printf("%x %x\n", tprobe->host_address_raw & 0xffffff, this->target_prefix);
  	if ((tprobe->host_address_raw & 0xffffff) == this->target_prefix)
  		dest_reached = true;
  }
  
  // XXX a la fin car arrival_time utilisé par NewInterface
  tprobe->arrival_time     = arrival_time;
  
  current_mprobes->nbr_replies++;
  
  wakeup(reply);

  pthread_mutex_unlock(&lock);
}

uint8
ExhaustiveOldTracert::getMinTTL () {
  return opts->ttl_initial;
}

uint8
ExhaustiveOldTracert::getMaxTTL () {
  return ttl_current - 1;
}

uint8
ExhaustiveOldTracert::getNbrProbes(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_probes;
}

uint8
ExhaustiveOldTracert::getNbrReplies(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_replies;
}

uint8
ExhaustiveOldTracert::getNbrInterfaces(uint8 ttl) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->nbr_interfaces;
}

uint8
ExhaustiveOldTracert::getLoadBalancingType(uint8 ttl, int useless) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return 0;
  return mprobes->per_flow?1:0;
}

const TimedProbe*
ExhaustiveOldTracert::getHopInfo (uint8 ttl, int nprobe) {
  MapProbes* mprobes = probes_by_ttl2[ttl];
  if (mprobes == NULL) return NULL;
  if (nprobe < 0 || nprobe >= mprobes->nbr_probes) return NULL;
  return mprobes->probes[nprobe];
}
