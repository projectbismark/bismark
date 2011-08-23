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
MihScannerTracert::MihScannerTracert (Options* opts) : TracertImpl(opts) {
  // Initialisation
  printf("MihScannerTracert\n");
  //Tracert::Tracert(opts);
  //init(opts);
}

/**
 * Destructor
 */
MihScannerTracert::~MihScannerTracert () {
}

/**
 * Start traceroute
 */
bool
MihScannerTracert::trace () {
  printf("MihScannerTracert::trace\n");
  
  // Number of sequential hops wich arn't replying
  int missing = 0;
  
  // Indicates if the destination has been reached
  stop_algo = false;
  printf("%d %d\n", ttl_current, opts->ttl_max);
  // Iterate on ttl from ttl_initial to ttl_max
  while (ttl_current <= opts->ttl_max) {
    
    pthread_mutex_lock(&lock);
    
    uint16 dst_port = opts->dst_port;
    
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
      lprobes->probes[i] = sendProbe2(id_current++, dst_port++);

      // Wait "delay_between_probes" before sending the next one
      usleep(opts->delay_between_probes * 1000);
    }

    pthread_mutex_lock(&lock);
    // All probes for this ttl have been sent
    all_probes_sent = true;

    waitProbes();

    missing = (nbr_replies_received == 0) ? (missing + 1) : 0;

    if (missing > opts->max_missing) {
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
  }

  int ttl = opts->ttl_initial;
  while (ttl <= opts->ttl_max) {
    ListProbes* lprobes = probes_by_ttl[ttl];
    TimedProbe *last_tprobe = NULL;
    int last_diff = 0;
    int prev_diff = 0;
    
    for (int i = 0; i < opts->max_try; i++) {
      TimedProbe *tprobe = lprobes->probes[i];

      if (tprobe->arrival_time == 0) {
        last_tprobe = NULL;
      
        printf("\n");
      } else {
        bool diff = false;
        
        if (last_tprobe != NULL
         && tprobe->host_address_raw != last_tprobe->host_address_raw)
        {
          diff = true;
        }
        
        printf("%-18s %d", tprobe->getHostAddress(), diff);
        
        if (diff != prev_diff) {
          int off = i - last_diff;
          
          printf(" %d", off);
          
          last_diff = i - 1;
        }
        
        printf("\n");
        
        last_tprobe = tprobe;
        prev_diff = diff;
      }
    }
    ttl++;
  }
  
  // Indicates the success of the traceroute
  return true;
}

uint8
MihScannerTracert::getNbrReplies(uint8 ttl) {
  log(WARN, "TODO");
  return 0;
}
