#include <stdio.h>
#include <math.h>

#include "Output.h"
#include "MtTracert.h"

void
Output::text (FILE* out, Tracert *results, Options* opts) {
  fprintf(out, "traceroute [(%s:%d) -> (%s:%d)], protocol %s, algo %s, duration %d s\n",
      opts->src_addr, opts->src_port,
      opts->dst_addr, opts->dst_port,
      opts->protocol, opts->algo, results->duration()/1000000);
  
  //bool exh_output = (strncmp(opts->algo, "mt", strlen(opts->algo)) == 0);
	bool exh_output = false;
	bool exh_old = false;
	
	if (opts->algo_id == EXHAUSTIVE_TRACERT)
		exh_output = true;
		
	if (opts->algo_id == EXHAUSTIVE_OLD_TRACERT) {
		exh_output = true;
		exh_old = true;
	}

	
  for (int i = results->getMinTTL(); i <= results->getMaxTTL(); i++) {
    //if (i < 10) fprintf(out, " %d ", i);
    //else fprintf(out, "%d ", i);
    int char_count = 0;
    char_count += fprintf(out, "%2d ", i);
    
    //int index = -1;
    //for (int j = 0; j < opts->max_try; j++) {
    //  if (results->getHopInfo(i, j)->getHostAddress() != NULL) {
    //    index = j;
    //    break;
    //  }
    //}

    if (exh_output)
      char_count += fprintf(out, " P(%d, %d)", results->getNbrReplies(i), results->getNbrProbes(i));
    
    //if (results->getLoadBalancingType(i) == 1)
    //  fprintf(out, " PF");
    
    const TimedProbe* last_tprobe = NULL;
    bool first_interf = true;
    
    for (int j = 0; j < results->getNbrProbes(i); j++) {

      const TimedProbe* tprobe = results->getHopInfo(i, j);
      //bool different_address = false;
      //if (index == j) show_address = true;
      //if (index != j && tprobe != NULL && last_tprobe != NULL
      //  && tprobe->host_address_raw != last_tprobe->host_address_raw)
      //  show_address = true;

      if (tprobe->arrival_time == 0)
      {
        // No valid reply : just print a star
        if (! exh_output)
          fprintf(out, " *");

        continue;
      }
      
      bool show_interface;
      
      if (!exh_output) {
        //if (tprobe->arrival_time != 0) {
          // The current address is different : print it
          // Check if the current and previous addresses are the same
          if (last_tprobe == NULL 
            || (tprobe->host_address_raw != last_tprobe->host_address_raw)) {

            fprintf(out, " %s", tprobe->getHostName());

            if (opts->resolve_hostname)
              fprintf(out, " (%s)", tprobe->getHostAddress());
          }
          
          show_interface = true;
        //}
      } else {
        
        // XXX ignore probes sent to classify load balancers
        //if (last_tprobe != NULL && tprobe->xtuple < last_tprobe->xtuple)
        //  continue;

        show_interface = true;
				//printf("%d\n", results->getNbrInterfaces(i));
        if (results->getNbrInterfaces(i) > 1) {
          // For all probes already treated
          for (int k = 0; k < j; k++) {
            const TimedProbe *tprobe2 = results->getHopInfo(i, k);
            // Ignore the current probe if its interface has already been treated
            if (tprobe2->arrival_time != 0
              && tprobe2->host_address_raw == tprobe->host_address_raw)
              show_interface = false;
          }
          //if (show_interface && tprobe->flow_identifier == 1)
          //	fprintf(out, "\n %s j=%d\n", tprobe->getHostName(), j);
        } else {
          if (last_tprobe != NULL) show_interface = false;
        }

				//fprintf(out, "%d %d\n", j, show_interface);

        // A "new interface"
        if (show_interface) {
        	if (! first_interf && opts->mline_output)
        		// there's a better way to do that with printf, 
        		// but I don't remember how..
        		for (int i = 0; i < char_count; i++)
        			fprintf(out, " ");
        	first_interf = false;
          fprintf(out, " %s", tprobe->getHostName());

					//fprintf(out, " XXX %d XXX\n", opts->resolve_hostname);
          if (opts->resolve_hostname)
            fprintf(out, " (%s)", tprobe->getHostAddress());

          // For per-flow load balancing, print all the xtuple identifiers
          // that reach this interface
          if (/*results->getLoadBalancingType(i) == 1
            &&*/ results->getNbrInterfaces(i) > 1) {
            	
            // if new algo, or old algo and per-flow lb
            if (!exh_old || results->getLoadBalancingType(i, j) == 1) {
	            fprintf(out, ":%d", tprobe->flow_identifier);
	
	            // Find all the probes that returned the same interface
	            for (int k = j + 1; k < results->getNbrProbes(i); k++) {
	              const TimedProbe *tprobe2 = results->getHopInfo(i, k);
	              if (tprobe2->arrival_time != 0 
	                && tprobe2->host_address_raw == tprobe->host_address_raw
	                // XXX ignore probes sent to classify load balancers
	                && tprobe2->flow_identifier != tprobe->flow_identifier) {
	                fprintf(out, ",%d", tprobe2->flow_identifier);
	              }
	            }
            }
            //fprintf(out, " ");
          }
          if (! exh_old) {
	          uint8 type = results->getLoadBalancingType(i, j);
						switch (type) {
							case 1:
								fprintf(out, " =");
								break;
							case 2:
								fprintf(out, " <");
								break;	 
						}
          }
        }
      }
        
      if (show_interface) {
        // Print the arrival time
        // XXX exhaustive mode ?
        float rtt = ((float)tprobe->getRTT()) / 1000.0;
        float acc = rtt;
        float min = rtt, max = rtt;
        int count = 1;
        
        if (exh_output) {
	        for (int k = j + 1; k < results->getNbrProbes(i); k++) {
	        	const TimedProbe *tprobe2 = results->getHopInfo(i, k);
	            
	          if (tprobe2->arrival_time != 0 
	            && tprobe2->host_address_raw == tprobe->host_address_raw) {
	            	rtt = (float)tprobe2->getRTT() / 1000.0;
	            	acc += rtt;
	            	count++;
	            	
	            	//fprintf(out, "  \n[[%04.03f ms]]\n ", rtt);

	            	if (rtt < min)
	            		min = rtt;
	            	if (rtt > max)
	            		max = rtt;
	          } // if probe comes from the current interface
	        } // for the following probes
	        
	        float avg = acc / count;
	        
	        acc = 0.0;
	        count = 0;
	        for (int k = j; k < results->getNbrProbes(i); k++) {
	        	const TimedProbe *tprobe2 = results->getHopInfo(i, k);
	            
	          if (tprobe2->arrival_time != 0 
	            && tprobe2->host_address_raw == tprobe->host_address_raw) {
	            	rtt = (float)tprobe2->getRTT() / 1000.0;
	            	
	            	acc += pow(rtt - avg, 2);
	            	count++;
	          } // if probe comes from the current interface
	        } // for the following probes
	        
	        acc /= count;
	        float stdev = sqrt(acc);
	        
	        fprintf(out, "  %04.03f/%04.03f/%04.03f/%04.03f ms ", min, avg, max, stdev);
	        
        } else {
        	fprintf(out, "  %04.03f ms ", ((float)tprobe->getRTT()) / 1000.0);
        } // exh output
        
        switch (tprobe->reply_type)
        {
          case Reply::HOST_UNREACHABLE:
            fprintf(out, "!H ");
            break;
          case Reply::NETWORK_UNREACHABLE:
            fprintf(out, "!N ");
            break;
          case Reply::SOURCE_QUENCH:
            fprintf(out, "!Q ");
            break;
          case Reply::DESTINATION_REACHED:
          case Reply::TIME_EXPIRED:
            break;
          case Reply::COMM_PROHIBITED:
          	fprintf(out, "!A ");
          	break;
          default:
            //fprintf(out, "!%d ", tprobe->reply_type);
            // FIX
            fprintf(out, "!? ");
            break;
        }

        // Print the probe TTL if it has a strange value
        if (tprobe->reply_ttl != 1 && tprobe->reply_ttl != -1)
          fprintf(out, "!T%d ", tprobe->reply_ttl);

        // Print the IP ID of the packet returned by the router (or target)
        if (opts->display_ipid)
          fprintf(out, "{%d} ", tprobe->ip_id);

        // Print the original TTL
        if (opts->display_ttl) {
          
          fprintf(out, "[%d", tprobe->fabien_ttl);
          
          // Find all the probes that returned the same interface
          for (int k = j + 1; k < results->getNbrProbes(i); k++) {
            const TimedProbe *tprobe2 = results->getHopInfo(i, k);
            
            if (tprobe2->arrival_time != 0 
              && tprobe2->host_address_raw == tprobe->host_address_raw) {
              	bool new_ttl = true;
              	
              	for (int k2 = j; k2 < k; k2++) {
              		const TimedProbe *tprobe3 = results->getHopInfo(i, k2);
              		if (tprobe3->arrival_time != 0 
              && tprobe3->host_address_raw == tprobe->host_address_raw 
              && tprobe2->fabien_ttl == tprobe3->fabien_ttl)
              			new_ttl = false;
              	}
              	
              	if (new_ttl)
              		fprintf(out, ",%d", tprobe2->fabien_ttl);
            }
          }
          
          fprintf(out, "] ");
        }
          
        if (opts->mline_output)
        	fprintf(out, "\n");
      }
      
      // Update only if tprobe is valid
      last_tprobe = tprobe;
      
#ifdef BRICEBRICE
      // We received a valid reply
      if (tprobe->arrival_time != 0) {
        // The current address is different : print it
        // Check if the current and previous addresses are the same
        if (last_tprobe == NULL 
          || (tprobe->host_address_raw != last_tprobe->host_address_raw)) {

          fprintf(out, " %s", tprobe->getHostName());

          if (opts->resolve_hostname)
            fprintf(out, " (%s) ", tprobe->getHostAddress());
        } 

        // Print the arrival time
        fprintf(out, " %04.03f ms ", ((float)tprobe->getRTT()) / 1000.0);
        
        switch (tprobe->reply_type)
        {
          case Reply::HOST_UNREACHABLE:
            fprintf(out, "!H ");
            break;
          case Reply::NETWORK_UNREACHABLE:
            fprintf(out, "!N ");
            break;
          case Reply::SOURCE_QUENCH:
            fprintf(out, "!Q ");
            break;
          default:
            break;
        }
        
        // Print the probe TTL if it has a strange value
        if (tprobe->reply_ttl != 1 && tprobe->reply_ttl != -1)
          fprintf(out, "!T%d ", tprobe->reply_ttl);

        // Print the IP ID of the packet returned by the router (or target)
        if (opts->display_ipid)
          fprintf(out, "{%d} ", tprobe->ip_id);

        // Print the original TTL
        if (opts->display_ttl)
          fprintf(out, "[%d] ", tprobe->fabien_ttl);

        // Update only if tprobe is valid
        last_tprobe = tprobe;
      } else
        // No valid reply : just print a star
        fprintf(out, " *");
#endif    
      //if (show_address && opts->resolve_hostname) {
        // check if we have received a reply
        //if (tprobe->arrival_time != 0)
          //fprintf(out," %s (%s) ",tprobe->getHostName(),tprobe->getHostAddress());
      //}

      //if (show_address && !opts->resolve_hostname)
        //fprintf(out," %s (%s) ", tprobe->getHostName(), tprobe->getHostAddress());

      //if (tprobe == NULL || tprobe->arrival_time == 0) fprintf(out, " *");

      //if (tprobe != NULL && tprobe->arrival_time != 0)
        //fprintf(out, " %04.03f ", ((float)tprobe->getRTT()) / 1000.0);

//       if (tprobe->arrival_time != 0) {
//         switch (tprobe->reply_type)
//         {
//           case Reply::HOST_UNREACHABLE:
//             fprintf(out, "!H ");
//             break;
//           case Reply::NETWORK_UNREACHABLE:
//             fprintf(out, "!N ");
//             break;
//           case Reply::SOURCE_QUENCH:
//             fprintf(out, "!Q ");
//             break;
//           default:
//             break;
//         }
//       }

      // Print the returned TTL (sticky nodes/targets should return weird TTLs)
      // XXX show only if interesting  TTLs !!
//      if (tprobe->arrival_time != 0 
//        && tprobe->reply_ttl != 1 && tprobe->reply_ttl != -1)
//        fprintf(out, "!T%d ", tprobe->reply_ttl);

      // Print the IP ID of the packet returned by the router (or target)
      // XXX show only if user requested it !!!
//       if (&& tprobe->arrival_time != 0 && opts->display_ipid)
//         fprintf(out, "{%d} ", tprobe->ip_id);

//       if (tprobe != NULL && tprobe->arrival_time != 0 && opts->display_ttl)
//         fprintf(out, "[%d] ", tprobe->fabien_ttl);
        
      // Update only if tprobe is valid
//       if (tprobe->arrival_time !=0)
//         last_tprobe = tprobe;
    }
    
    if (! opts->mline_output)
    	fprintf(stdout, "\n");

    // Print a second line if there are MPLS informations
    //

    last_tprobe = NULL;
    bool new_line = false;

    for (int j = 0; j < opts->max_try; j++) {
      const TimedProbe* tprobe = results->getHopInfo(i, j);
      bool show_stack = false;

      if (tprobe != NULL && tprobe->mpls_stack != NULL
        && last_tprobe != NULL){
        if (MPLSHeader::compareStacks(tprobe->mpls_stack, tprobe->nbrLabels,
            last_tprobe->mpls_stack, last_tprobe->nbrLabels) != 0) {
            fprintf(stdout, ", ");
            show_stack = true;
        }
      }
      else if (tprobe != NULL && tprobe->mpls_stack != NULL) {
        fprintf(stdout, "   MPLS Label ");
        show_stack = true;
        last_tprobe = tprobe;
      }

      if (show_stack) {
        fprintf(stdout, "%d TTL=%d", tprobe->mpls_stack[0], tprobe->mpls_ttl);

        for (int j = 1; j < tprobe->nbrLabels; j++)
            fprintf(stdout, " | %d", tprobe->mpls_stack[j]);

        new_line = true;
      }
      last_tprobe = tprobe;
    }
    if (new_line) fprintf(stdout, "\n");
  }
}

void
Output::raw (FILE* out, Tracert *results, Options* opts) {
  fprintf(out, "traceroute [(%s:%d) -> (%s:%d)], protocol %s, algo %s\n",
      opts->src_addr, opts->src_port,
      opts->dst_addr, opts->dst_port,
      opts->protocol, opts->algo);
	
	for (int i = results->getMinTTL(); i <= results->getMaxTTL(); i++) {
    fprintf(out, "%2d\n", i);
        
    const TimedProbe* last_tprobe = NULL;
    
    for (int j = 0; j < results->getNbrProbes(i); j++) {

      const TimedProbe* tprobe = results->getHopInfo(i, j);
     
			fprintf(out, "%-18s", tprobe->getHostAddress());
			
			fprintf(out, " %04.03f ms ", ((float)tprobe->getRTT()) / 1000.0);
			
			// Print the probe TTL if it has a strange value
      if (tprobe->reply_ttl != 1 && tprobe->reply_ttl != -1)
        fprintf(out, "!T%d ", tprobe->reply_ttl);

      // Print the IP ID of the packet returned by the router (or target)
      if (opts->display_ipid)
        fprintf(out, "{%d} ", tprobe->ip_id);

      // Print the original TTL
      if (opts->display_ttl)
        fprintf(out, "[%d] ", tprobe->fabien_ttl);
        
      fprintf(out, "\n");
    }
	}
}
