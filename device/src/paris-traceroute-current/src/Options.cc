#include "Options.h"

#include "Util.h"
#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef __FreeBSD__
#include <getopt.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


/**
 * Constructor
 *
 * Parse the command line and initialise all options.
 *
 * @param argc Command line arg
 * @param argv Command line arg
 */
Options::Options (int argc, char** argv) {
  // Initialise all params to default values
  strcpy(protocol, "udp");
  strcpy(targets, "");
  protocole            = 0x11;
  strcpy(algo, "hopbyhop");
  dst_addr 						 = NULL;
  src_port             = 33456;
  dst_port             = 33457;
  ttl_initial          = 1;
  ttl_max              = 30;
  tos                  = 0;
  timeout              = 5000;
  delay_between_probes = 50;
  max_try              = 3;
  max_missing          = 3;
  id_initial           = 1;
  resolve_hostname     = true;
  probe_length         = 0;
  display_ipid         = false;
  display_ttl          = false;
  proc_id              = src_port;
  debug                = false;
  bandwidth = 0;
  threads_count				= 1;
  raw_output					= false;
  mline_output				= false;
  prefix_len 					= 32;
  detection_type			= FLOW;
  factor 							= 1;
  return_flow_id 			= -1;
#ifndef __FreeBSD__
  struct option long_opts[] = {
    {"help",        0, NULL, 'h'},
    {"version",     0, NULL, 'V'},
    {"verbose",     0, NULL, 'v'},
    {"quiet",       0, NULL, 'Q'},
    {"ipid",        0, NULL, 'i'},
    {"print_ttl",   0, NULL, 'l'},
    {"first_ttl",   1, NULL, 'f'},
    {"max_ttl",     1, NULL, 'm'},
    {"protocol",    1, NULL, 'p'},
    {"source_port", 1, NULL, 's'},
    {"dest_port",   1, NULL, 'd'},
    {"tos",         1, NULL, 't'},
    {"timeout",     1, NULL, 'T'},
    {"wait",        1, NULL, 'w'},
    {"query",       1, NULL, 'q'},
    {"missing_hop", 1, NULL, 'M'},
    {"algo",        1, NULL, 'a'},
    {"length",      1, NULL, 'L'},
    {NULL,          0, NULL,  0 }
  };
#endif

  char* short_opts = "AZhVvQniDf:F:m:p:o:s:d:t:w:T:q:M:a:lb:L:B:c:E:r:";

  int opt = 1;
#ifndef __FreeBSD__  
  while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
#else
	while ((opt = getopt(argc, argv, short_opts/*, long_opts, NULL*/)) != -1) {
#endif
    switch (opt) {
      case 'v':   // verbose
        set_log_level(DUMP);
	break;
      case 'Q':   // quiet
				set_log_level(ERROR);
        break;
      case 'h':   // help
        log(DUMP, "Option : help");
        help();
        break;
      case 'V':   // version
        log(DUMP, "Option : version");
        version();
        break;
      case 'f':   // first ttl
        log(DUMP, "Option : first ttl, param = %s", optarg);
        ttl_initial = atoi(optarg);
        break;
      case 'F':
      	strncpy(targets, optarg, 32);
      	break;
      case 'm':   // max ttl
        log(DUMP, "Option : max ttl, param = %s", optarg);
        ttl_max = atoi(optarg);
        break;
      case 'p':   // protocol
        log(DUMP, "Option : protocol, param = %s", optarg);
        strncpy(protocol, optarg, 5);
        
        if (strncmp(optarg, "icmp", 4) == 0) {
          protocole = 0x01;
        	proc_id = getpid() + 32768;
        }
        else if (strncmp(optarg, "tcp", 3) == 0) {
          protocole = 0x06;
        	proc_id = getpid() + 32768;
        }
        break;
      case 'B':
      	bandwidth = atoi(optarg);
      	break;
      case 's':   // source port
        log(DUMP, "Option : source_port, param = %s", optarg);
        if (strncmp(optarg, "pid", 3) == 0) {
        	// XXX at least we don't want to interfer with classic traceroute
  				proc_id = getpid() + 32768;
  				src_port = proc_id;
        } else {
        	src_port = atoi(optarg);
					proc_id = src_port;
				}
        break;
      case 'd':   // destination port
        log(DUMP, "Option : dest_port, param = %s", optarg);
        dst_port = atoi(optarg);
        break;
      case 't':   // tos
        log(DUMP, "Option : tos, param = %s", optarg);
        tos = atoi(optarg);
        break;
      case 'w':   // wait between probes
        log(DUMP, "Option : w, param = %s", optarg);
        delay_between_probes = atoi(optarg);
        break;
      case 'T':   // timeout for each probe
        log(DUMP, "Option : timeout, param = %s", optarg);
        timeout = atoi(optarg);
        break;
      case 'q':   // Number of tests before we consider a router down
        log(DUMP, "Option : retry, param = %s", optarg);
        max_try = atoi(optarg);
        break;
      case 'r':
      	return_flow_id = atoi(optarg);
      	break;
      case 'M':   // Number of missing hop before stopping the traceroute
        log(DUMP, "Option : missing_hop, param = %s", optarg);
        max_missing = atoi(optarg);
        break;
      case 'a':
        log(DUMP, "Option : algorithm, param = %s", optarg);
        strncpy(algo, optarg, 20);
        if (strncmp(algo, "help", 20) == 0) helpAlgo();
        break;
      case 'L':
        log(DUMP, "Options : probe length, param = %s", optarg);
        probe_length = atoi(optarg);
        break;
      case 'n':   // Print hop addresses numerically
        log(DUMP, "Option : numeric = true");
        resolve_hostname = false;
        break;
      case 'i':   // Print the IP Id of the returned packet
        log(DUMP, "Option : ipid = true");
        display_ipid = true;
        break;
      case 'l':   // Print the TTL of the returned packet
        log(DUMP, "Option : print_ttl = true");
        display_ttl = true;
        break;
      case 'b':
        log(DUMP, "Option : id_initial, param = %s", optarg);
        id_initial = atoi(optarg);
        break;
      case 'Z':
      	debug = true;
      	break;
     	case 'c':
     		threads_count = atoi(optarg);
     		break;
     	case 'o':
     		if (strncmp(optarg, "raw", 3) == 0)
     			raw_output = true;
     		else if (strncmp(optarg, "mline", 5) == 0)
     			mline_output = true;
     		break;
     	case 'D':
     		
     		break;
     	case 'E':
     		factor = atoi(optarg);
     		break;
     	case 'A':
     		detection_type = ALL;
     		prefix_len = 24;
     		break;
    }
  }

	if (targets[0] == 0x00)
	{
	  log(DUMP, "dst_addr = %s", argv[optind]);
	  if (argv[optind] == NULL) {
	    help();
	    exit(1);
	  }
	
		char *p;
		if ((p = strchr(argv[optind], '/')) != NULL) {
			*p = 0x00;
			detection_type = DEST;
			
			if (*(p - 1) == '+') {
				*(p - 1) = 0x00;
				detection_type = ALL;
			}
			//per_dest = true;
			prefix_len = atoi(p+1);
		}
	
		dst_addr = Util::my_gethostbyname(argv[optind]);
		if (dst_addr == NULL)
			help();
	}

  // Get source address to use
  src_addr = strdup(Util::getRoute(dst_addr));
}

Options::~Options () {
	//printf("delete options\n");
  delete src_addr;
  delete dst_addr;
}

void
Options::help () {
  printf("Print the route packets take to network host\n");
  printf("\n");
  printf("Usage: traceroute [Options] [Destination]\n");
  printf("\n");
  printf("Options:\n");
  printf("  -h, --help               print this help\n");
  printf("  -V, --version            print version\n");
  printf("  -v, --verbose            print debug messages\n");
  printf("  -Q, --quiet              print only results\n");
  printf("  -f, --first_ttl=TTL      set the initial ttl to TTL (default: 1)\n");
  printf("  -m, --max_ttl=TTL        set the maximum ttl to TTL (default: 30)\n");
  printf("  -p, --protocol=PROTOCOL  use PROTOCOL to send probes (udp, tcp, icmp)\n");
  printf("                           The default is 'udp'\n");
  printf("  -s, --source_port=PORT   set PORT as source port (default: 33456) pid: use PID\n");
  printf("  -d, --dest_port=PORT     set PORT as destination port (default: 33457)\n");
  printf("  -t, --tos=TOS            set TOS as type of service (default: 0)\n");
  printf("  -w MS                    wait MS ms between each probe (default: 50ms)\n");
  printf("  -T, --timeout=MS         set a timeout of MS ms on each probe\n");
  printf("                           The default is 5000ms\n");
  printf("  -q, --query=NBR          send NBR probes to each host (default: 3)\n");
  printf("  -M, --missing_hop=HOP    stop traceroute after HOP consecutive down hops\n");
  printf("                           The default is 3\n");
  printf("  -a, --algo=ALGO          algorithm to use (--algo=help for more help)\n");
  printf("                           The default is 'hopbyhop'\n");
  printf("  -L, --length=LEN         set the packet length to be used in outgoing packets\n");
  printf("                           The default is 0\n");
  printf("  -n                       print hop addresses numerically\n");
  printf("                           The default is to print also hostnames\n");
  printf("  -i  --ipid               print the IP Identifier of the reply\n");
  printf("  -l  --print_ttl          print the TTL of the reply\n");
  printf("  -F                       targets file for the MT algo\n");
  printf("  -B                       set the bandwidth in packets/s\n");
  printf("  -c                       number of threads (default 1)\n");
  printf("  -E                       probe multiplier\n");
  printf("  -r                       set the return flow identifier\n");
  printf("\n");
  exit(0);
}

void
Options::helpAlgo () {
  printf("%s - algorithms\n\n", PACKAGE_NAME);
  printf("  --algo=null              Do nothing.\n");
  printf("\n");
  printf("  --algo=hopbyhop          Send x packets with the same ttl, then wait for all\n");
  printf("                           replies or a timeout. Increment the ttl and reiter\n");
  printf("                           the operation until we reached the destination.\n");
  printf("                           All packets hold the same 5-tuples (addresses, ports\n");
  printf("                           and protocol fields).\n");
  printf("\n");
  printf("  --algo=packetbypacket    Send one packet at a time, then wait for a reply or\n");
  printf("                           a timeout. Reiter the operation until we reached the\n");
  printf("                           destination. All packets are exactly the same except\n");
  printf("                           the TTL and checkum fields of the IP header.\n");
  printf("\n");
  printf("  --algo=scout             Send a scout probe with a ttl max to the destination.\n");
  printf("                           If the destination can be reached, it computes the\n");
  printf("                           number of hops used to reach the destination and\n");
  printf("                           start the concurrent algorithm with a max_ttl equal\n");
  printf("                           to this number of hops. If the destination cannot be\n");
  printf("                           reached, the hopbyhop algorithm will be used instead.\n");
  printf("                           This algorithm is only usable with udp probes\n");
  printf("\n");
  printf("  --algo=concurrent        Send all probes from min_ttl to max_ttl and then wait\n");
  printf("                           for all replies or a timeout. All packets hold the\n");
  printf("                           same 5-tuples.\n");
  printf("\n");
  printf("  --algo=exhaustive        Tries to classify load balancing\n");
  printf("                           and find all the interfaces for each hop.\n");
  exit(0);
}

void
Options::version () {
  printf("%s ver. %s\n", PACKAGE_NAME, PACKAGE_VERSION);
  printf("Report bugs to %s\n", PACKAGE_BUGREPORT);
  printf("\n");
  exit(0);
}

void
Options::dump () {
  log(DUMP, "protocol     = %s", protocol);
  log(DUMP, "src_add      = %s", src_addr);
  log(DUMP, "dst_addr     = %s", dst_addr);
  log(DUMP, "ttl_initial  = %d", ttl_initial);
  log(DUMP, "ttl_max      = %d", ttl_max);
  log(DUMP, "tos          = %d", tos);
  log(DUMP, "probe_length = %d", probe_length);
  log(DUMP, "algo         = %s", algo);
  log(DUMP, "timeout      = %d", timeout);
  log(DUMP, "delay        = %d", delay_between_probes);
  log(DUMP, "max_try      = %d", max_try);
  log(DUMP, "max_missing  = %d", max_missing);
  log(DUMP, "id_initial   = %d", id_initial);
  log(DUMP, "resolve      = %s", resolve_hostname ? "true" : "false");
  log(DUMP, "ipid         = %s", display_ipid ? "true" : "false");
}

