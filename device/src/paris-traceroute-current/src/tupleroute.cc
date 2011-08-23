#include "common.h"
#include "Options.h"
#include "Util.h"
#include "Server.h"
#include "Tracert.h"
#include "Output.h"

#include <stdio.h>
#include <unistd.h>

#define NULL_TRACERT		0
#define TEST_TRACERT		1
#define HOPBYHOP_TRACERT	2
#define PACKBYPACK_TRACERT	3
#define CONCURRENT_TRACERT	4
#define SCOUT_TRACERT		5
#define EXHAUSTIVE_TRACERT		6

int main (int argc, char** argv) {
  
  // Check CAP_NET_RAW capabilities
  if (getuid() != 0) {
    //log(FATAL, "You must be root to run this program");
    //exit(-1);
  }

  //printf("WARNING !! uncomment switch algo AND if algo scout !!\n");
  
  // Initialisation
  Options* opts        = new Options(argc, argv);
  Tracert* traceroute  = NULL;
  Server*  icmp_server = NULL;
  Server*  tcp_server  = NULL;
  opts->dump();

  // Select an algorithm
  int algo = NULL_TRACERT;
  if (strncmp(opts->algo, "hopbyhop", strlen(opts->algo)) == 0) {
    algo = HOPBYHOP_TRACERT;
  } else if (strncmp(opts->algo, "packetbypacket", strlen(opts->algo)) == 0) {
    algo = PACKBYPACK_TRACERT;
  } else if (strncmp(opts->algo, "test", strlen(opts->algo)) == 0) {
    algo = TEST_TRACERT;
  } else if (strncmp(opts->algo, "concurrent", strlen(opts->algo)) == 0) {
    algo = CONCURRENT_TRACERT;
  } else if (strncmp(opts->algo, "scout", strlen(opts->algo)) == 0) {
    if (strncmp(opts->protocol, "udp", 5) != 0) {
      log(INFO, "Scout algo is only usable with udp => hopbyhopalgo");
      algo = HOPBYHOP_TRACERT;
    } else algo = SCOUT_TRACERT;
  } else if (strncmp(opts->algo, "exhaustive", strlen(opts->algo)) == 0) {
    algo = EXHAUSTIVE_TRACERT;
  } else {
    strcpy(opts->algo, "null");
    // warn user.
    // maybe he made a mistake when typing the so-long-algo-names !
    log(WARN, "Unknown algo (--algo=help for more help)");
  }

  // Create algo structures
  switch (algo) {
    case HOPBYHOP_TRACERT:
      traceroute = new HopByHopTracert(opts);
      break;
    case EXHAUSTIVE_TRACERT:
      traceroute = new ExhaustiveTracert(opts);
      break;
    case PACKBYPACK_TRACERT:
      traceroute = new PackByPackTracert(opts);
      break;
    case CONCURRENT_TRACERT:
      traceroute = new ConcurrentTracert(opts, opts->ttl_max);
      break;
    case SCOUT_TRACERT:
      traceroute = new ScoutTracert(opts, opts->ttl_max);
      break;
    default:
      traceroute = new NULLTracert();
      break;
  }

  //traceroute->getHopInfo(0, 0);
  
  // Create and start servers
  icmp_server = new Server(opts, "icmp");
  icmp_server->setClient(traceroute);
  icmp_server->startThread();
  if (strncmp(opts->protocol, "tcp", 4) == 0) {
    tcp_server = new Server(opts, "tcp");
    tcp_server->setClient(traceroute);
    tcp_server->startThread();
  }

  // Main part
  bool possible = traceroute->trace();

  if (algo == SCOUT_TRACERT) {
    icmp_server->setClient(NULL);
    if (strncmp(opts->protocol, "tcp", 4) == 0)
       tcp_server->setClient(NULL);
    
    if (possible) {
      // Execute concurrent traceroute
      int reply_ttl = traceroute->getHopInfo(0, 0)->reply_ttl;
      int ttl_dest  = opts->ttl_max - reply_ttl + 1;
      log(INFO, "ttl of the destination is %d", ttl_dest);
      delete traceroute;
      traceroute = new ConcurrentTracert(opts, ttl_dest);
    } else {
      // Execute hop-by-hop traceroute
      log(INFO, "Concurrent algo is not usable => use hopbyhop algo");
      delete traceroute;
      traceroute = new HopByHopTracert(opts);
    }

    icmp_server->setClient(traceroute);
    if (strncmp(opts->protocol, "tcp", 4) == 0)
      tcp_server->setClient(traceroute);
    traceroute->trace();
  }

  // Output
  //if (algo != EXHAUSTIVE_TRACERT)
    Output::text(stdout, traceroute, opts);
  //else
  //  printf("Output disabled for ExhaustiveTracert\n");
  
  log(INFO, "output done");
  
  // Free ressources
  delete icmp_server;
  log(INFO, "deleted icmp_server");
  if (tcp_server != NULL) delete tcp_server;
  delete traceroute;
  log(INFO, "deleted traceroute");
  delete opts;

  log(INFO, "exiting...");
  
  return 0;
}

