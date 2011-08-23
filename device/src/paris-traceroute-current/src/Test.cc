#include "Tracert.h"
#include "Server.h"

int
main (int argc, char** argv) {
  Options* opts   = new Options(argc, argv);
  Tracert* trace  = new NULLTracert();
  Server*  server = new Server(trace, opts, "tcp");
  trace->trace();
  while (true) sleep(5);
}

