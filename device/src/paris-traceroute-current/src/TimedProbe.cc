#include "Tracert.h"

long
TimedProbe::getRTT () const {
  if (arrival_time <= send_time) return 0;
  else return arrival_time - send_time;
}

const char*
TimedProbe::getHostAddress () const {
  return host_address;
}

const char*
TimedProbe::getHostName () const {
  if (host_name == NULL) return host_address;
  else return host_name;
}

