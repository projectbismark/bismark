#include "Tracert.h"

#include "common.h"
#include "TrException.h"
#include "Reply.h"
#include "Time.h"

NULLTracert::NULLTracert () {
	printf("tracert impl\n");	
  log(INFO, "NULL algo");
}

/**
 * Destructor
 */
NULLTracert::~NULLTracert () {
}

bool
NULLTracert::trace () {
  return true;
}

uint8
NULLTracert::getMinTTL () {
  return 1;
}

uint8
NULLTracert::getMaxTTL () {
  return 0;
}

uint8
NULLTracert::getNbrProbes(uint8 ttl) {
  return 0;
}

uint8
NULLTracert::getNbrReplies(uint8 ttl) {
  return 0;
}

uint8
NULLTracert::getNbrInterfaces(uint8 ttl) {
  return 0;
}

/*const TimedProbe*
NULLTracert::getHopInfo (uint8 ttl, int nprobe) {
  printf("NULLTracert::getHopInfo\n");
  return NULL;
}*/

void
NULLTracert::notifyReply (Reply* reply) {
}
