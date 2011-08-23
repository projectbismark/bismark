#include "Reply.h"

#include "Header.h"
#include "TrException.h"
#include "Util.h"

/**
 * Create a reply from an IP packet.
 *
 * At present, it can forge a reply from a ICMP packet or a TCP packet.
 */
Reply*
Reply::replyFactory (const uint8* packet, int packet_len) {
  if (packet_len > 20) {
    // Get protocol from IP packet (field 9)
    uint8 protocol = packet[9];
    switch (protocol) {
      case 1:  // ICMP
        return new ICMPReply(packet, packet_len);
      case 6:  // TCP
        return new TCPReply(packet, packet_len);
      default:
        log(DUMP, "The reply used protocol %d", protocol);
        return NULL;
    }
  } else {
    log(DUMP, "Malformed reply");
    return NULL;
  }
}

/**
 * Return the hop adress in network endianess
 * TODO: should return char*?
 */
uint32
Reply::getSourceAddress () {
  IP4Header* ip = (IP4Header*)getHeader(0);
  return ip->getSourceAddress();
}

/**
 * Return the TTL of the reply (not the original probe)
 */
uint8
Reply::getTTL () {
  IP4Header* ip = (IP4Header*)getHeader(0);
  return ip->getTTL();
}

/**
 * Debug.
 */
void
Reply::dump () {
  for (int i = 0; i < getNbrHeaders(); i++) {
    getHeader(i)->dump();
  }
}

/**
 * Debug.
 */
void
Reply::dumpRaw () {
  for (int i = 0; i < getNbrHeaders(); i++) {
    printf("header %d\n", i);
    getHeader(i)->dumpRaw();
  }
  if (data != NULL) {
  	printf("data\n");
  	dumpRawData(WARN, data, data_length);
  }
}

int
Reply::getIPId () {
  IP4Header* ip = (IP4Header*)getHeader(0);
  return ip->getIPId();
}

bool
Reply::IPOptions () {
  IP4Header* ip = (IP4Header*)getHeader(0);
  return (ip->getHeaderLength() > 20);
}
