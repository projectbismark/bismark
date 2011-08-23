#include "Reply.h"

#include "Header.h"
#include "TrException.h"
#include "Util.h"

TCPReply::TCPReply (const uint8* packet, int packet_len) {
  // Get the IP4 header
  IP4Header* ip4 = new IP4Header(packet, packet_len, 0);
  addHeader(ip4);

  // Check the protocol field, should be TCP (6)
  if (ip4->getProtocol() != 6)
    throw TrException(str_log(ERROR, "Reply should be TCP datagram"));

  int ip4_hdrlen = ip4->getHeaderLength();
    
  // Get the TCP header
  TCPHeader* tcp = new TCPHeader(packet, packet_len, ip4_hdrlen);
  addHeader(tcp);
}

TCPReply::~TCPReply () {
	//printf("delete tcpreply\n");
}

int
TCPReply::getType () {
  // A TCP reply means that we reached the destination
  return DESTINATION_REACHED;
}

int TCPReply::getProcId () {
  // Get the TCP header
  TCPHeader* tcp = (TCPHeader*)getHeader(1);
  //log(WARN, "TCPReply::getProcId TODO %x", tcp->getAckNumber() - 1);
  // Return (ack number - 1)
  return (tcp->getAckNumber() - 1) >> 16;
}

int
TCPReply::getID () {
  // Get the TCP header
  TCPHeader* tcp = (TCPHeader*)getHeader(1);
  //log(WARN, "TCPReply::getId TODO");
  // Return (ack number - 1)
  return (tcp->getAckNumber() - 1) & 0xffff;
}

int
TCPReply::getID2 () {
	log(WARN, "TCPReply::getID2 TODO");
	return 0;
}

int
TCPReply::getID3 () {
	log(WARN, "TCPReply::getID3 TODO");
	return 0;
}

int
TCPReply::getReturnFlowId () {
	//log(WARN, "getReturnFlowId() TODO\n");
	return 0;
}

uint32
TCPReply::getReservedWords () {
	return 0;
}

bool
TCPReply::resetRequired () {
  // Get the TCP header
  TCPHeader* tcp = (TCPHeader*)getHeader(1);

  // A reset is required if our syn segment has been acknowledged
  return (tcp->getSYNFlag() && tcp->getACKFlag());
}

int
TCPReply::getResetID () {
  // Get the TCP header
  TCPHeader* tcp = (TCPHeader*)getHeader(1);

  // The ID to use for the reset probe the acknowledged field of the reply + 1
  return tcp->getAckNumber() + 1;
}

int
TCPReply::getOriginalProtocol () {
  return 0x06;
}

int
TCPReply::getOriginalTTL () {
  return -1;
}

/*
never called
*/
uint32*
TCPReply::getMPLSLabelStack() {
   return NULL;
}

/*
never called
*/
int
TCPReply::getMPLSNbrLabels() {
   return 0;
}

/*
never called
*/
uint8
TCPReply::getMPLSTTL() {
  return 0;
}

/*
XXX
*/
uint32
TCPReply::getOriginalDestAddress()
{
  return 0;
}
