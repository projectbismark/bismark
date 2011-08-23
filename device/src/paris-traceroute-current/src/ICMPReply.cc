#include "Reply.h"

#include "Header.h"
#include "TrException.h"
#include "Util.h"
#include "common.h"
/**
 * Create a new <i>ICMPReply</i> from an ICMP packet.
 *
 * This constructor will initialize up to 4 headers:
 * <ul>
 *   <li>IPv4 header</li>
 *   <li>ICMP header</li>
 *   <li>Erroneous IPv4 header</li>
 *   <li>Erroneous TCP/UDP/ICMP header</li>
 * </ul>
 */
ICMPReply::ICMPReply (const uint8* packet, int packet_len) {
  // Get the IP4 header
  IP4Header* ip4 = new IP4Header(packet, packet_len, 0);
  addHeader(ip4);

  // Check the protocol, should be ICMP
  if (ip4->getProtocol() != 1)
    throw TrException(str_log(ERROR, "Reply should be ICMP datagram"));
  
  int ip4_hdrlen = ip4->getHeaderLength();
    
  // Get the ICMP header
  ICMPHeader* icmp = new ICMPHeader(packet, packet_len, ip4_hdrlen);
  addHeader(icmp);

  // Case of a Port Unreachable or Time Exceeded ICMP Message
  if (icmp->getType() == 0x0b || icmp->getType() == 0x03) {
    // Get the IP header of the erronous message
    IP4Header* err_ip4 = new IP4Header(packet, packet_len, ip4_hdrlen + 8);
    addHeader(err_ip4);

    int ip_remaining_len = ip4->getTotalLength() - 8 - 128;
    //printf("remain len %d bytes (IP %d)\n", ip_remaining_len, ip4->getTotalLength());
#if defined __NetBSD__ || __FreeBSD__ || __APPLE__
	#ifdef USEPCAP
		ip_remaining_len -= ip4_hdrlen;
		//printf("remaining %d\n", ip_remaining_len);
	#endif
#else

    ip_remaining_len -= ip4_hdrlen;

#endif // __NETBSD__
		//printf("Remaining %d\n", ip_remaining_len);

    // If the protocol is UDP, get the UDP header.
    if (err_ip4->getProtocol() == 17) {
      UDPHeader* err_udp = new UDPHeader(packet, packet_len, ip4_hdrlen + 28);
      addHeader(err_udp);
      // Check if there is an ICMP MPLS extension
      if (ip_remaining_len > 0) {
        MPLSHeader* mpls = new MPLSHeader(packet, ip_remaining_len, ip4_hdrlen + 8 + 128);
        addHeader(mpls);
      }
    // Else if the protocol is ICMP, get the ICMP header
    } else if (err_ip4->getProtocol() == 1) {
       ICMPHeader* err_icmp = new ICMPHeader(packet, packet_len, 48);
       addHeader(err_icmp);
       // Check if there is an ICMP MPLS extension
       if (ip_remaining_len > 0) {
         MPLSHeader* mpls = new MPLSHeader(packet, ip_remaining_len, ip4_hdrlen + 8 + 128);
         addHeader(mpls);
       }
    // Else set the last height bytes as RAW data
    } else if (err_ip4->getProtocol() == 6) {
       ICMPHeader* err_icmp2 = new ICMPHeader(packet, packet_len, ip4_hdrlen + 28);
       //printf("adding header\n");
       addHeader(err_icmp2);
       //printf("done\n");
       // Check if there is an ICMP MPLS extension
       if (ip_remaining_len > 0) {
         //printf("adding MPLS\n");
         MPLSHeader* mpls = new MPLSHeader(packet, ip_remaining_len, ip4_hdrlen + 8 + 128);
         addHeader(mpls);
       }
       setData(packet + ip4_hdrlen + 28, 8);
    }
    
    else {
       setData(packet + ip4_hdrlen + 28, 8);
    }
  }
}

ICMPReply::~ICMPReply () {
	//printf("delete icmpreply\n");
}

/**
 * Return the type of the message.
 *
 * For ICMP reply:
 * <ul>
 *   <li>An ICMP Echo Reply means that the dest has been reached(ICMP)</li>
 *   <li>An ICMP Port Unreachable means that the dest has been reached(UDP)</li>
 *   <li>An ICMP Time Expired means that a intermediary router has been found</li>
 *   <li>All other ICMP message are unknow</li>
 * </ul>
 */
int
ICMPReply::getType () {
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  //printf("%d\n", icmp->getType());
  switch (icmp->getType()) {
    case 0x00: // echo_reply
      return DESTINATION_REACHED;
    case 0x03: // unreach
      switch (icmp->getCode()) {
        case 0x00:
          return NETWORK_UNREACHABLE;
        case 0x01:
          return HOST_UNREACHABLE;
        case 0x02:
          // brice 09/06/2006
          // classic traceroute stops with this message
          return DESTINATION_REACHED;
          //return PROTOCOL_UNREACHABLE;
        case 0x03:
          return DESTINATION_REACHED;
        case 0x0d:
        	return COMM_PROHIBITED;
        default:
          return OTHER_UNREACHABLE;
      }
      break;
    case 0x04:
      return SOURCE_QUENCH;
    case 0x0b: // time_xceed
      return TIME_EXPIRED;
  }
  return UNKNOW;
}

int
ICMPReply::getProcId () {
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  switch (icmp->getType()) {
    case 0x00:
      return icmp->getIdentifier();
    case 0x03:
    case 0x0b:
      IP4Header* err_ip = (IP4Header*)getHeader(2);
      /*
      ICMPReply.cc: In member function `virtual int ICMPReply::getProcId()':
      ICMPReply.cc:141: jump to case label
      ICMPReply.cc:139:   crosses initialization of `UDPHeader*err_udp'
      ICMPReply.cc:144: jump to case label
      ICMPReply.cc:142:   crosses initialization of `ICMPHeader*err_icmp'
      ICMPReply.cc:139:   crosses initialization of `UDPHeader*err_udp'
      */
      /*switch (err_ip->getProtocol()) {
        case 6:
          return Util::readbe16(data, 4);
          break;
        case 17:
          UDPHeader* err_udp = (UDPHeader*)getHeader(3);
          return err_udp->getChecksum();
          break;
        case 1:
          ICMPHeader* err_icmp = (ICMPHeader*)getHeader(3);
          return err_icmp->getIdentifier();
        default:
          return 0;
      }*/
      if (err_ip->getProtocol() == 6) { // TCP : hash is sequence number
        // Sequence number is the bytes 6-7 of the data field
        return Util::readbe16(data, 4);
      } else if (err_ip->getProtocol() == 17) { // UDP : "id" is the checksum
        UDPHeader* err_udp = (UDPHeader*)getHeader(3);
        return err_udp->getSourcePort();
        return proc_id;
      } else if (err_ip->getProtocol() == 1) { // ICMP : "id" is the identifier
        ICMPHeader* err_icmp = (ICMPHeader*)getHeader(3);
        return err_icmp->getIdentifier();
      } else { // Protocol not supported : return 0
        log(DUMP, "Protocol not supported");
        return 0;
      }
  }
  return 0;
}

/**
 * Return the ID of this ICMP reply:
 * <ul>
 *   <li>For an ICMP Echo reply, the ID is the <i>sequence</i> field</li>
 *   <li>For an ICMP Time Exceeded and ICMP Port Unreachable message,
 *     the ID depends on the protocol encapsulated (cfr. TODO)</li>
 * </ul>
 */
int
ICMPReply::getID () {
  // Get the ICMP header
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  switch (icmp->getType()) {
    case 0x00:	// Echo reply
      // "id" is the identifier field
      return icmp->getSequence();
    case 0x03:	// Port unreachable
    case 0x0b:	// Time Exceeded
      // Get Erroneous IPv4 header
      IP4Header* err_ip = (IP4Header*)getHeader(2);
      if (err_ip->getProtocol() == 6) { // TCP : hash is sequence number
        // Sequence number is the bytes 6-7 of the data field
        return Util::readbe16(data, 6);
      } else if (err_ip->getProtocol() == 17) { // UDP : "id" is the checksum
        //UDPHeader* err_udp = (UDPHeader*)getHeader(3);
        //return err_udp->getChecksum();
        return err_ip->getIPId();
      } else if (err_ip->getProtocol() == 1) { // ICMP : "id" is the identifier
        ICMPHeader* err_icmp = (ICMPHeader*)getHeader(3);
        //return err_ip->getIPId();
        return err_icmp->getSequence();
      } else { // Protocol not supported : return 0
        log(DUMP, "Protocol not supported");
        return 0;
      }

  }
  log(DUMP, "Unsupported ICMP message");
  return 0;
}

int
ICMPReply::getID2 () {
	ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
	switch (icmp->getType()) {
    case 0x00:	// Echo reply
    	log(WARN, "getID2 icmp reply TODO\n");
      return 0;
    case 0x03:	// Port unreachable
    case 0x0b:	// Time Exceeded
      // Get Erroneous IPv4 header
      IP4Header* err_ip = (IP4Header*)getHeader(2);
      if (err_ip->getProtocol() == 6) { 
      	log(WARN, "getID2 tcp TODO\n");
        return 0;
      } else if (err_ip->getProtocol() == 17) {
        UDPHeader* err_udp = (UDPHeader*)getHeader(3);
        return err_udp->getChecksum();
      } else if (err_ip->getProtocol() == 1) {
      	log(WARN, "getID2, icmp err TODO\n");
        ICMPHeader* err_icmp = (ICMPHeader*)getHeader(3);
        return 0;
      } else { // Protocol not supported : return 0
        log(DUMP, "Protocol not supported");
        return 0;
      }

  }
  log(DUMP, "Unsupported ICMP message");
  return 0;
}

int
ICMPReply::getID3 () {
	ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
	switch (icmp->getType()) {
    case 0x00:	// Echo reply
    	log(WARN, "getID3 icmp reply TODO\n");
      return 0;
    case 0x03:	// Port unreachable
    case 0x0b:	// Time Exceeded
      // Get Erroneous IPv4 header
      IP4Header* err_ip = (IP4Header*)getHeader(2);
      if (err_ip->getProtocol() == 6) { 
      	log(WARN, "getID3 tcp TODO\n");
        return 0;
      } else if (err_ip->getProtocol() == 17) {
        UDPHeader* err_udp = (UDPHeader*)getHeader(3);
        return err_udp->getDestPort();
      } else if (err_ip->getProtocol() == 1) {
      	log(WARN, "getID3, icmp err TODO\n");
        ICMPHeader* err_icmp = (ICMPHeader*)getHeader(3);
        return 0;
      } else { // Protocol not supported : return 0
        log(DUMP, "Protocol not supported");
        return 0;
      }

  }
  log(DUMP, "Unsupported ICMP message");
  return 0;
}

uint32
ICMPReply::getReservedWords () {
	ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
	uint32 val = icmp->getIdentifier() << 16 | icmp->getSequence();
	return val;
}

int
ICMPReply::getReturnFlowId () {
	ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
	return icmp->getChecksum();
}

/**
 * Indicates if we have to reset the connection.
 * Always false for ICMP message.
 */
bool
ICMPReply::resetRequired () {
  return false;
}

/**
 * Return the ID to use to reset the connection.
 * No reset required for ICMP reply => return 0
 */
int
ICMPReply::getResetID () {
  return 0;
}

int
ICMPReply::getOriginalTTL () {
  // Get the ICMP header
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  IP4Header* err_ip;
  switch (icmp->getType()) {
    case 0x03:  // Port unreachable
    case 0x0b:  // Time Exceeded
      // Get Erroneous IPv4 header
      err_ip = (IP4Header*)getHeader(2);
      return err_ip->getTTL();
    default:
      return -1;
  }
}

int
ICMPReply::getOriginalProtocol () {
  // Get the ICMP header
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  IP4Header* err_ip;
  switch (icmp->getType()) {
    case 0x03:  // Port unreachable
    case 0x0b:  // Time Exceeded
      // Get Erroneous IPv4 header
      err_ip = (IP4Header*)getHeader(2);
      return err_ip->getProtocol();
    default:
      return 0x01;
  }
}

/*
*/
uint32*
ICMPReply::getMPLSLabelStack() {
   if (getNbrHeaders() < 5)
      return NULL;

   MPLSHeader* mpls = (MPLSHeader*)getHeader(4);

   return mpls->getLabelStack();
}

/*
*/
int
ICMPReply::getMPLSNbrLabels() {
   if (getNbrHeaders() < 5)
      return 0;

   MPLSHeader* mpls = (MPLSHeader*)getHeader(4);

   return mpls->getNbrLabels();
}

/*
*/
uint8
ICMPReply::getMPLSTTL() {
  if (getNbrHeaders() < 5)
      return 0;

   MPLSHeader* mpls = (MPLSHeader*)getHeader(4);

   return mpls->getTTL();
}

/*
XXX
*/
uint32
ICMPReply::getOriginalDestAddress() {
  // Get the ICMP header
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  IP4Header* err_ip;
  switch (icmp->getType()) {
    case 0x03:  // Port unreachable
    case 0x0b:  // Time Exceeded
      // Get Erroneous IPv4 header
      err_ip = (IP4Header*)getHeader(2);
      return err_ip->getDestAddress();
    default:
      return 0;
  }
}
