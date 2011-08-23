#include "Probe.h"

/**
 * Create a new UDP probe.
 *
 * Each probe are defined by 7 parameters:
 * <ul>
 *   <li>The tuple which define an UDP-connection:
 *	(source address, source port, destination address, destination port</li>
 *   <li>The ttl to use with this Probe</li>
 *   <li>The length of data to send with the Probe</li>
 *   <li>An identifier to differentiate each Probe and their replies</li>
 * </ul>
 *
 * @param src_addr Source address (in dotted notation)
 * @param src_port Source port
 * @param dst_addr Destination address (in dotted notation)
 * @param dst_port Destination port
 * @param ttl The Time to Live
 * @param length Append <i>length</i> bytes of data after the headers (min 2)
 * @param id Identifier
 *
 * @throws TrException The source or destination address is invalid.
 */
UDPProbe::UDPProbe (const char* src_addr, int src_port,
		/*const char**/uint32 dst_addr, int dst_port,
		uint8 ttl, uint8 tos, int data_len,
		uint16 proc_id, uint16 id, int return_flow_id) : Probe() {
  // Set data_len to a minimum of 2
  if (data_len < 2) data_len = 2;

	ICMPHeader* icmp;
	if (return_flow_id != -1) {
		icmp = new ICMPHeader ();
		icmp->setType(11);
		icmp->setCode(0);
		//printf("Desired ret flow id %x\n", return_flow_id);
		icmp->setChecksum(return_flow_id);
	}
	
  // Create the IP4 header of the Probe
  IP4Header* ip4 = new IP4Header();
  //addHeader(ip4);

  // Set source address
  ip4->setSourceAddress(src_addr);

  // Set destination address
  ip4->setDestAddress(dst_addr);

  // Set TTL
  ip4->setTTL(1);
	
	ip4->setIPId(id);

  // Set ToS
  ip4->setToS(tos);

  // Set Protocol to UDP (17)
  ip4->setProtocol("udp");

	uint16 iplen = 20 + 8 + data_len;
  // Set the total length of this UDP datagram (IP + UDP + data)
  ip4->setTotalLength(htons(iplen));

	//ip4->setChecksum(Util::computeChecksum((uint16 *)ip4, 20));
	ip4->computeAndSetChecksum();

  // Create UDP header of the Probe
  UDPHeader* udp = new UDPHeader();
  //addHeader(udp);

  // Set source port
	udp->setSourcePort(src_port);

  // Set destination port
#ifdef DEVANOMALIES
	udp->setDestPort(id);
#else
  udp->setDestPort(dst_port);
#endif

#ifdef DEVANOMALIES
	udp->setChecksum(id);
#endif

	// Set the datagram length (UDP header(8) + len(data))
  int datagram_len = 8 + data_len;
  udp->setDatagramLength(datagram_len);
	
	if (return_flow_id != -1) {
		// Compute the udp checksum
		datagram_len = 8 + 20 + 8;
	  uint8* icmp_datagram = new uint8[datagram_len];
	  icmp->pack(icmp_datagram, datagram_len, 0);
	  ip4->pack(icmp_datagram, datagram_len, 8);
	  udp->pack(icmp_datagram, datagram_len, 28);
	  
	  uint16 udp_chksum = Util::computeChecksum((uint16 *)icmp_datagram, datagram_len);
	  //printf("UDP checksum 0x%x\n", udp_chksum);
	  
	  udp->setChecksum(udp_chksum);
	  
	  delete[] icmp_datagram;
	  
	  delete icmp;
	}
	
	//icmp->dumpRaw();
	//ip4->dumpRaw();
	//udp->dumpRaw();
	
	ip4->setTTL(ttl);
	ip4->setTotalLength(iplen);
	//ip4->setChecksum(Util::computeChecksum((uint16 *)ip4, 20));
	ip4->setChecksum(0);
	
	addHeader(ip4);
	addHeader(udp);
  
  if (return_flow_id != -1) {
	  // Compute the UDP data value
	  int len = 8 + 2;
	  uint8* udp_dgram = new uint8[len + 12];
	  ip4->packPseudo(len, udp_dgram, len + 12 , 0);
	  udp->pack(udp_dgram, len + 12, 12);
	  
	  //printf("dump\n");
	  //dumpRawData(WARN, udp_dgram, len + 12);
	  //printf("end dump\n");
	  
	  uint16 val = Util::computeChecksum((uint16*)udp_dgram, len +12 -2/*XXX consider data is filled with 0s; no need to compute checksum on it */);
	  //val = 0x5efe;
	  
	  delete[] udp_dgram;
	  
	  id = val;
  }
  
  //printf("Data value 0x%x\n", id);
  
  // Add the message id followed by (data_len - 2) zero's as data
  uint8* d = new uint8[data_len];
  memset(d, 0, data_len);
#ifndef DEVANOMALIES
	//log(WARN, "desactivated ID in UDP DATA");
  memcpy(d, &id, 2);
#endif
  setData(d, data_len);

	if (return_flow_id == -1) {
	  // Compute and set the UDP checksum
	  int dgram_checksum_len = datagram_len + 12;
	  uint8* dgram_checksum = new uint8[dgram_checksum_len];
	  ip4->packPseudo(datagram_len, dgram_checksum, dgram_checksum_len, 0);
	  udp->pack(dgram_checksum, dgram_checksum_len, 12);
	  packData(dgram_checksum, dgram_checksum_len, 20);
	  
	  uint16 udp_checksum = Util::computeChecksum((uint16*)dgram_checksum,
								dgram_checksum_len);
#ifdef DEVANOMALIES
		memcpy(d, &udp_checksum, 2);
		setData(d, data_len);
#else
	  udp->setChecksum(udp_checksum);
#endif
		
  	delete[] dgram_checksum;
	}
	delete[] d;		
}

UDPProbe::~UDPProbe () {
	//printf("delete udp probe\n");
}

/**
 * Send the probe.
 *
 * @throws TrException Something wrong happened.
 */
/*void
UDPProbe::send () {
  // Get the IP4 header (first header)
  IP4Header* ip4 = (IP4Header*)getHeader(0);

  // Create the socket and set some IP options
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0)
    throw TrException(str_log(ERROR, "Can't create the socket : %s",
		strerror(errno)));

  // Tell the OS to not append a IP header to the datagram
  int one = 1;
  if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
    throw TrException(str_log(ERROR, "Can't set socket option IP_HDRINCL :%s",
               strerror(errno)));

  // Get the UDP header
  UDPHeader* udp = (UDPHeader*)getHeader(1);

  // Send the message/probe
  struct sockaddr_in buff;
  buff.sin_family       = AF_INET;
  buff.sin_port         = htons(udp->getDestPort());
  buff.sin_addr.s_addr  = ip4->getDestAddress();
  uint8* datagram;
  int    length;
  getDatagram(&datagram, &length);
  dumpRawData(DUMP, datagram, length);
  int res = sendto(sock,datagram,length,0,(sockaddr*)&buff,sizeof(sockaddr_in));
  if (res < 0) throw TrException(str_log(ERROR,
		"Can't send the probe : %s", strerror(errno)));

  // Close the socket
  res = close(sock);
  if (res < 0) throw TrException(str_log(ERROR,
		"Can't close the socket : %s", strerror(errno)));
}*/

/**
 * Return an hashcode of this Probe.
 *
 * Some properties on this hashcode:
 * <ul>
 *   <li>For two probes with the same source/destination address/port, the same
 *     length and the same identifier, the two hash will be the same.</li>
 *   <li>For two different probes where the only difference is its 
 *     <i>Identifier</i> field, the two hash will be different.</li>
 *   <li>When we received an UDPReply for a probe, the <i>hash</i> method on
 *     the probe and on its reply will be the same.</li>
 * </ul>
 */
int
UDPProbe::getID () {
  //UDPHeader* udp = (UDPHeader*)getHeader(1);
  //return (int)udp->getChecksum();
	IP4Header* ip = (IP4Header*)getHeader(0);
	return (int)ip->getIPId();
}

/**
 * Debug.
 */
void
UDPProbe::dump () {
  log(DUMP, "==> UDP Probe :");
  for (int i = 0; i  < getNbrHeaders(); i++)
    getHeader(i)->dump();
  log(DUMP, "Data :");
  if (data != NULL)
    dumpRawData(DUMP, data, data_length);
}

/**
 * Debug.
 */
void
UDPProbe::dumpRaw () {
  uint8* data;
  int   length;
  getDatagram(&data, &length);
  log(DUMP, "==> UDP Probe :");
  dumpRawData(DUMP, data, length);
}

