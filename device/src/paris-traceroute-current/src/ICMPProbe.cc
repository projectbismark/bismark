#include "Probe.h"

/**
 * TODO: ICMP
 * Create a new UDP probe.
 *
 * Each probe are defined by 5 parameters:
 * <ul>
 *   <li>The tuple which define an "IP-connection":
 *      (source address, destination address</li>
 *   <li>The ttl to use with this Probe</li>
 *   <li>The length of data to send with the Probe</li>
 *   <li>An identifier to differentiate each Probe and their replies</li>
 * </ul>
 *
 * @param src_addr Source address (in dotted notation)
 * @param src_port Source port
 * @param ttl The Time to Live
 * @param length Append <i>length</i> bytes of data after the headers (min 2)
 * @param id Identifier
 *
 * @throws TrException The source or destination address is invalid.
 */
ICMPProbe::ICMPProbe (const char* src_addr, uint32/*const char**/ dst_addr,
		  uint8 ttl, uint8 tos,
			int data_len, int chksum, uint16 proc_id, uint16 id, int return_flow_id) : Probe() {
  // Set data_len to a minimum of 2
  if (data_len < 2) data_len = 2;
  
  // Create the IP4 header of the Probe
  IP4Header* ip4 = new IP4Header();
  addHeader(ip4);

  // Set source address
  ip4->setSourceAddress(src_addr);

  // Set destination address
  ip4->setDestAddress(dst_addr);

  // Set TTL
  ip4->setTTL(ttl);

	//ip4->setIPId(id);

  // Set ToS
  ip4->setToS(tos);

  // Set Protocol to ICMP (1)
  ip4->setProtocol("icmp");

  // Set the total length of this ICMP datagram (IP + UDP + data)
  ip4->setTotalLength(20 + 8 + data_len); 

  // Create the ICMP header of the Probe
  ICMPHeader* icmp = new  ICMPHeader();
  addHeader(icmp);

  // Set type to "Echo Request" (type 8)
  icmp->setType(8);

  // Set the identifier
  //icmp->setIdentifier(id);
  icmp->setIdentifier(proc_id);
  
  //
  icmp->setSequence(id);
  
  // Set <i>data_len</i> zero's as data
  //if (data_len > 0) {
    uint8* d = new uint8[data_len];
    memset(d, 0, data_len);
    //if (return_flow_id != -1)
    //	memcpy(d, &return_flow_id, 2);
    setData(d, data_len);
    
  //}

  // XXX
  icmp->setChecksum(chksum);
  
  // Compute the checksum
  int datagram_len = 8 + data_len;
  uint8* icmp_datagram = new uint8[datagram_len];
  icmp->pack(icmp_datagram, datagram_len, 0);
  packData(icmp_datagram, datagram_len, 8);

  uint16 chksum_balance = Util::computeChecksum((uint16*)icmp_datagram,datagram_len);

  //icmp->setChecksum(Util::computeChecksum((uint16*)icmp_datagram,datagram_len));
  
  (*(uint16 *)d) = chksum_balance;
  setData(d, data_len);

	//icmp->setSequence(chksum_balance);
  
  delete[] d;
}

ICMPProbe::~ICMPProbe () {
	//printf("delete icmp probe\n");
}

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
ICMPProbe::getID () {
  ICMPHeader* icmp = (ICMPHeader*)getHeader(1);
  return (int)icmp->getSequence();
}

/**
 * Debug.
 */
void
ICMPProbe::dump () {
  log(DUMP, "==> ICMP Probe :");
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
ICMPProbe::dumpRaw () {
  uint8* data;
  int   length;
  getDatagram(&data, &length);
  log(DUMP, "==> ICMP Probe :");
  dumpRawData(DUMP, data, length);
}

