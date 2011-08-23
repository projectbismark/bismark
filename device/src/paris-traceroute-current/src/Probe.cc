#include "Probe.h"

/**
 * Create a new Probe.
 *
 * @param protocol Protocol to use for this probe (udp, tcp or icmp)
 * @param src_addr Source address
 * @param src_port Source port (not relevant for icmp)
 * @param dst_addr Destination address
 * @param dst_port Destination port (not relevant for icmp)
 * @param ttl Time to live
 * @param tos Time of service
 * @param data_len Length of the data to add to the probe
 * @param id Unique ID used to identify the probe (cfr. TODO)
 * @param reset The probe will be used to reset a connection
 */
Probe*
Probe::probeFactory(const char* protocol,
			const char* src_addr, int src_port,
			uint32/*const char**/ dst_addr, int dst_port,
			uint8 ttl, uint8 tos, int data_len,
			uint16 proc_id, uint16 id, int return_flow_id, bool reset) {
  if (strncmp(protocol, "icmp", 5) == 0)
    return new ICMPProbe(src_addr, dst_addr, 
    			ttl, tos, data_len, dst_port, proc_id, id, return_flow_id);
  else if (strncmp(protocol, "udp", 4) == 0)
    return new UDPProbe(src_addr, src_port, dst_addr, dst_port,
		    	ttl, tos, data_len, proc_id, id, return_flow_id);
  else if (strncmp(protocol, "tcp", 4) == 0)
    return new TCPProbe(src_addr, src_port, dst_addr, dst_port,
		    	ttl, tos, data_len, proc_id, id, reset);
  else
    return NULL;
}

Probe::~Probe () {
	//printf("delete probe\n");
}

void
Probe::getDatagram (uint8** data, int* length) {
  // Compute the total length
  int len = 0;
  for (int i = 0; i < getNbrHeaders(); i++)
    len += getHeader(i)->getHeaderLength();
  len += data_length;
  *length = len;

  // Create the datagram
  *data = new uint8[len];
  uint8* datagram = *data;
  int pos = 0;
  for (int i = 0; i < getNbrHeaders(); i++) {
    getHeader(i)->pack(datagram, len, pos);
    pos += getHeader(i)->getHeaderLength();
  }

  if (this->data != NULL)
    memcpy(datagram + pos, this->data, data_length);
}

/**
 * Send the probe.
 *
 * @throws TrException Something wrong happened.
 */
void
Probe::send () {
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

  /* Get the second header (UDP, TCP, ICMP) */
  Header* seg = getHeader(1);

  // Send the message/probe
  struct sockaddr_in buff;
  buff.sin_family       = AF_INET;
  switch (seg->getHeaderType()) {
    case Header::ICMP:
      buff.sin_port = 0;
      break;
    case Header::UDP:
      buff.sin_port = ((UDPHeader*)seg)->getDestPort();
      break;
    case Header::TCP:
      buff.sin_port = ((TCPHeader*)seg)->getDestPort();
      break;
  }
  buff.sin_addr.s_addr  = ip4->getDestAddress();
  uint8* datagram;
  int    length;
  getDatagram(&datagram, &length);
  dumpRawData(DUMP, datagram, length);
  int res = sendto(sock,datagram,length,0,(sockaddr*)&buff,sizeof(sockaddr_in));
  
  if (res < 0) throw TrException(str_log(ERROR,
		"Can't send the probe : %s", strerror(errno)));

	delete datagram;

  // Close the socket
  res = close(sock);
  if (res < 0) throw TrException(str_log(ERROR,
		"Can't close the socket : %s", strerror(errno)));
}

