#include "Probe.h"

TCPProbe::TCPProbe (const char* src_addr, int src_port,
			uint32 /*const char**/ dst_addr, int dst_port,
			uint8 ttl, uint8 tos, int data_len,
			uint16 proc_id, uint16 id, bool rst) : Probe() {
  // Create the IPv4 header
  IP4Header* ip4 = new IP4Header();
  addHeader(ip4);

  // Set source address
  ip4->setSourceAddress(src_addr);

  // Set destination address
  ip4->setDestAddress(dst_addr);

  // Set TTL
  ip4->setTTL(ttl);

  // Set ToS
  ip4->setToS(tos);

  // Set Protocol to TCP
  ip4->setProtocol("tcp");

  // Set the total length of this UDP datagram (IP + TCP + data)
  ip4->setTotalLength(20 + 20 + data_len);

  // Create the TCP header
  TCPHeader* tcp = new TCPHeader();
  addHeader(tcp);

  // Set source port
  tcp->setSourcePort(src_port);

  // Set destination port
  tcp->setDestPort(dst_port);
	//printf("creating a probe with id = %d, proc_id = %d\n", id, proc_id);
  // Set sequence number
  tcp->setSeqNumber((uint32)proc_id << 16 | id);

  // Set ack number
  tcp->setAckNumber(0);

  if (rst) {
    // This probe should reset the connection : set RST flag
    tcp->setRSTFlag(true);
  } else {
    // This probe should establish a connection : set SYN flag
    tcp->setSYNFlag(true);
  }

  // Set Window to any value
  tcp->setWindow(32767);

  // add data_len zero's as data
  if (data_len != 0) {
    uint8* d = new uint8[data_len];
    memset(d, 0, data_len);
    setData(d, data_len);
    delete[] d;
  }

  // Compute and set Checksum field
  int datagram_len = 20 + data_len;
  int dgram_checksum_len = datagram_len + 12;
  uint8* dgram_checksum = new uint8[dgram_checksum_len];
  ip4->packPseudo(datagram_len, dgram_checksum, dgram_checksum_len, 0);
  tcp->pack(dgram_checksum, dgram_checksum_len, 12);
  packData(dgram_checksum, dgram_checksum_len, 32);
  tcp->setChecksum(
	Util::computeChecksum((uint16*)dgram_checksum, dgram_checksum_len));
  delete[] dgram_checksum;
}

/*void
TCPProbe::send () {
  // Get the IP4 header (first header)
  IP4Header* ip4 = (IP4Header*)getHeader(0);

  // Create the socket and set some IP options
  int sock = socket(PF_INET, SOCK_RAW, ip4->getProtocol());
  if (sock < 0)
    throw TrException(str_log(ERROR, "Can't create the socket : %s",
				 strerror(errno)));

  // Set the TTL value
  uint8 ttl = ip4->getTTL();
  int res = setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(uint8));
  if (res < 0) throw TrException(str_log(ERROR,
                "Can't set the TTL on the socket : %s", strerror(errno)));

  // Set the ToS value
  uint8 tos = ip4->getToS();
  res = setsockopt(sock, SOL_IP, IP_TOS, &tos, sizeof(uint8));
  if (res < 0) throw TrException(str_log(ERROR,
                "Can't set the ToS on the socket : %s", strerror(errno)));

  // Get the TCP header
  TCPHeader* tcp = (TCPHeader*)getHeader(1);

  // Bind to the source address and port
  struct sockaddr_in buff;
  buff.sin_family       = AF_INET;
  buff.sin_port         = htons(tcp->getSourcePort());
  buff.sin_addr.s_addr  = ip4->getSourceAddress();
  res = bind(sock, (sockaddr*)&buff, sizeof(sockaddr_in));
  if (res < 0) throw TrException(str_log(ERROR,
                "Can't bind to source address : %s", strerror(errno)));

  // Send the message/probe
  buff.sin_port         = htons(tcp->getDestPort());
  buff.sin_addr.s_addr  = ip4->getDestAddress();
  uint8* datagram;
  int    length;
  getDatagram(&datagram, &length);
  res = sendto(sock, datagram, length, 0, (sockaddr*)&buff,sizeof(sockaddr_in));
  if (res < 0) throw TrException(str_log(ERROR,
                "Can't send the probe : %s", strerror(errno)));

  // Close the socket
  res = close(sock);
  if (res < 0) throw TrException(str_log(ERROR,
                "Can't close the socket : %s", strerror(errno)));
}*/

int
TCPProbe::getID () {
  TCPHeader* tcp = (TCPHeader*)getHeader(1);
  return (int)tcp->getSeqNumber() & 0xffff;
}

void
TCPProbe::dump () {
  log(DUMP, "==> TCP Probe :");
  for (int i = 0; i  < getNbrHeaders(); i++)
    getHeader(i)->dump();
  log(DUMP, "Data :");
  if (data != NULL)
    dumpRawData(DUMP, data, data_length);
}

void
TCPProbe::dumpRaw () {
  uint8* data;
  int   length;
  getDatagram(&data, &length);
  log(DUMP, "==> TCP Probe :");
  dumpRawData(DUMP, data, length);
}

