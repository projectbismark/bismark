#include "Header.h"

#include "TrException.h"
#include "Util.h"
#include "common.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * Create a new IPv4 header.
 *
 * All fields are initialized to zero.
 * @todo Handle IPv4 options
 */
IP4Header::IP4Header () {
  header = new uint8[20];
  header_len = 20;
  memset(header, 0, 20);
  header[0] = 0x45;
}

/**
 * Create a new IPv4 header and initialize it with 20 bytes of <i>data</i> array
 * beginning at offset <i>offset</i>.
 */
IP4Header::IP4Header (const uint8* data, int length, int offset) {
  const uint8* ptr = data + offset;
  // 'Version' field
  if ((ptr[0] & 0xf0) != 0x40)
    throw TrException(str_log(ERROR, "Bad IP version"));

  // 'Header length' field
  if ((ptr[0] & 0x0f) != 0x05) {
    printf("ihl=%d\n", (ptr[0] & 0x0f));
    dumpRawData(WARN, (uint8 *)ptr, length);
  
    /*throw TrException(str_log(ERROR,
      "IP4Header doesn't support IP options yet"));*/
  }
  
  // Initialize the header field
  header_len = (ptr[0] & 0x0f) << 2;
  header = new uint8[header_len];
  memcpy(header, ptr, header_len);
}

/**
 * Delete <i>this</i> IPv4 header.
 */
IP4Header::~IP4Header () {
	//printf("QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ delete IP4header\n");
  delete[] header;
}

/**
 * Set the value of the <i>Type of Service</i> field (byte 1)
 */
void
IP4Header::setToS (uint8 tos) {
  header[1] = tos;
}

/**
 * Return the value of the <i>Type of Service</i> field (byte 1)
 */
uint8
IP4Header::getToS () {
  return header[1];
}

#ifdef __APPLE__
/**
 * Set the total length of the IP datagram (bytes 2-3)
 */
void
IP4Header::setTotalLength (uint16 length) {
  Util::write16(header, 2, length);
}

/**
 * Return the total length of the IP datagram (bytes 2-3)
 */
uint16
IP4Header::getTotalLength () {
  return Util::read16(header, 2);
}

#else // __APPLE__

#if defined __NetBSD__ || __FreeBSD__
/**
 * Set the total length of the IP datagram (bytes 2-3)
 */
void
IP4Header::setTotalLength (uint16 length) {
  Util::write16(header, 2, length);
}

#ifdef USEPCAP
	/**
	 * Return the total length of the IP datagram (bytes 2-3)
	 */
	uint16
	IP4Header::getTotalLength () {
	  return Util::readbe16(header, 2);
	}
#else
/**
 * Return the total length of the IP datagram (bytes 2-3)
 */
uint16
IP4Header::getTotalLength () {
  return Util::read16(header, 2);
}
#endif
#else
void
IP4Header::setTotalLength (uint16 length) {
  Util::writebe16(header, 2, length);
}
   
uint16
IP4Header::getTotalLength () {
  return Util::readbe16(header, 2);
}
#endif // NETBSD
#endif // __APPLE__

// APPLE: be
void
IP4Header::setIPId (uint16 id) {
  Util::writebe16(header, 4, id);
}

/**
 * Return the IP Identifier
 */
#if 0
uint16
IP4Header::getIPId () {
  return Util::read16(header, 4);
}
#else
uint16
IP4Header::getIPId () {
  return Util::readbe16(header, 4);
}
#endif

/**
 * Set the <i>TTL</i> field (byte 8)
 */
void
IP4Header::setTTL (uint8 ttl) {
  header[8] = (uint8)ttl;
}

/**
 * Return the <i>TTL</i> field (byte 8)
 */
uint8
IP4Header::getTTL () {
  return header[8];
}

/**
 * Set the <i>Protocol</i> field (byte 9)
 *
 * @param protocol The protocol number
 */
void
IP4Header::setProtocol (uint8 protocol) {
  header[9] = (uint8)protocol;
}

/**
 * Set the <i>Protocol</i> field (byte 9)
 *
 * @param protocol The protocol name
 * @throw TrException Incorrect protocol name
 */
void
IP4Header::setProtocol (const char* prot_name) {
  //if (strcmp(prot_name, "udp") != 0)
  //	throw TrException(str_log(ERROR, "Memory leak test : %s not allowed", prot_name));
  
  //header[9] = 0x11;
  
  //return;
  
  struct protoent* protocol = getprotobyname(prot_name);
  
  if (protocol == NULL) {
    perror("getprotobyname");
    throw TrException(str_log(ERROR, "Invalid protocol name : %s", prot_name));
  }
  else {
    header[9] = (uint8)protocol->p_proto;
  }
}

/**
 * Return the <i>Protocol</i> field (byte 9)
 */
uint8
IP4Header::getProtocol () {
  return header[9];
}

/**
 * Set the <i>Checksum</i> field (byte 10-11)
 */
void
IP4Header::setChecksum (uint16 checksum) {
  Util::write16(header, 10, checksum);
}

/**
 * Return the <i>Protocol</i> field (byte 10-11)
 */
uint16
IP4Header::getChecksum () {
  return Util::read16(header, 10);
}

/**
 * Compute and set the <i>Checksum</i> field (byte 10-11)
 * To be valid, verify that all fields of the IP datagram have been filled.
 */
void
IP4Header::computeAndSetChecksum () {
  Util::write16(header, 10, 0);
  uint16 chk = Util::computeChecksum((const uint16*)header, 20);
  Util::write16(header, 10, chk);
}

/**
 * Set the <i>Source address</i> field (bytes 12-15)
 */
void
IP4Header::setSourceAddress (const char* address) {
  struct in_addr buff;
  int res = inet_aton(address, &buff);
  if (res == 0)
    throw TrException(str_log(ERROR, "Invalid source address : %s", address));
  Util::write32(header, 12, buff.s_addr);
}

/**
 * Return the <i>Source Address</i> field (byte 12-15)
 */
uint32
IP4Header::getSourceAddress () {
  return Util::read32(header, 12);
}

/**
 * Set the <i>Destination address</i> field (bytes 16-19)
 */
void
IP4Header::setDestAddress (uint32 /*const char**/ address) {
  /*struct in_addr buff;
  int res = inet_aton(address, &buff);
  if (res == 0)
    throw TrException(str_log(ERROR,
			"Invalid destination address : %s", address));*/
  Util::write32(header, 16, address/*buff.s_addr*/);
}

/**
 * Return the value of the <i>Destination Address</i> field (bytes 16-19)
 */
uint32
IP4Header::getDestAddress () {
  return Util::read32(header, 16);
}

/**
 * Return the header type : Header::IP4
 */
int
IP4Header::getHeaderType () {
  return IP4;
}

/**
 * Return the header length in bytes.
 */
int
IP4Header::getHeaderLength () {
  return header_len;
}

/**
 * Copy this IPv4 header at offset <i>offset</i> in the array <i>data</i>.
 *
 * @param data The destination array
 * @param length The length of the destination array
 * @param offset The offset where the header has to be copied
 *
 * @throw TrException There isn't enough place in the array <i>data</i> to hold
 *		the header
 */
void
IP4Header::pack (uint8* data, int length, int offset) {
  uint8* ptr = data + offset;

  // Check if the data structure can contain the IP header
  if (offset + 20 > length)
    throw TrException(str_log(ERROR, "Not enough space in data array"));

  // Copy the header
  memcpy(ptr, header, 20);
}

/**
 * @throw TrException There isn't enough place in the array <i>data</i> to hold
 *		the pseudo header
 */
void
IP4Header::packPseudo (uint16 dgram_len, uint8* data, int data_len, int offset){
  uint8* ptr = data + offset;

  // Check if the data structure can contain the IP pseudo header
  if (offset + 12 > data_len)
    throw TrException(str_log(ERROR, "Not enough space in data array"));

  // Create the pseudo header
  memset(ptr, 0, 12);
  Util::write32(ptr, 0, getSourceAddress());
  Util::write32(ptr, 4, getDestAddress());
  ptr[9] = getProtocol();
  Util::writebe16(ptr, 10, dgram_len);
}

/**
 * Debug.
 */
void
IP4Header::dump () {
  log(DUMP, "IP4 header :");
  log(DUMP, "tos                = %d", getToS());
  log(DUMP, "total_length       = %d", getTotalLength());
  log(DUMP, "ttl                = %d", getTTL());
  log(DUMP, "protocol           = %d", getProtocol());
  struct in_addr addr;
  addr.s_addr = *(uint32*)(header + 12);
  log(DUMP, "source_address     = %s", inet_ntoa(addr));
  addr.s_addr = *(uint32*)(header + 16);
  log(DUMP, "dest_address       = %s", inet_ntoa(addr));
}

/**
 * Debug.
 */
void
IP4Header::dumpRaw () {
  log(DUMP, "IP4 header :");
  dumpRawData(WARN, header, header_len);
}

