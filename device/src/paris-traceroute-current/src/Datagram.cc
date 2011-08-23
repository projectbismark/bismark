#include "Datagram.h"

#include "TrException.h"

#include <stdlib.h>
#include <string.h>

/**
 * Create a new datagram.
 */
Datagram::Datagram () {
  headers = new Header*[8];
  nbr_headers = 0;
  data = NULL;
  data_length = 0;
}

/**
 * Delete <i>this</i> datagram.
 */
Datagram::~Datagram () {
	//printf("delete datagram %d\n", nbr_headers);
  for (int i = 0; i < nbr_headers; i++) {
  	IP4Header* ip;
  	ICMPHeader* icmp;
  	UDPHeader* udp;
  	TCPHeader* tcp;
  	MPLSHeader* mpls;
  	
  	switch (headers[i]->getHeaderType()) {
  		case Header::IP4:
  			ip = (IP4Header*)headers[i];
  			delete ip;
  			break;
  		case Header::ICMP:
  			icmp = (ICMPHeader*)headers[i];
  			delete icmp;
  			break;
  		case Header::UDP:
  			udp = (UDPHeader*)headers[i];
  			delete udp;
  			break;
  		case Header::TCP:
  			tcp = (TCPHeader*)headers[i];
  			delete tcp;
  			break;
  		case Header::MPLS:
  			mpls = (MPLSHeader*)headers[i];
  			delete mpls;
  			break;
  		default:
  			throw TrException(str_log(DUMP, "Unknown header type"));
  			break;
  	}
  }
  
  // 16 nov 2006 23h00 #&!@ memory leak 
  delete[] headers;
  
  if (data != NULL) delete[] data;
}

/**
 * Append an header at the end of this datagram.
 * At most, 8 headers can be appended to a datagram.
 *
 * @param h The header to append
 */
void
Datagram::addHeader (Header* h) {
  if (nbr_headers >= 8)
    throw TrException(str_log(DUMP, "Datagram : Too many headers (8)"));
  headers[nbr_headers++] = h;
}

void
Datagram::rmHeaders () {
	nbr_headers = 0;
}

/**
 * Return the number of headers
 */
int
Datagram::getNbrHeaders () {
  return nbr_headers;
}

/**
 * Return the <i>index<sup>e</sup></i> header of this datagram.
 */
Header*
Datagram::getHeader (int index) {
  return headers[index];
}

/**
 * Set the data part of the datagram.
 *
 * @param data Array which hold the data.
 * @param length Length of the array <i>data</i>.
 */
void
Datagram::setData (const uint8* data, int length) {
  if (this->data != NULL) delete[] this->data;
  this->data = new uint8[length];
  memcpy(this->data, data, length);
  data_length = length;
}

//uint8*
//Datagram::getData () {
//	return data;
//}

/**
 * Copy data part of the datagram at offset <i>offset</i> in the array
 * <i>data</i>.
 *
 * @param datagram The destination array.
 * @param length The length of the destination array (in bytes).
 * @param offset The offset in the array where data has to be copied.
 */
void
Datagram::packData (uint8* datagram, int length, int offset) {
  // Check if the datagram is long enough to hold data
  if (offset + data_length > length)
    throw TrException(str_log(ERROR, "Not enough space in datagram array"));

  // Copy data
  memcpy(datagram + offset, data, data_length);
}

