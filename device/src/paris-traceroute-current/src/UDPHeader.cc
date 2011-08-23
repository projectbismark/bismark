#include "Header.h"

#include "TrException.h"
#include "Util.h"

#include <stdio.h>
#include <string.h>

/**
 * Create a new UDP header.
 */
UDPHeader::UDPHeader () {
  header = new uint8[8];
  memset(header, 0, 8);
  header_len = 8;
}

/**
 * Create a new IDP header and initialise it with 8 bytes of <i>data</i> array
 * beginning at offset <i>offset</i>.
 */
UDPHeader::UDPHeader (const uint8* data, int length, int offset) {
  // Initialize the header field
  header = new uint8[8];
  header_len = 8;
  memcpy(header, data + offset, 8);
}

/**
 * Delete <i>this</i> UDP header.
 */
UDPHeader::~UDPHeader () {
  delete[] header;
}

/**
 * Set the 'Source port' field (bytes 0-1)
 */
void
UDPHeader::setSourcePort (uint16 port) {
  Util::writebe16(header, 0, port);
}

/**
 * Get the 'Source port' field (bytes 0-1)
 */
uint16
UDPHeader::getSourcePort () {
  return Util::readbe16(header, 0);
}

/**
 * Set the 'Destination port' field (bytes 2-3)
 */
void
UDPHeader::setDestPort (uint16 port) {
  Util::writebe16(header, 2, port);
}

/**
 * Get the 'Destination port' field (bytes 2-3)
 */
uint16
UDPHeader::getDestPort () {
  return Util::readbe16(header, 2);
}

/**
 * Set the total length of the datagram : header UDP + data (bytes 4-5)
 */
void
UDPHeader::setDatagramLength (uint16 length) {
  Util::writebe16(header, 4, length);
}

/**
 * Get the total length of the datagram : header UDP + data (bytes 4-5)
 */
uint16
UDPHeader::getDatagramLength () {
  return Util::readbe16(header, 4);
}

/**
 * Set the checksum (0 -> optional) (bytes 6-7)
 */
void
UDPHeader::setChecksum (uint16 checksum) {
  Util::write16(header, 6, checksum); // TODO
}

/**
 * Get the checksum (bytes 6-7)
 */
uint16
UDPHeader::getChecksum () {
  return Util::read16(header, 6);
}

/**
 * Return the header type : Header::UDP
 */
int
UDPHeader::getHeaderType () {
  return UDP;
}

/**
 * Return the header length in bytes (always 8).
 */
int
UDPHeader::getHeaderLength () {
  return 8;
}

/**
 * Copy this UDP header at offset <i>offset</i> in the array <i>data</i>.
 *
 * @param data The destination array
 * @param length The length of the destination array (in bytes).
 * @param offset The offset where the jeader has to be copied
 *
 * @throw TrException There isn't enough place in the array <i>data</i> to hold
 *		the header
 */
void
UDPHeader::pack (uint8* data, int length, int offset) {
  uint8* ptr = data + offset;

  // Check if the data structure can contain the UDP header
  if (offset + 8 > length)
    throw TrException(str_log(ERROR, "Not enough space in data array"));

  // Copy the header
  memcpy(ptr, header, 8);
}

/**
 * Debug
 */
void
UDPHeader::dump () {
  log(DUMP, "UDP header :");
  log(DUMP, "source_port        = %d", getSourcePort());
  log(DUMP, "dest_port          = %d", getDestPort());
  log(DUMP, "datagram_length    = %d", getDatagramLength());
  log(DUMP, "checksum           = %d", getChecksum());
}

/**
 * Debug
 */
void
UDPHeader::dumpRaw () {
  dumpRawData(WARN, header, header_len);
}

