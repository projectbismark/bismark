#include "Header.h"

#include "TrException.h"
#include "Util.h"

/**
 * Create a new TCP header.
 */
TCPHeader::TCPHeader () {
  header = new uint8[20];
  memset(header, 0, 20);
  header_len = 20;
  header[12] = 0x50; // Number of 32-bit word in this header
}

/**
 * Create a new TCP header and initialise it with 20 bytes of <i>data</i> array
 * beginning at offset <i>offset</i>.
 */
TCPHeader::TCPHeader (const uint8* data, int length, int offset) {
  header = new uint8[20];
  header_len = 20;
  memcpy(header, data + offset, 20);
}

/**
 * Delete <i>this</i> TCP header.
 */
TCPHeader::~TCPHeader () {
  delete[] header;
}

/**
 * Set the 'Source port' field (bytes 0-1).
 */
void
TCPHeader::setSourcePort (uint16 port) {
  Util::writebe16(header, 0, port);
}

/**
 * Get the 'Source port' field (bytes 0-1).
 */
uint16
TCPHeader::getSourcePort () {
  return Util::readbe16(header, 0);
}

/**
 * Set the 'Destination port' field (bytes 2-3).
 */
void
TCPHeader::setDestPort (uint16 port) {
  Util::writebe16(header, 2, port);
}

/**
 * Get the 'Destination port' field (bytes 2-3).
 */
uint16
TCPHeader::getDestPort () {
  return Util::readbe16(header, 2);
}

/**
 * Set the <i>sequence number</i> field (bytes 4-7).
 */
void
TCPHeader::setSeqNumber (uint32 seq) {
  Util::writebe32(header, 4, seq);
}

/**
 * Return the <i>sequence number</i> field (bytes 4-7).
 */
uint32
TCPHeader::getSeqNumber () {
  return Util::readbe32(header, 4);
}

/**
 * Set the <i>ack</i> field (bytes 8-11).
 */
void
TCPHeader::setAckNumber (uint32 ack) {
  Util::writebe32(header, 8, ack);
}

/**
 * Return the <i>ack</i> field (bytes 8-11).
 */
uint32
TCPHeader::getAckNumber () {
  return Util::readbe32(header, 8);
}

/**
 * Set the <i>URG</i> flag (byte 13, bit 5).
 */
void
TCPHeader::setURGFlag (bool flag) {
  if (flag) header[13] |= 0x20;
  else header[13] &= 0xdf;
}

/**
 * Return the <i>URG</i> flag (byte 13, bit 5).
 */
bool
TCPHeader::getURGFlag () {
  return (header[13] & 0x20);
}

/**
 * Set the <i>ACK</i> flag (byte 13, bit 4).
 */
void
TCPHeader::setACKFlag (bool flag) {
  if (flag) header[13] |= 0x10;
  else header[13] &= 0xef;
}

/**
 * Return the <i>ACK</i> flag (byte 13, bit 4).
 */
bool
TCPHeader::getACKFlag () {
  return (header[13] & 0x10);
}

/**
 * Set the <i>PSH</i> flag (byte 13, bit 3).
 */
void
TCPHeader::setPSHFlag (bool flag) {
  if (flag) header[13] |= 0x08;
  else header[13] &= 0xf7;
}

/**
 * Return the <i>PSH</i> flag (byte 13, bit 3).
 */
bool
TCPHeader::getPSHFlag () {
  return (header[13] & 0x08);
}

/**
 * Set the <i>RST</i> flag (byte 13, bit 2).
 */
void
TCPHeader::setRSTFlag (bool flag) {
  if (flag) header[13] |= 0x04;
  else header[13] &= 0xfb;
}

/**
 * Return the <i>RST</i> flag (byte 13, bit 2).
 */
bool
TCPHeader::getRSTFlag () {
  return (header[13] & 0x04);
}

/**
 * Set the <i>SYN</i> flag (byte 13, bit 1).
 */
void
TCPHeader::setSYNFlag (bool flag) {
  if (flag) header[13] |= 0x02;
  else header[13] &= 0xfd;
}

/**
 * Return the <i>SYN</i> flag (byte 13, bit 1).
 */
bool
TCPHeader::getSYNFlag () {
  return (header[13] & 0x02);
}

/**
 * Set the <i>FIN</i> flag (byte 13, bit 0).
 */
void
TCPHeader::setFINFlag (bool flag) {
  if (flag) header[13] |= 0x01;
  else header[13] &= 0xfe;
}

/**
 * Return the <i>FIN</i> flag (byte 13, bit 0).
 */
bool
TCPHeader::getFINFlag () {
  return (header[13] & 0x01);
}

/**
 * Set the <i>window</i> field (bytes 14-15).
 */
void
TCPHeader::setWindow (uint16 win) {
  Util::writebe16(header, 14, win);
}

/**
 * Return the <i>window</i> field (bytes 14-15).
 */
uint16
TCPHeader::getWindow () {
  return Util::readbe16(header, 14);
}

/**
 * Set the <i>checksum</i> field (bytes 16-17).
 */
void
TCPHeader::setChecksum (uint16 sum) {
  Util::write16(header, 16, sum);
}

/**
 * Return the <i>checksum</i> field (bytes 16-17).
 */
uint16
TCPHeader::getChecksum () {
  return Util::read16(header, 16);
}

/**
 * Set the <i>Urgent Pointer</i> field (bytes 18-19).
 */
void
TCPHeader::setUrgentPointer (uint16 ptr) {
  Util::writebe16(header, 18, ptr);
}

/**
 * Return the <i>Urgent Pointer</i> field (bytes 18-19).
 */
uint16
TCPHeader::getUrgentPointer () {
  return Util::readbe16(header, 18);
}

/**
 * Return the header type : Header::TCP
 */
int
TCPHeader::getHeaderType () {
  return TCP;
}

/**
 * Return the header length (always 20).
 */
int
TCPHeader::getHeaderLength () {
  return 20;
}

/**
 * Copy this TCP header at offset <i>offset</i> in the array <i>data</i>.
 *
 * @param data The destination array
 * @param length The length of the destination array (in bytes).
 * @param offset The offset where the header has to be copied
 *
 * @throw TrException There isn't enough place in the array <i>data</i> to hold
 *              the header
 */
void
TCPHeader::pack (uint8* data, int length, int offset) {
  uint8* ptr = data + offset;

  // Check if the data structure can contain the TCP header
  if (offset + 20 > length)
    throw TrException(str_log(ERROR, "Not enough space in data array"));

  // Copy the header
  memcpy(ptr, header, 20);
}

/**
 * Debug
 */
void
TCPHeader::dump () {
  log(DUMP, "TCP header :");
  log(DUMP, "source_port        = %d", getSourcePort());
  log(DUMP, "dest_port          = %d", getDestPort());
  log(DUMP, "sequence_number    = %d", getSeqNumber());
  log(DUMP, "ack_number         = %d", getAckNumber());
  log(DUMP, "flags              = 0x%x", header[13]);
  log(DUMP, "fin_flag(1)        = %s", getFINFlag() ? "true" : "false");
  log(DUMP, "syn_flag(2)        = %s", getSYNFlag() ? "true" : "false");
  log(DUMP, "rst_flag(4)        = %s", getRSTFlag() ? "true" : "false");
  log(DUMP, "psh_flag(8)        = %s", getPSHFlag() ? "true" : "false");
  log(DUMP, "ack_flag(16)       = %s", getACKFlag() ? "true" : "false");
  log(DUMP, "urg_flag(32)       = %s", getURGFlag() ? "true" : "false");
  log(DUMP, "windown            = %d", getWindow());
  log(DUMP, "checksum           = %d", getChecksum());
  log(DUMP, "urgent_pointer     = %d", getUrgentPointer());
}

/**
 * Debug
 */
void
TCPHeader::dumpRaw () {
  log(DUMP, "TCP header :");
  dumpRawData(DUMP, header, header_len);
}

