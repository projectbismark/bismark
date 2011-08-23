#include "Header.h"

#include "TrException.h"
#include "Util.h"
#include "common.h"

/**
 * Create a new ICMP Echo header (Echo request or echo reply).
 * @param request <i>True</i> for an <i>Echo Request</i> and 
 *		<i>false</i> for an <i>Echo Reply</i>
 *
 * All fields, except <i>type</i>, are initialized to zero.
 */
ICMPEcho::ICMPEcho (bool request) : ICMPHeader() {
  if (request) setType(8);
  else setType(0);
}

/**
 * Create a new ICMP Echo header and initialize it with 16 bytes of <i>data</i>
 * array beginning at offset <i>offset</i>.
 *
 * This constructor doesn't check the validity of the code field in the data.
 * The static method "ICMP::create()" allow you to create the correct ICMP
 * message from a data array.
 */
ICMPEcho::ICMPEcho (const uint8* data, int length, int offset) :
			 ICMPHeader(data, length, offset) {
}

/**
 * Delete <i>this</i> ICMP Echo message.
 */
ICMPEcho::~ICMPEcho () {
  delete[] header;
}

/**
 * Set the <i>identifier</i> field (bytes 4-5)
 */
void
ICMPEcho::setIdentifier (uint16 id) {
  Util::writebe16(header, 4, id);
}

/**
 * Return the <i>identifier</i> field (bytes 4-5)
 */
uint16
ICMPEcho::getIdentifier () {
  return Util::readbe16(header, 4);
}

/**
 * Set the <i>sequence</i> field (bytes 6-7)
 */
void
ICMPEcho::setSequence (uint16 id) {
  Util::writebe16(header, 6, id);
}

/**
 * Return the <i>sequence</i> field (bytes 6-7)
 */
uint16
ICMPEcho::getSequence () {
  return Util::readbe16(header, 6);
}

#define NA "N/A"
/**
 * Get the description of the <i>code</i> field (byte 1).
 *
 * Return "N/A" string because there's no code defined for Echo messages.
 */
const char*
ICMPEcho::getCodeDesc () {
  return NA;
}

/**
 * Return the header length.
 */
int
ICMPEcho::getHeaderLength () {
  return 16;
}

/**
 * Debug
 */
void
ICMPEcho::dump () {
  log(DUMP, "ICMP Echo header :\n");
  log(DUMP, "type                = %s\n", getTypeDesc());
  log(DUMP, "code                = %s\n", getCodeDesc());
  log(DUMP, "checksum            = %d\n", getChecksum());
  log(DUMP, "identifier          = %d\n", getIdentifier());
  log(DUMP, "sequence            = %d\n", getSequence());
}

