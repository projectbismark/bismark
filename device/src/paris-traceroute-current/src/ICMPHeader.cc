#include "Header.h"

#include "TrException.h"
#include "Util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Create a new ICMP header.
 *
 * All fields are initialized to 0.
 */
ICMPHeader::ICMPHeader () {
  header = new uint8[8];
  memset(header, 0, 8);
  header_len = 8;
}

/**
 * Create a new ICMP header and initialize it from the <i>data</i> array
 * beginning at offset <i>offset</i>.
 */
ICMPHeader::ICMPHeader (const uint8* data, int length, int offset) {
  // Initialize the header field
  header = new uint8[8];
  header_len = 8;
  memcpy(header, data + offset, 8);
}

ICMPHeader::~ICMPHeader () {
	//printf("delete icmp header\n");
	delete header;
}

/**
 * Set the <i>type</i> field (byte 0).
 */
void
ICMPHeader::setType (uint8 type) {
  header[0] = type;
}

/**
 * Get the <i>type</i> field (byte 0).
 */
uint8
ICMPHeader::getType () {
  return header[0];
}

#define TYPE_UNKNOW "Unknow"
// A desctiption of each type
const char*
ICMPHeader::type_desc[] = {
  "Echo reply",			// 0
  "Unknow",			// 1
  "Unknow",			// 2
  "Destination unreachable",	// 3
  "Source quench",		// 4
  "Redirect",			// 5
  "Unknow",			// 6
  "Unknow",			// 7
  "Echo request",		// 8
  "Router advertisment",	// 9
  "Router sollicitation",	// 10
  "Time exceeded",		// 11
  "Parameter problem",		// 12
  "Timestamp request",		// 13
  "Timestamp reply",		// 14
  "Information request",	// 15
  "Information reply",		// 16
  "Addressmask request",	// 17
  "Addressmask reply"		// 18
};

/**
 * Return a short description of each type.
 *
 * Here is the list of valid type and their description:
 * <ul>
 *   <li>0x00 - Echo reply</li>
 *   <li>0x03 - Destination unreachable</li>
 *   <li>0x04 - Source quench</li>
 *   <li>0x05 - Redirect</li>
 *   <li>0x08 - Echo request</li>
 *   <li>0x09 - Router advertisment</li>
 *   <li>0x0a - Router sollicitation</li>
 *   <li>0x0b - Time exceeded</li>
 *   <li>0x0c - Parameter problem</li>
 *   <li>0x0d - Timestamp request</li>
 *   <li>0x0e - Timestamp reply</li>
 *   <li>0x0f - Information request</li>
 *   <li>0x10 - Information reply</li>
 *   <li>0x11 - Addressmask request</li>
 *   <li>0x12 - Addressmask reply</li>
 * </ul>
 */
const char*
ICMPHeader::getTypeDesc () {
  int type = getType();
  if (type >= 0 && type <= 18) return type_desc[type];
  return TYPE_UNKNOW;
}

/**
 * Set the field <i>code</i> (byte 1).
 */
void
ICMPHeader::setCode (uint8 code) {
  header[1] = code;
}

/**
 * Return the field <i>code</i> (byte 1).
 */
uint8
ICMPHeader::getCode () {
  return header[1];
}

/**
 * Set the <i>checksum</i> field (bytes 3-4).
 */
void
ICMPHeader::setChecksum (uint16 id) {
  Util::write16(header, 2, id);
}

/**
 * Return the <i>checksum</i> field (bytes 3-4).
 */
uint16
ICMPHeader::getChecksum () {
  return Util::read16(header, 2);
}

/**
 * Set the <i>identifier</i> field (bytes 4-5)
 */
void
ICMPHeader::setIdentifier (uint16 id) {
  Util::writebe16(header, 4, id);
}

/**
 * Return the <i>identifier</i> field (bytes 4-5)
 */
uint16
ICMPHeader::getIdentifier () {
  return Util::readbe16(header, 4);
}

/**
 * Set the <i>sequence</i> field (bytes 6-7)
 */
void
ICMPHeader::setSequence (uint16 id) {
  Util::writebe16(header, 6, id);
}

/**
 * Return the <i>sequence</i> field (bytes 6-7)
 */
uint16
ICMPHeader::getSequence () {
  return Util::readbe16(header, 6);
}

#define NA "N/A"

const char*
ICMPHeader::code_desc_unreachable[] = {
	"Net unreachable",
	"Host unreachable",
	"Protocol unreachable",
	"Port unreachable",
	"Fragmentation needed and DF set",
	"Source route failed"
};

const char*
ICMPHeader::code_desc_exceeded[] = {
	"Time to live exceeded int tansit",
	"Fragmentation reassembly tume exceeded"
};

/**
 * Get the description of the <i>code</i> field (byte 1).
 *
 * @todo
 */
const char*
ICMPHeader::getCodeDesc () {
  if (getType() == 0x03) return code_desc_unreachable[getCode()];
  if (getType() == 0x0b) return code_desc_exceeded[getCode()];
  return NA;
}

/**
 * Return the header type : Header::ICMP
 */
int
ICMPHeader::getHeaderType () {
  return ICMP;
}

/**
 * Return the header length (always 8).
 */
int
ICMPHeader::getHeaderLength () {
  return 8;
}

/**
 * Copy this ICMP header at offset <i>offset</i> in the array <i>data</i>.
 *
 * @param data The destination array
 * @param length The length of the destination array
 * @param offset The offset where the header has to be copied
 *
 * @throw TrException There isn't enough place in the array <i>data</i> to hold
 *		the header
 */
void
ICMPHeader::pack (uint8* data, int length, int offset) {
  uint8* ptr = data + offset;

  // Check if the data structure can contain the ICMP header
  if (offset + getHeaderLength() > length)
    throw TrException("Not enough space in data array");

  // Copy the header
  memcpy(ptr, header, getHeaderLength());
}

/**
 * Debug.
 */
void
ICMPHeader::dump () {
  log(DUMP, "ICMP Header :");
  log(DUMP, "type                = %s", getTypeDesc());
  log(DUMP, "code                = %s", getCodeDesc());
  log(DUMP, "checksum            = %d", getChecksum());
  log(DUMP, "identifier          = %d", getIdentifier());
  log(DUMP, "sequence            = %d", getSequence());
}

/**
 * Debug.
 */
void
ICMPHeader::dumpRaw () {
  log(DUMP, "ICMP Header :\n");
  dumpRawData(WARN, header, header_len);
}

