#include "Header.h"

#include "TrException.h"
#include "Util.h"
#include "common.h"

/**
 * Create a new ICMP Time Exceeded header and initialize it from the <i>data</i>
 * array beginning at offset <i>offset</i>.
 */
ICMPTimeExceeded::ICMPTimeExceeded (const uint8* data, int length, int offset) 
		: ICMPHeader(data, length, offset) {
  ip4_err = new IP4Header(data, length, offset + 8);
  data_err = new uint8[8];
  memcpy(data_err, data + offset + 28, 8);
}

/**
 * Delete <i>this</i> header.
 */
ICMPTimeExceeded::~ICMPTimeExceeded () {
  delete[] header;
  delete ip4_err;
  delete[] data_err;
}

#define UNKNOW_CODE "Unknow code"
// List of code description
const char*
ICMPTimeExceeded::code_desc[] = {
  "Time to live exceeded in transit",	// 0
  "Fragment reassembly time exceeded"	// 1
};

/**
 * Return a description of the <i>code</i> field.
 */
const char*
ICMPTimeExceeded::getCodeDesc () {
  if (getCode() == 0 || getCode() == 1) return code_desc[getCode()];
  return UNKNOW_CODE;
}

/**
 * Return the erroneous IP4 header which has caused this ICMP message.
 *
 * The IP4 header returned is part of this instance and shouldn't be modified
 * nor freed.
 */
const IP4Header*
ICMPTimeExceeded::getErroneousIP4Header () {
  return ip4_err;
}

/**
 * Return the 8 first bytes of data from the erroneous datagram which caused
 * this ICMP message.
 *
 * The data field returned is part of this instance and shouldn't be modifier
 * nor freed.
 */
void
ICMPTimeExceeded::getErroneousData (uint8** data, int* length) {
  *length = 8;
  *data   = data_err;
}

/**
 * Return the length of the ICMP header (always 8).
 */
int
ICMPTimeExceeded::getHeaderLength () {
  return 8;
}

/**
 * Debug.
 */
void
ICMPTimeExceeded::dump () {
  log(DUMP, "ICMP Time Exceeded Header :\n");
  log(DUMP, "type                = %s\n", getTypeDesc());
  log(DUMP, "code                = %s\n", getCodeDesc());
  log(DUMP, "checksum            = %d\n", getChecksum());
  log(DUMP, "bytes 4-7           = 0x%x\n", *(uint32*)(header+4));
  log(DUMP, "Erroneous IP4 header :\n");
  ip4_err->dump();
  log(DUMP, "Erroneous data :\n");
  dumpRawData(DUMP, data_err, 8);
}

