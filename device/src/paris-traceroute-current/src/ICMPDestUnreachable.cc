#include "Header.h"

#include "TrException.h"
#include "Util.h"
#include "common.h"

/**
 * Create a new ICMP Destination Unreachable header and initialize it from the
 * <i>data</i> array beginning at offset <i>offset</i>.
 */
ICMPDestUnreachable::ICMPDestUnreachable (const uint8* data, int len, int offs)
		: ICMPHeader(data, len, offs) {
  ip4_err = new IP4Header(data, len, offs + 8);
  data_err = new uint8[8];
  memcpy(data_err, data + offs + 28, 8);
}

/**
 * Delete <i>this</i> header.
 */
ICMPDestUnreachable::~ICMPDestUnreachable () {
  delete[] header;
  delete ip4_err;
  delete[] data_err;
}

#define UNKNOW_CODE "Unknow code"
// List of code description
const char*
ICMPDestUnreachable::code_desc[] = {
  "Net unreachable",			// 0
  "Host unreachable",			// 1
  "Protocol unreachable",		// 2
  "Port unreachable",			// 3
  "Fragmentation needed and DF set",	// 4
  "Source route failed"			// 5
};

/**
 * Return a description of the <i>code</i> field.
 */
const char*
ICMPDestUnreachable::getCodeDesc () {
  if (getCode() <= 5) return code_desc[getCode()];
  return UNKNOW_CODE;
}

/**
 * Return the erroneous IP4 header which has caused this ICMP message.
 *
 * The IP4 header returned is part of this instance and shouldn't be modified
 * nor freed.
 */
const IP4Header*
ICMPDestUnreachable::getErroneousIP4Header () {
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
ICMPDestUnreachable::getErroneousData (uint8** data, int* length) {
  *length = 8;
  *data   = data_err;
}

/**
 * Return the length of the ICMP header (always 8).
 */
int
ICMPDestUnreachable::getHeaderLength () {
  return 8;
}

/**
 * Debug.
 */
void
ICMPDestUnreachable::dump () {
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

