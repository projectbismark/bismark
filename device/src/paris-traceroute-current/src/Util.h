#ifndef __UTIL_H__
#define __UTIL_H__

#include "common.h"

/**
 * Class which implements some usefull conversion functions.
 */
class Util {
	public:
		static char*  getRoute (const char* dest);
		static uint16 computeChecksum (const uint16* data, int length);
		static uint16 readbe16 (uint8* data, int ofs);
		static uint32 readbe32 (uint8* data, int ofs);
		static uint16 readle16 (uint8* data, int ofs);
		static uint32 readle32 (uint8* data, int ofs);
		static uint16 read16 (uint8* data, int ofs);
		static uint32 read32 (uint8* data, int ofs);
		static void   writebe16 (uint8* data, int ofs, uint16 value);
		static void   writebe32 (uint8* data, int ofs, uint32 value);
		static void   writele16 (uint8* data, int ofs, uint16 value);
		static void   writele32 (uint8* data, int ofs, uint32 value);
		static void   write16 (uint8* data, int ofs, uint16 value);
		static void   write32 (uint8* data, int ofs, uint32 value);
		static int    protocol2int (const char* protocol);
		static char*  my_inet_ntoa(uint32 addr);
		static uint32 my_inet_aton(char *addr);
		static char*	my_gethostbyname(char* host);
		//static char*  getHostName (const char* host_address);
		//static char*  getHostAddress (const char* host_name);
};

#endif // __UTIL_H__

