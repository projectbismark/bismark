#include "Header.h"

#include "TrException.h"
#include "Util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

MPLSHeader::MPLSHeader(const uint8* data, int length, int offset) {
  int i;
  uint16 obj_len;
  uint16 obj_end;
  int nbr_entries;
  uint32 label;

  log(INFO, "MPLSHeader %d %d", length, offset);
  
  header = new uint8[length];
  header_len = length;

  memcpy(header, data+offset, length);

  labels = NULL;
  nbrLabels = 0;

  if (header[0]>>4 != 2) {
    nbrLabels = 0;
    log(WARN, "MPLS version %d", header[0]>>4);
  } else {
    i = 4;

    while (i + 4 <= length) {
      obj_len = Util::readbe16(header, i);
      if (obj_len < 4)
        break;
      // We are only interested in MPLS Stack entries
      if (header[i+2] == 1 && header[i+3] == 1) {
        nbr_entries = (obj_len - 4)>>2;

        labels = new uint32[nbr_entries+1];

        nbrLabels = 0;

        obj_end = i + obj_len;
        i+=4;

        while (i + 4 <= obj_end) {
          label = header[i]<<12;
          label |= header[i+1]<<4;
          label |= header[i+2]>>4;

          labels[nbrLabels++] = label;
          
          ttl = header[i+3];
          
          i+=4;
        }
      }
      i += obj_len;
    }
  }
  
  log(INFO, "MPLSHeader fin");
}

MPLSHeader::~MPLSHeader () {
	//printf("delete MPLS header\n");
	delete[] header;
}

int
MPLSHeader::getNbrLabels(){
  return nbrLabels;
}

uint32*
MPLSHeader::getLabelStack() {
   return labels;
}

uint8
MPLSHeader::getExp() {
   return 0;
}

bool
MPLSHeader::getStackBit() {
   return true;
}

uint8
MPLSHeader::getTTL() {
   return ttl;
}

/*
Compares 2 MPLS stacks
XXX should we put this function in another file ?
*/
int
MPLSHeader::compareStacks(uint32* stack1, int size1, uint32* stack2, int size2)
{
  // xxx stack1 et stack2 peuvent etre NULL!
  //if (stack2 == NULL)
  //  return (stack1 == NULL)?0:-1;
  
  // XXX pas correct !
  if (stack1 == NULL || stack2 == NULL)
  {
    return 0;
  }
  
  if (stack1 == NULL)
  {
    printf("stack1 est null\n");
    if (stack2 != NULL)
      printf("%d\n", stack2[0]);
  }

  if (stack2 == NULL)
  {
    printf("stack2 est null\n");
    if (stack1 != NULL)
      printf("%d\n", stack1[0]);
  }

  for (int i = 0; i < size1; i++)
    if (stack1[i] != stack2[i])
      return -1;

  return 0;
}

/**
 * Return the header type : Header::MPLS
 */
int
MPLSHeader::getHeaderType () {
  return MPLS;
}

/**
 * Return the header length
 */
int
MPLSHeader::getHeaderLength () {
  return 0;
}


/**
 */
void
MPLSHeader::pack (uint8* data, int length, int offset) {
  /*uint8* ptr = data + offset;

  // Check if the data structure can contain the ICMP header
  if (offset + getHeaderLength() > length)
    throw TrException("Not enough space in data array");

  // Copy the header
  memcpy(ptr, header, getHeaderLength());*/
  // xxx test
}


/**
 * Debug.
 */
void
MPLSHeader::dump () {
  log(DUMP, "MPLS Header");
  // xxx
}

/**
 * Debug.
 */
void
MPLSHeader::dumpRaw () {
  log(DUMP, "MPLS Header :\n");
  dumpRawData(DUMP, header, header_len);
  // xxx
}
