#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#define __GNU_SOURCE

#include "common.h"
#include <unistd.h>
//#include <getopt.h>

enum {FLOW, DEST, ALL};

struct Options {
	char 		targets[32];
	// Probe type
  // to be removed, replaced by int protocol
	char		protocol[5];
  int     protocole;
  
	// Probe parameter
	char*		src_addr;
	char*		dst_addr;
	uint16		src_port;
	uint16		dst_port;
	uint8		ttl_initial;
	uint8		ttl_max;
	uint8		tos;
	int		probe_length;

	// Algorithm parameter
	char		algo[20];
	int 		algo_id;
	long		timeout;
	long		delay_between_probes;
	int		max_try;
	int		max_missing;
	int		id_initial;
  int   proc_id;
  int bandwidth;
  bool raw_output;
  bool mline_output;
  
	// Output result options
	bool		resolve_hostname;
  bool            display_ipid;
  bool            display_ttl;
  bool            debug;
  int threads_count;
  int						prefix_len;
  int						detection_type;
  int							factor;
  int 						return_flow_id;
	Options (int argc, char** argv);
	~Options ();
	void dump ();
	void help ();
	void helpAlgo ();
	void version ();
};

#endif // __OPTIONS_H__

