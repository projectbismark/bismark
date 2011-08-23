#ifndef __PROBE_H__
#define __PROBE_H__

#include "common.h"
#include "TrException.h"
#include "Util.h"
#include "Header.h"
#include "Datagram.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Abstract - Generic form of a probe.
 */
class Probe : public Datagram {
	public:
		static Probe* probeFactory(const char* protocol,
				const char* src_addr, int src_port,
				uint32 /*const char* */dst_addr, int dst_port,
				uint8 ttl, uint8 tos, int data_length,
				uint16 proc_id, uint16 id, int return_flow_id, bool reset);
		Probe () : Datagram() {}
		~Probe ();
		/// Get this probe in a packet form.
		void getDatagram (uint8** data, int* length);
		/// Send this probe
		void send  ();
		/// Return the ID of this probe.
		virtual int  getID () = 0;
		/// Debug
		virtual void dump  () = 0;
		/// Debug
		virtual void dumpRaw () = 0;
};

/**
 * Wrapper for an ICMP probe.
 */
class ICMPProbe : public Probe {
	public:
		ICMPProbe (const char* src_addr, uint32/*const char**/ dst_addr,
			uint8 ttl, uint8 tos, int data_len, int chksum, uint16 proc_id, uint16 id, int return_flow_id);
		~ICMPProbe ();
		int	getID ();
		void	dump  ();
		void	dumpRaw ();
};

/**
 * Wrapper for a UDP probe.
 */
class UDPProbe : public Probe {
	public:
		UDPProbe (const char* src_addr, int src_port,
			uint32/*const char* */ dst_addr, int dst_port,
			uint8 ttl, uint8 tos, int data_len, uint16 proc_id, uint16 id, int return_flow_id);
		~UDPProbe ();
		int 	getID ();
		void	dump  ();
		void	dumpRaw ();
};

/**
 * Wrapper for a TCP probe.
 */
class TCPProbe : public Probe {
	public:
		TCPProbe (const char* src_addr, int src_port,
			uint32/*const char**/ dst_addr, int dst_port,
			uint8 ttl, uint8 tos, int length, 
			uint16 proc_id, uint16 id, bool reset);
		int 	getID ();
		void	dump  ();
		void	dumpRaw ();
};

#endif // __PROBE_H__
