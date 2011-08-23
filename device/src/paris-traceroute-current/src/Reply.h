#ifndef __REPLY_H__
#define __REPLY_H__

#include "common.h"
#include "Datagram.h"

/**
 * Abstract class which defines the format of a reply.
 */
class Reply : public Datagram {
  public:
    // XXX temp : proc_id for udp not impl yet
    // return this fake value to make
    // the caller (notifyReply)  happy
    int proc_id;
    
    /// Type of a reply
    enum reply_type {
      DESTINATION_REACHED,
      TIME_EXPIRED,
      HOST_UNREACHABLE,
      NETWORK_UNREACHABLE,
      PROTOCOL_UNREACHABLE,
      OTHER_UNREACHABLE,
      SOURCE_QUENCH,
      COMM_PROHIBITED,
      UNKNOW
    };

		static Reply* replyFactory(const uint8* packet, int packet_len);
		uint32  getSourceAddress ();
		uint8   getTTL ();
		int     getIPId ();
    bool    IPOptions();
    virtual int  getOriginalProtocol () = 0;
		virtual int  getOriginalTTL () = 0;
    virtual int  getProcId () = 0;
		virtual int   getID () = 0;
		virtual int  	getID2 () = 0;
		virtual int		getID3 () = 0;
		virtual int		getReturnFlowId () = 0;
		virtual uint32		getReservedWords () = 0;
		virtual int   getType () = 0;
		virtual bool  resetRequired () = 0;
		virtual int   getResetID () = 0;
		virtual uint32* getMPLSLabelStack() = 0;
		virtual int getMPLSNbrLabels() = 0;
    virtual uint8 getMPLSTTL() = 0;
    virtual uint32  getOriginalDestAddress () = 0;
		void    dump ();
    void    dumpRaw ();
};

/**
 * This class hold an ICMP message.
 * Three types of Reply are usefull:
 * <ul>
 *   <li>Time Exceeded reply : we found an intermediary router</li>
 *   <li>Port Unreachable : we found the destination (UDP Probe)</li>
 *   <li>Echo reply : we found the destination (ICMP Probe)</li>
 * </ul>
 */
class ICMPReply : public Reply {
	public:
		ICMPReply (const uint8* packet, int packet_len);
		~ICMPReply ();
    int   getProcId ();
		int   getID   ();
		int		getID2 ();
		int   getID3 ();
		int		getReturnFlowId ();
		uint32		getReservedWords ();
		int   getType ();
		bool  resetRequired ();
		int   getResetID ();
    int   getOriginalProtocol ();
		int   getOriginalTTL ();
		uint32* getMPLSLabelStack();
		int getMPLSNbrLabels();
    uint8 getMPLSTTL();
    uint32 getOriginalDestAddress ();
};

/**
 * This class hold a TCP message.
 */
class TCPReply : public Reply {
	public:
		TCPReply (const uint8* packet, int packet_len);
		~TCPReply ();
    int   getProcId ();
		int   getID   ();
		int		getID2  ();
		int 	getID3  ();
		int		getReturnFlowId ();
		uint32		getReservedWords ();
		int   getType ();
		bool  resetRequired ();
		int   getResetID ();
		int   getOriginalTTL ();
    int   getOriginalProtocol ();
		uint32* getMPLSLabelStack();
		int getMPLSNbrLabels();
    uint8 getMPLSTTL();
    uint32  getOriginalDestAddress ();
};

#endif // __REPLY_H__

