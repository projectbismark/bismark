#ifndef __HEADER_H__
#define __HEADER_H__

#include "common.h"

/**
 * Generic container which represents a datagram header.
 */
class Header {
	public:
		enum type { IP4, UDP, TCP, ICMP, MPLS };
		//Header ();
		//~Header ();
		/// Return the type of the header (IP4, UDP, TCP or ICMP)
		virtual int	getHeaderType () = 0;
		/// Return the length of the header
		virtual int	getHeaderLength () = 0;
		/// Copy the header at offset <i>offset</i> into the array
		/// <i>data</i> of length <i>length</i>.
		virtual void	pack (uint8* data, int length, int offset) = 0;
		/// Debug
		virtual void	dump () = 0;
		/// Debug
		virtual void	dumpRaw () = 0;
};

/**
 * IP4 header.
 * Cfr. RFC 791
 */
class IP4Header : public Header {
	private:
		uint8*	header;
		int	header_len;

	public:
		IP4Header ();
		IP4Header (const uint8* data, int length, int offset);
		~IP4Header ();
		void	setToS (uint8 tos);
		uint8	getToS ();
		void	setTotalLength (uint16 length);
		uint16	getTotalLength ();
		void  setIPId (uint16 id);
		uint16  getIPId ();
		void	setTTL (uint8 ttl);
		uint8	getTTL ();
		void	setProtocol (uint8 protocol);
		void	setProtocol (const char* protocol_name);
		uint8	getProtocol ();
		void	setChecksum (uint16 chk);
		void	computeAndSetChecksum ();
		uint16	getChecksum ();
		void	setSourceAddress (const char* address);
		uint32	getSourceAddress ();
		void	setDestAddress (uint32 address/*const char* address*/);
		uint32	getDestAddress ();
		int	getHeaderType ();
		int	getHeaderLength ();
		void	pack (uint8* data, int length, int offset);
		void	packPseudo (uint16 dgram_len,
				uint8* data, int length, int offset);
		void	dump ();
		void	dumpRaw ();
};

/**
 * TCP header.
 * Cfr. RFC 793
 */
class TCPHeader : public Header {
	private:
		uint8*	header;
		int	header_len;

	public:
		TCPHeader ();
		TCPHeader (const uint8* data, int length, int offset);
		~TCPHeader ();
		void	setSourcePort (uint16 port);
		uint16	getSourcePort ();
		void	setDestPort (uint16 port);
		uint16	getDestPort ();
		void	setSeqNumber (uint32 seq);
		uint32	getSeqNumber ();
		void	setAckNumber (uint32 ack);
		uint32	getAckNumber ();
		void	setURGFlag (bool flag);
		bool	getURGFlag ();
		void	setACKFlag (bool flag);
		bool	getACKFlag ();
		void	setPSHFlag (bool flag);
		bool	getPSHFlag ();
		void	setRSTFlag (bool flag);
		bool	getRSTFlag ();
		void	setSYNFlag (bool flag);
		bool	getSYNFlag ();
		void	setFINFlag (bool flag);
		bool	getFINFlag ();
		void	setWindow (uint16 win);
		uint16	getWindow ();
		void	setChecksum (uint16 sum);
		uint16	getChecksum ();
		void	setUrgentPointer (uint16 ptr);
		uint16	getUrgentPointer ();
		int	getHeaderType ();
		int	getHeaderLength ();
		void	pack (uint8* data, int length, int offset);
		void	dump ();
		void	dumpRaw ();
};

/**
 * UDP header.
 * Cfr. RFC 768
 */
class UDPHeader : public Header {
	private:
		uint8*	header;
		int	header_len;

	public:
		UDPHeader ();
		UDPHeader (const uint8* data, int length, int offset);
		~UDPHeader ();
		void	setSourcePort (uint16 port);
		uint16	getSourcePort ();
		void	setDestPort (uint16 port);
		uint16	getDestPort ();
		void	setDatagramLength (uint16 length);
		uint16	getDatagramLength ();
		void	setChecksum (uint16 checksum);
		uint16	getChecksum ();
		int	getHeaderType ();
		int	getHeaderLength ();
		void	pack (uint8* data, int length, int offset);
		void	dump ();
		void	dumpRaw ();
};

/**
 * ICMP header.
 * Cfr. RFC 792
 */
class ICMPHeader : public Header {
	private:
		static const char*	type_desc[];
		static const char*	code_desc_unreachable[];
		static const char*	code_desc_exceeded[];
		uint8*			header;
		int			header_len;

	public:
		ICMPHeader ();
		ICMPHeader (const uint8* data, int length, int offset);
		~ICMPHeader ();
		void			setType (uint8 type);
		uint8			getType ();
		const char*		getTypeDesc ();
		void			setCode (uint8 code);
		uint8			getCode ();
		const char*		getCodeDesc ();
		void			setChecksum (uint16 checksum);
		uint16			getChecksum ();
		void			setIdentifier (uint16 id);
		uint16			getIdentifier ();
		void			setSequence (uint16 seq);
		uint16			getSequence ();
		int			getHeaderType ();
		int			getHeaderLength ();
		void			pack (uint8* data, int len, int offs);
		void			dump ();
		void			dumpRaw ();
};

/**
 * ICMP MPLS Extention header.
 * draft-ietf-mpls-icmp-02.txt (obsolete but still used by LSRs)
 */
class MPLSHeader : public Header {
	private:
		uint8*			header;
		int					header_len;
		uint32*			labels;
		int					nbrLabels;
    // XXX handle multiple TTLs (if there is more than one label in the stack)
    uint8         ttl;

	public:
		MPLSHeader(const uint8* data, int length, int offset);
		~MPLSHeader ();
		uint32*			getLabelStack();
		int					getNbrLabels();
		uint8				getExp();
		bool				getStackBit();
		uint8				getTTL();
    static int  compareStacks(uint32* stack1, int size1, uint32* stack2, int size2);
		int					getHeaderType ();
		int					getHeaderLength ();
		void				pack (uint8* data, int len, int offs);
		void				dump ();
		void				dumpRaw ();
};

/**
 * Class which represent a <i>"Destination Unreachable"</i> ICMP header.
 * Cfr. RFC 792
 */
/*class ICMPDestUnreachable : public ICMPHeader {
	private:
		IP4Header*		ip4_err;
		uint8*			data_err;
		static const char*	code_desc[];

	public:
		ICMPDestUnreachable (const uint8* data, int length, int offset);
		virtual ~ICMPDestUnreachable ();
		const char*	getCodeDesc ();
		const IP4Header*getErroneousIP4Header ();
		void		getErroneousData (uint8** data, int* length);
		int		getHeaderLength ();
		void		dump ();
};*/

/**
 * Class which represent a <i>"Time Exceeded"</i> ICMP header.
 * Cfr. RFC 792
 */
/*class ICMPTimeExceeded : public ICMPHeader {
	private:
		IP4Header*		ip4_err;
		uint8*			data_err;
		static const char*	code_desc[];

	public:
		ICMPTimeExceeded (const uint8* data, int length, int offset);
		virtual ~ICMPTimeExceeded ();
		const char*	getCodeDesc ();
		const IP4Header*getErroneousIP4Header ();
		void		getErroneousData (uint8** data, int* length);
		int		getHeaderLength ();
		void		dump ();
};*/

/**
 * Class which represent a <i>"Echo request"</i> or <i>"Echo reply"</i>
 * ICMP header.
 * Cfr. RFC 792
 */
/*class ICMPEcho : public ICMPHeader {
	public:
		ICMPEcho (bool request);
		ICMPEcho (const uint8* data, int length, int offset);
		virtual ~ICMPEcho ();
		void		setIdentifier (uint16 id);
		uint16		getIdentifier ();
		void		setSequence (uint16 seq);
		uint16		getSequence ();
		const char*	getCodeDesc ();
		int		getHeaderLength ();
		void		dump ();
};*/

#endif // __HEADER_H__

