#ifndef __DATAGRAM_H__
#define __DATAGRAM_H__

#include "common.h"
#include "Header.h"

/**
 * This class implements a datagram.
 * A datagram consist in up to 8 headers and some data.
 *
 * Each header is represented by the instantiation of the class Header.
 * The data is represented by an array.
 */
class Datagram {
	private:
		Header**	headers;
		int		nbr_headers;

	public:
	//protected:
		uint8*		data;
		int		data_length;

	
		Datagram ();
		virtual ~Datagram();
		void		addHeader (Header* h);
		void		rmHeaders ();
		int		getNbrHeaders ();
		Header*		getHeader (int index);
		void		setData (const uint8* data, int length);
		//uint8*   getData ();
		void		packData (uint8* data, int length, int offset);
		virtual void	dump () = 0;
};

#endif // __DATAGRAM_H__
