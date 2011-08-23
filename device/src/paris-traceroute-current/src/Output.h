#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "Tracert.h"
#include "Options.h"

class Output {
	public:
		static void text (FILE* out, Tracert* results, Options* opts);
		static void raw (FILE* out, Tracert* results, Options* opts);
};

#endif // __OUTPUT_H__

