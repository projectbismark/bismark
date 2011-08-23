#ifndef __TIME_H__
#define __TIME_H__

#include <sys/time.h>

class Time {
	private:
		struct timeval init_time;

	public:
		Time ();
		long getCurrentTime ();
		long getCurrentSeconds ();
		long getNormalizedTime (struct timeval *tv);
};

#endif // __TIME_H__

