#ifndef __BW_WATCH__
#define __BW_WATCH__

#include <pthread.h>
#include "Options.h"

class Bandwidth {
	private:
		pthread_cond_t cond_wait;
		pthread_mutex_t lock;
		pthread_t thread;
		int sent;
		int recv;
		int max;
		int interval;
		int display_counter;
		int display_sent;
		int display_recv;
		
	public:
		Bandwidth(Options* opts);
		virtual ~Bandwidth();
		void wait();
		void startThread();
		void runThread();
		void newResponse();
};

#endif
