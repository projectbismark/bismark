#include <unistd.h>

#include "Bandwidth.h"

#include "TrException.h"
#include "common.h"

Bandwidth::Bandwidth(Options* opts) {
	if (pthread_mutex_init(&lock, NULL) != 0)
		throw TrException(str_log(ERROR, "Create a mutex"));
		
	if (pthread_cond_init(&cond_wait, NULL) != 0)
		throw TrException(str_log(ERROR, "Create a thread condition"));
		
	max = opts->bandwidth;
	sent = 0;
	recv = 0;
	display_sent = 0;
	display_recv = 0;
	
	interval = 1;
	//if (opts->bandwidth == 0)
	display_counter = 0;
}

Bandwidth::~Bandwidth () {
	
}

void
Bandwidth::wait() {
	if (max == 0) {
		sent++;
		display_sent++;
		return;
	}
	pthread_mutex_lock(&lock);
	
	//printf("sent = %d\n", sent);
	while (sent >= max) {
		//printf("je dors\n");
		pthread_cond_wait(&cond_wait, &lock);
		//printf("je suis reveille\n");
	}
	
	display_sent++;
	sent++;
		
	//fprintf(stderr, "[2]\n");	
	pthread_mutex_unlock(&lock);
	//fprintf(stderr, "[2] unlocked\n");	
}

void
Bandwidth::newResponse() {
	pthread_mutex_lock(&lock);
	recv++;
	display_recv++;
	//fprintf(stderr, "[3]\n");
	pthread_mutex_unlock(&lock);
}

/**
 * C callback function used to start the Server thread
 */
void*
run_thread2 (void* arg) {
  Bandwidth* bw = (Bandwidth*)arg;
  bw->runThread();
  return NULL;
}

void
Bandwidth::startThread () {
  // Create and execute the listening thread
  //stop_thread = false;
  if (pthread_create(&thread, NULL, run_thread2, this) != 0)
  	throw TrException(str_log(ERROR, "Create a thread"));
}

void
Bandwidth::runThread() {
	while (1) {
		pthread_mutex_lock(&lock);
		
		if (++display_counter >= 60) {
			fprintf(stdout, "# Bandwidth, sent = %d pkt/s, recv = %d pkt/s\n", 
					display_sent/display_counter, display_recv/display_counter);
			display_counter = 0;
			display_sent = 0;
			display_recv = 0;
		}
		
		sent = 0;
		recv = 0;
		
		pthread_cond_broadcast(&cond_wait);
		
		//fprintf(stderr, "[1]\n");
		pthread_mutex_unlock(&lock);
		
		sleep(interval);
	}
}
