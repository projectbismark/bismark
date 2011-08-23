#include "Server.h"
#include "Options.h"
#include "Bandwidth.h"

#define NULL_TRACERT		0
#define TEST_TRACERT		1
#define HOPBYHOP_TRACERT	2
#define PACKBYPACK_TRACERT	3
#define CONCURRENT_TRACERT	4
#define SCOUT_TRACERT		5
#define EXHAUSTIVE_TRACERT		6
#define MT_TRACERT	7
#define EXHAUSTIVE_OLD_TRACERT		8

class MtTracert {
	private:
	int id;
	FILE* targets;
	pthread_mutex_t* targets_lock;
	pthread_mutex_t* output_lock;
	//Tracert* t;
	Server* server;
	Options * opts;
	Bandwidth* bw;
	int addr_count;
	pthread_t	thread;
	bool terminated;
	public:
	MtTracert (Options* opts, int id, Server* icmp_server, FILE* targets, pthread_mutex_t* targets_lock, pthread_mutex_t* output_lock, Bandwidth* bw);
	virtual ~MtTracert ();
	void trace(char *dest_addr, int id_initial, int id_max, bool per_dest);
	int stats ();
	void runThread   ();
	void startThread ();
	bool wait(bool block);
};
