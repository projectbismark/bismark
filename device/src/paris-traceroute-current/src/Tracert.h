#ifndef __TRACERT_H__
#define __TRACERT_H__

#include "common.h"
#include "Options.h"
#include "Probe.h"
#include "Reply.h"
#include "Time.h"
#include "Bandwidth.h"

#include <sys/time.h>
#include <pthread.h>
#include <map>

using namespace std;

struct test {
	public:
		 int entier;
};

struct Interface {
	public:
		uint32								address;
		// 0: no; 1: PF; 2: PP
		uint8 								load_bal;
		float									flow_fract;
		int 									expected_interf_count;
		Interface**						next_hops;
		int 									next_hops_count;
		int 									max_next_hops;
};

struct TimedProbe {
  public:
    Probe*      probe;
    long        send_time;
    long        arrival_time;
    long        timeout_time;
    uint32      dest_port;
    uint32      flow_identifier;
    uint32      xtuple;
    int         reply_type;
    int         reply_ttl;
    int         fabien_ttl;
    // The ID of the returned IP packet
    uint16      ip_id;
    uint32      host_address_raw;
    char*       host_address;
    char*       host_name;
    uint32*     mpls_stack;
    // number of labels in the mpls stack
    int	        nbrLabels;
    uint8       mpls_ttl;
    // XXX
    uint32      destination_address;
    // XXX classif
    // l'interface associee a cette sonde
    Interface*	interf;
    // l'interface du saut precedent, a travers laquelle la sonde est 
    // passee (si per-flow)
    Interface* 	classif_interf;
    uint32			classif_expected_addr;
    long        getRTT () const;
    const char* getHostAddress () const;
    const char* getHostName () const;
};



struct ListProbes {
  public:
    int             ttl;
    TimedProbe**    probes;
};

struct MapProbes {
  public:
    int                   ttl;
    bool 									backward_update;
    int                   nbr_probes;
    int                   nbr_replies;
    int                   nbr_interfaces;
    // used by old exh algo
    bool                  per_flow;
    map<int,TimedProbe*>  probes;
    map<int,Interface*>		interfaces;
};

class Tracert {
  public:
    virtual bool              trace () = 0;
    virtual bool              trace (char* dst_addr, int id, int id_max) = 0;
    // XXX
    virtual void							free () = 0;
    virtual long							duration () = 0;
    virtual TimedProbe*       sendProbe (int id) = 0;
    virtual TimedProbe*       sendProbe2 (int id, int xtuple) = 0;
    virtual	TimedProbe*				sendProbe3 (int id, int xtuple, Interface* interf, uint32 addr) = 0;
    virtual void              reSendProbe(TimedProbe * tprobe) = 0;
    virtual void              waitProbes () = 0;
    virtual void 							setBandwidth(Bandwidth* bw) = 0;
    virtual uint8             getMinTTL () = 0;
    virtual uint8             getMaxTTL () = 0;
    // XXX uint8 -> max 256 interfaces ?
    virtual uint8             getNbrProbes(uint8 ttl) = 0;
    virtual uint8             getNbrReplies(uint8 ttl) = 0;
    virtual uint8             getNbrInterfaces(uint8 ttl) = 0;
    virtual uint8             getLoadBalancingType(uint8 ttl, int nprobe) = 0;
    virtual const TimedProbe* getHopInfo(uint8 ttl, int probe) = 0;
    virtual TimedProbe*       validateReply(Reply *reply, struct timeval *tv) = 0;
    virtual void              updateInfos(TimedProbe* tprobe, Reply *reply) = 0;
    virtual void              wakeup(Reply* reply) = 0;
    virtual void              notifyReply (Reply* reply, struct timeval* tv) = 0;
};

class TracertImpl : public Tracert {
  private:
    
    // used by scout. can be removed and replaced by ttl_current ?
    uint8                     ttl;
    // used by scout, can be replaced by current_tprobe ?
    //TimedProbe*               tprobe;
    // used in notifyReply by hopbyhop and packbypack
    int                       nbr_unreach;
    // used by pack::trace but not in pack:notif -> totally useless !
    bool                      reply_received;
		
  protected:
  	 Time*                     time;
     Options*                  opts;
     Bandwidth*								 bw;
     uint32/*char**/										 target;
     pthread_mutex_t           lock;
     pthread_cond_t            cond_wait;
     map<int,ListProbes*>      probes_by_ttl;
     map<int,TimedProbe*>      probes_by_id;
     // les trois suivants utilises uniq par hopbyhop et concurrent et exh
     // on peut surement simplifier et en utiliser seuleemnt 2
     bool                      all_probes_sent;
     int                       nbr_probes_sent;
     int                       nbr_replies_received;
     // not used by pack but could easily be
     int                       id_current;
     // XXX debug
     int 											 id_initial;
     int 											 id_max;
     // not used by concurrent
     int                       ttl_current;
     // not used by concurrent
     bool                      stop_algo;
     bool											 dest_reached;
  public:
    TracertImpl ();
    TracertImpl (Options* opts);
    ~TracertImpl ();
    bool                      trace ();
    bool                      trace (char* dst_addr, int id, int id_max);
    long											duration ();
    void 											deleteTimedProbe (TimedProbe *tprobe);
    void											free ();
    TimedProbe*               sendProbe (int id);
    TimedProbe*               sendProbe2 (int id, int xtuple);
    TimedProbe*								sendProbe3 (int id, int xtuple, Interface* interf, uint32 addr);
    void                      reSendProbe(TimedProbe * tprobe);
    void                      waitProbes ();
    void 											setBandwidth (Bandwidth* bw);
    uint8                     getMinTTL ();
    uint8                     getMaxTTL ();
    // XXX uint8 -> max 256 interfaces ?
    uint8                     getNbrProbes(uint8 ttl);
    uint8                     getNbrReplies(uint8 ttl);
    uint8                     getNbrInterfaces(uint8 ttl);
    uint8                     getLoadBalancingType(uint8 ttl, int nprobe);
    const TimedProbe*         getHopInfo(uint8 ttl, int probe);
    TimedProbe*               validateReply(Reply *reply, struct timeval *tv);
    void                      updateInfos(TimedProbe* tprobe, Reply *reply);
    void                      wakeup(Reply* reply);
    void                      notifyReply (Reply* reply, struct timeval *tv);
};

class NULLTracert : public TracertImpl {
	public:
    NULLTracert ();
    virtual ~NULLTracert ();
		bool              trace ();
    uint8             getMinTTL ();
    uint8             getMaxTTL ();
    uint8             getNbrProbes(uint8 ttl);
    uint8             getNbrReplies(uint8 ttl);
    uint8             getNbrInterfaces(uint8 ttl);
    //uint8             getLoadBalancingType(uint8 ttl, int nprobe);
    //const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
    void              notifyReply (Reply* reply);
};

class ScoutTracert : public TracertImpl {
	private:
		//Options*	opts;
		//Time*		time;
		//uint8		ttl;
		TimedProbe*	tprobe;
		//pthread_mutex_t	lock;
		//pthread_cond_t	cond_wait;

	public:
		ScoutTracert (Options* opts, uint8 ttl);
		virtual ~ScoutTracert ();
		bool              trace ();
		bool              trace (char* dst_addr, int id, int id_max);
		//uint8             getMinTTL ();
		//uint8             getMaxTTL ();
    //uint8             getNbrProbes(uint8 ttl);
    uint8             getNbrReplies(uint8 ttl);
    //uint8             getNbrInterfaces(uint8 ttl);
    //uint8             getLoadBalancingType(uint8 ttl);
		//const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
		//void              notifyReply (Reply* reply);
};

class HopByHopTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int,ListProbes*>	probes_by_ttl;
		//map<int,TimedProbe*>	probes_by_id;
		//bool			stop_algo;
    //int     nbr_unreach;
    // les trois suivants utilises uniq par hopbyhop et concurrent et exh
    // on peut surement simplifier et en utiliser seuleemnt 2
    //bool			all_probes_sent;
		//int			nbr_probes_sent;
		//int			nbr_replies_received;
		//int			id_current;
		//int			ttl_current;
		//pthread_mutex_t		lock;
		//pthread_cond_t		cond_wait;

	public:
    HopByHopTracert (Options* opts);
    virtual ~HopByHopTracert ();
    bool              trace ();
    bool              trace (char* dst_addr, int id);
    bool              trace (char* dst_addr, int id, int id_max);
    uint8             getNbrReplies(uint8 ttl);
    //const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
    //void              notifyReply (Reply* reply);
};

class PackByPackTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int, ListProbes*>	probes_by_ttl;
		TimedProbe*		current_probe;
		//int			ttl_current;
		//bool			reply_received;
		//bool			stop_algo;
    //int     nbr_unreach;
		//pthread_mutex_t		lock;
		//pthread_cond_t		cond_wait;

	public:
    PackByPackTracert (Options* opts);
    virtual ~PackByPackTracert ();
    bool              trace ();
    bool              trace (char* dst_addr, int id, int id_max);
    uint8             getNbrReplies(uint8 ttl);
};

class ConcurrentTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int, ListProbes*>	probes_by_ttl;
		//map<int, TimedProbe*>	probes_by_id;
		int			ttl_max;
		int			last_resp_ttl;
    //int     nbr_unreach;
    // les trois suivants utilises uniq par hopbyhop et concurrent et exh
    // on peut surement simplifier et en utiliser seuleemnt 2
    //bool			all_probes_sent;
		//int			nbr_probes_sent;
		//int			nbr_replies_received;
		//int                     id_current;
		//pthread_mutex_t         lock;
		//pthread_cond_t          cond_wait;

	public:
		ConcurrentTracert (Options* opts, int max_ttl);
		~ConcurrentTracert ();
		bool              trace ();
		bool              trace (char* dst_addr, int id, int id_max);
		//uint8             getMinTTL ();
		uint8             getMaxTTL ();
    //uint8             getNbrProbes(uint8 ttl);
    uint8             getNbrReplies(uint8 ttl);
    //uint8             getNbrInterfaces(uint8 ttl);
    //uint8             getLoadBalancingType(uint8 ttl);
		//const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
		//void              notifyReply (Reply* reply);
};

class ExhaustiveTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int,MapProbes*>	probes_by_ttl;
		//map<int,TimedProbe*>	probes_by_id;
    MapProbes *current_mprobes;
    MapProbes* mprobes_prev;
		map<int,MapProbes*>      probes_by_ttl2;
		//bool			stop_algo;
    //int     nbr_unreach;
    // les trois suivants utilises uniq par hopbyhop et concurrent et exh
    // on peut surement simplifier et en utiliser seuleemnt 2
    //bool			all_probes_sent;
		//int			nbr_probes_sent;
		//int			nbr_replies_received;
    //bool    classify_balancer;
    //uint32  first_interface;
    //uint32  first_xtuple;
    uint16 	flow_identifier;
		//int			id_current;
		//int			ttl_current;
		//pthread_mutex_t		lock;
		//pthread_cond_t		cond_wait;
		uint32	target_prefix;
		bool		per_dest;
		
    Interface* findInterface(MapProbes *mprobes, uint32 interf);
    int ProbesToSend(int nbr_interfaces);
    Interface* add_interface(MapProbes* mp, uint32 addr);
    void addNextHopInterface(Interface* interf1, Interface*interf2);
    void send_probes_and_wait(MapProbes* mprobes, int count);
    void send_probes_and_wait(MapProbes* mprobes, int count, int constant, Interface* interf, uint32 addr);
	public:
		ExhaustiveTracert (Options* opts, bool per_dest);
		~ExhaustiveTracert ();
		bool              trace ();
		bool              trace (char* dst_addr, int id, int id_max);
		void							free ();
		uint8             getMinTTL ();
		uint8             getMaxTTL ();
    uint8             getNbrProbes(uint8 ttl);
    uint8             getNbrReplies(uint8 ttl);
    uint8             getNbrInterfaces(uint8 ttl);
    uint8             getLoadBalancingType(uint8 ttl, int nprobe);
		const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
		void              notifyReply (Reply* reply, struct timeval *tv);
};


/*class ScoutTracert : public Tracert {
	private:
		Options*		opts;
		Time*			time;
		map<int,ListProbes*>	probes_by_ttl;
		map<int,TimedProbe*>	probes_by_id;
		bool			scout;
		Probe*			scout_probe;
		int			ttl_dest;
		bool			all_probes_sent;
		int			nbr_probes_sent;
		int			nbr_replies_received;
		int			id_current;
		pthread_mutex_t		lock;
		pthread_cond_t		cond_wait;
		bool			traceScout ();
		void			traceHelper ();
		void			notifyScoutReply (Reply* reply);
		void			notifyNormalReply (Reply* reply);

	public:
		ScoutTracert (Options* opts);
		virtual ~ScoutTracert ();
		bool              trace ();
		uint8             getMinTTL ();
		uint8             getMaxTTL ();
		const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
		void              notifyReply (Reply* reply);
};*/

class ExhaustiveOldTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int,MapProbes*>	probes_by_ttl;
		//map<int,TimedProbe*>	probes_by_id;
    MapProbes *current_mprobes;
		map<int,MapProbes*>      probes_by_ttl2;
		//bool			stop_algo;
    //int     nbr_unreach;
    // les trois suivants utilises uniq par hopbyhop et concurrent et exh
    // on peut surement simplifier et en utiliser seuleemnt 2
    //bool			all_probes_sent;
		//int			nbr_probes_sent;
		//int			nbr_replies_received;
    bool    classify_balancer;
    uint32  first_interface;
    uint32  first_xtuple;
    uint32	target_prefix;
    bool		per_dest;
		//int			id_current;
		//int			ttl_current;
		//pthread_mutex_t		lock;
		//pthread_cond_t		cond_wait;
    bool NewInterface(MapProbes *mprobes, uint32 interf);
    int ProbesToSend(int nbr_interfaces);
    
	public:
		ExhaustiveOldTracert (Options* opts, bool per_dest);
		~ExhaustiveOldTracert ();
		bool              trace ();
		bool              trace (char* dst_addr, int id, int id_max);
		void							free ();
		uint8             getMinTTL ();
		uint8             getMaxTTL ();
    uint8             getNbrProbes(uint8 ttl);
    uint8             getNbrReplies(uint8 ttl);
    uint8             getNbrInterfaces(uint8 ttl);
    uint8             getLoadBalancingType(uint8 ttl, int useless);
		const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
		void              notifyReply (Reply* reply, struct timeval *tv);
};

class MihScannerTracert : public TracertImpl {
	private:
		//Options*		opts;
		//Time*			time;
		//map<int,ListProbes*>	probes_by_ttl;
		//map<int,TimedProbe*>	probes_by_id;
		//bool			stop_algo;
    //int     nbr_unreach;
    // les trois suivants utilises uniq par hopbyhop et concurrent et exh
    // on peut surement simplifier et en utiliser seuleemnt 2
    //bool			all_probes_sent;
		//int			nbr_probes_sent;
		//int			nbr_replies_received;
		//int			id_current;
		//int			ttl_current;
		//pthread_mutex_t		lock;
		//pthread_cond_t		cond_wait;

	public:
    MihScannerTracert (Options* opts);
    virtual ~MihScannerTracert ();
    bool              trace ();
    uint8             getNbrReplies(uint8 ttl);
    //const TimedProbe* getHopInfo (uint8 ttl, int nprobe);
    //void              notifyReply (Reply* reply);
};

#endif // __TRACE_RT__

