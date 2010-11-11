#ifndef _PACKET_H
#define _PACKET_H

enum ptypes
{
	P_NEWCLIENT,
	P_NEWCLIENT_ACK,
	P_CAPEST_START,
	P_CAP_ACK,
	P_TBDETECT_START,
	P_TBDETECT_START_ACK,
	P_TBDETECT_END,
	P_RECVDATA,
	P_MEASFLOW_START,
	P_MEASFLOW_START_ACK,
	P_MEASFLOW_END
};

enum probetypes
{
	CAP,
	MEAS,
	TB,
	BLP_P,
	LIP_P,
	LDP_P,
	BLP_A,
	LIP_A,
	LDP_A,
	BLP_AP,
	LIP_AP,
	LDP_AP
};

enum flow { flowP, flowA };

typedef struct _header
{
	unsigned char ptype;
	unsigned int length;
} __attribute__((packed)) pheader;

typedef struct _newclientpkt
{
	pheader header;
	unsigned int version;
	unsigned int fileid;
	double delta;
} __attribute__((packed)) pnewclientpacket;

typedef struct _newclientack
{
	pheader header;
	unsigned char compatibilityFlag;
} __attribute__((packed)) pnewclientack;

typedef struct _capeststart
{
	pheader header;
} __attribute__((packed)) pcapeststart;

typedef struct _capestack
{
	pheader header;
	unsigned int capacity;//Kbps
	unsigned int finalflag;
	unsigned int trainlength;
} __attribute__((packed)) pcapestack;

typedef struct _tbdetectstart
{
	pheader header;
} __attribute__((packed)) ptbdetectstart;

typedef struct _tbdetectstartack
{
	pheader header;
	unsigned int duration;
} __attribute__((packed)) ptbdetectstartack;

typedef struct _tbdetectend
{
	pheader header;
	unsigned int result;
	unsigned int minbucketDepth;
	unsigned int maxbucketDepth;
	unsigned int tokenRate; //Kbps
	unsigned int abortflag;
} __attribute__((packed)) ptbdetectend;

typedef struct _rcvdata
{
	pheader header;
	unsigned int datalength;
} __attribute__((packed)) prcvdata;

typedef struct _mflowstart
{
	pheader header;
} __attribute__((packed)) pmflowstart;

typedef struct _mflowstartack
{
	pheader header;
	unsigned int duration;
} __attribute__((packed)) pmflowstartack;

typedef struct _mflowend
{
	pheader header;
	unsigned int recvrate;
} __attribute__((packed)) pmflowend;


int readwrapper(int sock, char *buf, size_t size);
int writewrapper(int sock, char *buf, size_t size);

#endif

