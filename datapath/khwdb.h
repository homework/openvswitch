#ifndef __HWDB_H_
#define __HWDB_H_

/* number of hwdb char devices */
#define HWDB_DEVNUM 4

#define K 10
#define HWDB_FLOW_DURATION 10 /* 10 seconds */

struct __hwdb_flow_key {
	unsigned   int sa;
	unsigned   int da;
	unsigned short sp;
	unsigned short dp;
	unsigned  char protocol;
	unsigned  char tos;
}__attribute__((__packed__));

struct __hwdb_flow {
	struct __hwdb_flow_key key;
	struct timeval stamp;
	unsigned long long packets;
	unsigned long long bytes;
	unsigned char flags;
}__attribute__((__packed__));

struct __hwdb_request {
	struct __hwdb_flow_key key;
	unsigned int len;
}__attribute__((__packed__));

/* device circular buffer size - defaults to 100 elements */
#define HWDB_CBSIZE (100 * sizeof(struct __hwdb_flow))

#define HWDB_FLOW_ELEMENTS (HWDB_CBSIZE/sizeof(struct __hwdb_flow))

union __hwdb_data {
	char buffer[HWDB_CBSIZE];
	struct __hwdb_flow flow[HWDB_FLOW_ELEMENTS];
};

#endif /* hwdb.h */

