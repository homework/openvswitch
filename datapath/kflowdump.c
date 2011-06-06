#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h> /* ntohs */

#include "hwdb.h"

#include "debug.h"

void process(char *s, int l) {
	int i;
	int elements = l/sizeof(struct __hwdb_flow);
	union __hwdb_data *data = (union __hwdb_data *) s;
	dbg("buffer size %d; %d elements \n", l, elements);
	if (!s) /* unlikely */
		return;
	for(i = 0; i < elements; i++) {
		dbg("%u:"IP4_FMT":%05hu:"IP4_FMT":%05hu:%llu:%llu"FLG_FMT"\n",
		data->flow[i].key.protocol,
		IP4_ARG(&data->flow[i].key.sa), ntohs(data->flow[i].key.sp),
		IP4_ARG(&data->flow[i].key.da), ntohs(data->flow[i].key.dp),
		data->flow[i].packets,
		data->flow[i].bytes,
		FLG_ARG(data->flow[i].flags)
		);
	}
}

int main(int argc, char *argv[]) {
	char buffer[HWDB_CBSIZE];
	int f;
	int l, count;
	if (argc < 2) {
		fprintf(stderr, "kflowcat [device]\n");
		return(1);
	}
	f=open(argv[1], O_RDONLY);
	if (f<0) {
		fprintf(stderr, "Error opening %s\n", argv[1]);
		return(1);
	}
	count=0;
	dbg("klogger reads\n");
	while (count <= 1) {
	memset(buffer, 0, sizeof(buffer));
	l = read(f, buffer, HWDB_CBSIZE);
	++count;
	process(buffer, l);
	}
	close(f);
	return(0);
}

