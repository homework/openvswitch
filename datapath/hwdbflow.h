#ifndef HWDB_FLOW_H
#define HWDB_FLOW_H

#include "khwdb.h"

#include "hashtable.h"

#include "debug.h"

#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#include <linux/skbuff.h>

struct hwdb_flow_key {
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;
	uint8_t protocol;
	uint8_t tos;
	uint8_t reserved[2]; /* 32-bit aligned */
};

struct a {
	u64 pckt_count;
	u64 byte_count;
	u8 flags; /* OR-ed TCP flags */
};

struct hwdb_flow_packet {
	struct timeval stamp;
	u64 bytes;
	u8 flags;
};

struct f {
	u64 packets;
	struct hwdb_flow_packet packet[K + 1];
};

struct r { /* HTTP request */
	u8 fin;
	unsigned int len;
	char *header;
};

enum {
	HWDB_FLOW_ACC_EXPORTED = 01,
	HWDB_FLOW_FNP_EXPORTED = 02,
	HWDB_FLOW_REQ_EXPORTED = 04
};

struct hwdb_flow {
	struct rcu_head rcu;
	struct ht_node ht_node;
	struct hwdb_flow_key key;
	spinlock_t lock;
	struct timeval last;
	struct a acc;
	struct f first;
	struct r request;
	int clone;
};

int hwdb_flow_init(void);

void hwdb_flow_exit(void);

u32 hwdb_flow_hash(const struct hwdb_flow_key *key);

struct hwdb_flow *hwdb_flow_alloc(void);

int hwdb_flow_copy(struct hwdb_flow *, struct hwdb_flow *);

void hwdb_flow_free(struct hwdb_flow *);

void hwdb_flow_acc_reset(struct hwdb_flow *);

void hwdb_flow_first_reset(struct hwdb_flow *);

void hwdb_flow_request_reset(struct hwdb_flow *);

void hwdb_flow_deferred_free(struct hwdb_flow *); /* rcu call */

void hwdb_flow_dump(struct hwdb_flow *);

void hwdb_flow_update(struct hwdb_flow *, struct sk_buff *);

int hwdb_flow_extract(struct sk_buff *, struct hwdb_flow_key *);

int hwdb_flow_ht_node_cmp(const struct ht_node *, void *k);

void hwdb_flow_ht_node_free(struct ht_node *);

void hwdb_flow_ht_node_deferred_free(struct ht_node *);

int hwdb_flow_ht_node_dump(struct ht_node *, void *);

int hwdb_flow_f_count(struct ht_node *, void *);

int hwdb_flow_p_count(struct ht_node *, void *);

int hwdb_flow_r_count(struct ht_node *, void *);

int hwdb_flow_fake_f_export(struct ht_node *, void *);

int hwdb_flow_fake_p_export(struct ht_node *, void *);

int hwdb_flow_fake_r_export(struct ht_node *, void *);

int hwdb_flow_export_cumulative(struct ht_node *, void *, size_t *, size_t);

int hwdb_flow_export_details(struct ht_node *, void *, size_t *, size_t);

int hwdb_flow_export_requests(struct ht_node *, void *, size_t *, size_t);

bool hwdb_flow_ht_node_exported(struct ht_node *);

static inline struct hwdb_flow *hwdb_flow_cast(const struct ht_node *node) {
	return container_of(node, struct hwdb_flow, ht_node);
}

static inline bool hwdb_flow_finished(const struct hwdb_flow *f) {
	struct timeval n;
	u8 idx = (f->first.packets < K) ? f->first.packets : K;
	do_gettimeofday(&n);
	return (
		(f->first.packet[idx].flags & FIN)
		||
		(f->first.packet[idx].stamp.tv_sec + HWDB_FLOW_DURATION < n.tv_sec)
	);
}

#endif /* hwdbflow.h */
