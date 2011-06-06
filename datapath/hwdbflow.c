#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/jiffies.h>

#include <linux/jhash.h>

#include <linux/in.h>

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/llc.h>
#include <linux/ip.h>

#include <net/inet_ecn.h>
#include <net/ip.h>

#include "hwdbflow.h"

struct kmem_cache *hwdb_flow_cache;
static unsigned int seed;

int hwdb_flow_init(void) {
	hwdb_flow_cache = kmem_cache_create("flowcache", sizeof(struct hwdb_flow), 
		0, 0, NULL);
	if (!hwdb_flow_cache)
		return -ENOMEM;
	get_random_bytes(&seed, sizeof seed);
	dbg("[%s] flow cache created; seed %u\n", __FUNCTION__, seed);
	return 0;
}

void hwdb_flow_exit(void) {
	kmem_cache_destroy(hwdb_flow_cache);
}

u32 hwdb_flow_hash(const struct hwdb_flow_key *key) {
	return jhash2((u32*) key, sizeof(*key)/sizeof(u32), seed);
}

struct hwdb_flow *hwdb_flow_alloc(void) {
	struct hwdb_flow *f;
	f = kmem_cache_zalloc(hwdb_flow_cache, GFP_ATOMIC);
	if (!f)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&f->lock);
	hwdb_flow_acc_reset(f);
	hwdb_flow_first_reset(f);
	hwdb_flow_request_reset(f);
	f->clone = 0;
	return f;
}

int hwdb_flow_copy(struct hwdb_flow *f, struct hwdb_flow *p) {
	memcpy(&f->key, &p->key, sizeof(struct hwdb_flow_key));
	
	f->last = p->last;
	
	memcpy(&f->acc, &p->acc, sizeof(struct a));
	
	memcpy(&f->first, &p->first, sizeof(struct f));
	
	f->clone = p->clone;
	
	/* copy request */
	f->request.fin = p->request.fin;
	f->request.len = p->request.len;
	if (p->request.header != NULL && p->request.len > 0) {
		f->request.header = kmalloc(f->request.len, GFP_ATOMIC);
		if (f->request.header)
			memcpy(f->request.header, p->request.header, f->request.len);
		else {
			f->request.header = NULL;
			f->request.len = 0;
			f->request.fin = 1;
			f->clone |= HWDB_FLOW_REQ_EXPORTED;
		}
	}
	return 0;
}

void hwdb_flow_acc_reset(struct hwdb_flow *f) {
	if (unlikely(!f))
		return;
	f->acc.pckt_count = 0;
	f->acc.byte_count = 0;
	f->acc.flags = 0;
	f->clone &= ~(HWDB_FLOW_ACC_EXPORTED);
}

static void hwdb_flow_first_reset_packet(struct hwdb_flow *f, size_t idx) {
	memset(&f->first.packet[idx].stamp, 0, sizeof(struct timeval));
	f->first.packet[idx].bytes = 0;
	f->first.packet[idx].flags = 0;	
}


void hwdb_flow_first_reset(struct hwdb_flow *f) {
	int i;	
	if (unlikely(!f))
		return;
	f->first.packets = 0;
	for (i = 0; i < K+1; i++) {
		hwdb_flow_first_reset_packet(f, i);	
	}
	f->clone &= ~(HWDB_FLOW_FNP_EXPORTED);
}

void hwdb_flow_request_reset(struct hwdb_flow *f) {
	if (unlikely(!f))
		return;
	f->request.len = 0;
	f->request.fin = 0;
	if (f->request.header)
		kfree(f->request.header);
	f->request.header = NULL;
	f->clone &= ~(HWDB_FLOW_REQ_EXPORTED);
}

void hwdb_flow_free(struct hwdb_flow *f) {
	if (unlikely(!f))
		return;
	hwdb_flow_acc_reset(f);
	hwdb_flow_first_reset(f);
	hwdb_flow_request_reset(f);
	kmem_cache_free(hwdb_flow_cache, f);
}

static void hwdb_flow_rcu_call(struct rcu_head *rcu) {
	struct hwdb_flow *f = container_of(rcu, struct hwdb_flow, rcu);
	hwdb_flow_free(f);
}

void hwdb_flow_deferred_free(struct hwdb_flow *f) {
	call_rcu(&f->rcu, hwdb_flow_rcu_call);
}

void hwdb_flow_ht_node_deferred_free(struct ht_node *node) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_deferred_free(f);
}

static void hwdb_flow_get_request(struct hwdb_flow *f, struct sk_buff *skb) {
	struct iphdr *iph;
	unsigned int ipl;
	struct tcphdr *tcph;
	unsigned int tcpl;
	char *payload;
	unsigned int payload_size;
	char *eoh;
	if (f->key.protocol == IPPROTO_TCP && 
	(ntohs(f->key.dst_port) == 80 || ntohs(f->key.dst_port) == 8080)) {
		dbg("[%s] network header length %hu\n", __FUNCTION__, 
		skb_network_header_len(skb));
		iph = ip_hdr(skb);
		ipl = iph->ihl * 4;
		dbg("[%s] ip header @%p length %u\n", __FUNCTION__, iph, ipl);
		tcph = tcp_hdr(skb);
		tcpl = (tcph->doff * 4);
		dbg("[%s] tcp header @%p length %u\n", __FUNCTION__, tcph, tcpl);
		payload_size = ntohs(iph->tot_len) - (ipl + tcpl);
		dbg("[%s] ip total length %u payload size %u\n", __FUNCTION__, 
		ntohs(iph->tot_len), payload_size);
		/* jump to http packet payload */
		payload = (char *) tcph + tcpl;
		dbg("[%s] payload starts @%p ends @%p size %u\n", __FUNCTION__, 
		payload, payload + payload_size, payload_size);	
		if (payload_size == 0)
			return;
		/* accumulate payload */
		if (f->request.len == 0) { /* first packet */
			
			eoh = strstr(payload, "\r\n\r\n"); /* find end of header */
			if (eoh) {
				dbg("[%s] eoh found\n", __FUNCTION__);
				f->request.len = eoh - payload + 4;
				dbg("[%s] request header size %u\n", __FUNCTION__,
					f->request.len);
				if (f->request.len > HWDB_CBSIZE) {
					dbg("[%s] warning: ignoring request (buffer overflow)\n", 
					__FUNCTION__);
					f->request.header = NULL;
					f->request.len = 0;
					f->request.fin = 1;
					f->clone |= HWDB_FLOW_REQ_EXPORTED; /* delete on export */
					return;
				}
				f->request.header = kmalloc(f->request.len, GFP_ATOMIC);
				if (f->request.header) {
					memcpy(f->request.header, payload, f->request.len);
					dbg("[%s] %u bytes copied\n", __FUNCTION__, f->request.len);
					f->request.fin = 1;
				} else {
					f->request.header = NULL;
					f->request.len = 0;
					f->request.fin = 1;
					f->clone |= HWDB_FLOW_REQ_EXPORTED; /* delete on export */
				}
			} else { /* first fragment */
				dbg("[%s] warning: ignoring request fragment of size %d\n", 
				__FUNCTION__, f->request.len);
				f->request.header = NULL;
				f->request.len = 0;
				f->request.fin = 1;
				f->clone |= HWDB_FLOW_REQ_EXPORTED; /* delete on export */
			}
		} else {
			/* re-assembly */
			dbg("[%s] warning: control reached unsupported block\n", 
			__FUNCTION__);
			f->request.fin = 1;
		}
	} else { /* other than outgoing http flow */
		f->request.header = NULL;
		f->request.len = 0;
		f->request.fin = 1;
		f->clone |= HWDB_FLOW_REQ_EXPORTED; /* delete on export */
	}
}

#define TCP_FLAG_OFFSET 13
#define TCP_FLAG_MASK 0x3f
void hwdb_flow_update(struct hwdb_flow *f, struct sk_buff *skb) {
	unsigned long flags;
	int idx;
	u8 tcpflags = 0;
	u8 *tcp;
	if (f->key.protocol == IPPROTO_TCP) {
		tcp = (u8 *) tcp_hdr(skb);
		tcpflags = *(tcp + TCP_FLAG_OFFSET) & TCP_FLAG_MASK;
	}
	spin_lock_irqsave(&f->lock, flags);
	do_gettimeofday(&f->last);
	/* cumulative values */
	f->acc.pckt_count += 1;
	f->acc.byte_count += skb->len;
	f->acc.flags |= tcpflags;
	/* first k packets */
	idx = (f->first.packets < K) ? f->first.packets : K;
	f->first.packets++;
	f->first.packet[idx].stamp = f->last;
	f->first.packet[idx].bytes += skb->len;
	f->first.packet[idx].flags |= tcpflags;
	/* http request header */
	if (!f->request.fin)
		hwdb_flow_get_request(f, skb);	
	spin_unlock_irqrestore(&f->lock, flags);
}

static inline int chk_iphdr(struct sk_buff *skb) {
	unsigned int offset = skb_network_offset(skb);
	unsigned int len;
	if (skb->len < offset + sizeof(struct iphdr))
		return -EINVAL;
	len = ip_hdrlen(skb);
	if (len < sizeof(struct iphdr) || skb->len < offset + len)
		return -EINVAL;
	if (!pskb_may_pull(skb, min(offset + len + 20, skb->len)))
		return -ENOMEM;
	skb_set_transport_header(skb, offset + len);
	return 0;
}

static inline bool chk_tcphdr(struct sk_buff *skb) {
	int offset = skb_transport_offset(skb);
	if (skb->len >= offset + sizeof(struct tcphdr)) {
		int len = tcp_hdrlen(skb);
		return (len >= sizeof(struct tcphdr) && skb->len >= offset + len);
	}
	return false;
}

static inline bool chk_udphdr(struct sk_buff *skb) {
	return skb->len >= skb_transport_offset(skb) + sizeof(struct udphdr);
}

int hwdb_flow_extract(struct sk_buff *skb, struct hwdb_flow_key *key) {
	int r;
	struct iphdr *ip;	
	memset(key, 0, sizeof *key);
	r = chk_iphdr(skb);
	if (unlikely(r)) {
		dbg("ip header error\n");
		return r;
	}
	ip = ip_hdr(skb);
	key->src_addr = ip->saddr;
	key->dst_addr = ip->daddr;
	key->tos = ip->tos & ~INET_ECN_MASK;
	key->protocol = ip->protocol;
	if (key->protocol == IPPROTO_TCP) {
		if (chk_tcphdr(skb)) {
			struct tcphdr *tcp = tcp_hdr(skb);
			key->src_port = tcp->source;
			key->dst_port = tcp->dest;
			return 0;
		}
		dbg("tcp header error\n");
	} else
	if (key->protocol == IPPROTO_UDP) {
		if (chk_udphdr(skb)) {
			struct udphdr *udp = udp_hdr(skb);
			key->src_port = udp->source;
			key->dst_port = udp->dest;
			return 0;
		}
		dbg("udp header error\n");
	} else
	{	/* neither TCP nor UDP packet */
		key->src_port = 0;
		key->dst_port = 0;
		return 0;
	}
	return 1;
}

void hwdb_flow_ht_node_free(struct ht_node* node) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_free(f);
}

void hwdb_flow_dump(struct hwdb_flow *flow) {
	/* formats and argumements defined in debug.h */
	unsigned long irqflags;
	int i;
	spin_lock_irqsave(&flow->lock, irqflags);
	dbg("%u:"IP4_FMT":%05hu:"IP4_FMT":%05hu:%llu:%llu"FLG_FMT"\n",
	flow->key.protocol,
	IP4_ARG(&flow->key.src_addr), ntohs(flow->key.src_port),
	IP4_ARG(&flow->key.dst_addr), ntohs(flow->key.dst_port),
	flow->acc.pckt_count,
	flow->acc.byte_count,
	FLG_ARG(flow->acc.flags)
	);
	for(i = 0; i < K+1; i++) {
		if (flow->first.packet[i].bytes > 0)
			dbg("index %d (of %llu):%llu"FLG_FMT"\n",
			i,
			flow->first.packets,
			flow->first.packet[i].bytes,
			FLG_ARG(flow->first.packet[i].flags)
			);
	}
	dbg("header len %u fin %u\n", flow->request.len, flow->request.fin);
	spin_unlock_irqrestore(&flow->lock, irqflags);
}

int hwdb_flow_ht_node_dump(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_dump(f);
	return 0;
}

int hwdb_flow_f_count(struct ht_node *node, void *aux) {
	unsigned int *nflows = (unsigned int *) aux;
	*nflows += 1;
	return 0;
}

int hwdb_flow_p_count(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	unsigned int *packets = (unsigned int *) aux;
	*packets += ((f->first.packets > K) ? K+1 : f->first.packets);
	return 0;
}

int hwdb_flow_r_count(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	unsigned int *bytes = (unsigned int *) aux;
	if (f->request.len > 0)
		*bytes += (f->request.len + sizeof(struct __hwdb_request));
	return 0;
}

int hwdb_flow_fake_f_export(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_acc_reset(f);
	f->clone |= HWDB_FLOW_ACC_EXPORTED; 
	return 0;
}

int hwdb_flow_fake_p_export(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_first_reset(f);
	f->clone |= HWDB_FLOW_FNP_EXPORTED;
	return 0;
}

int hwdb_flow_fake_r_export(struct ht_node *node, void *aux) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	hwdb_flow_request_reset(f);
	f->clone |= HWDB_FLOW_REQ_EXPORTED;
	return 0;
}

int hwdb_flow_export_cumulative(struct ht_node *node, void *aux, size_t *index, 
	size_t count) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	struct __hwdb_flow *data = (struct __hwdb_flow *) aux;
	size_t idx;
	
	if (f->acc.pckt_count == 0) {
		f->clone |= HWDB_FLOW_ACC_EXPORTED; /* nothing to export */
		return 0;
	}
	
	idx = *index;
	dbg("[%s] data @%p index %u\n", __FUNCTION__, &data[idx], idx);
	data[idx].key.sa = f->key.src_addr;
	data[idx].key.da = f->key.dst_addr;
	data[idx].key.sp = f->key.src_port;
	data[idx].key.dp = f->key.dst_port;
	data[idx].key.protocol = f->key.protocol;
	data[idx].key.tos = f->key.tos;
	data[idx].stamp = f->last;
	data[idx].packets = f->acc.pckt_count;
	data[idx].bytes = f->acc.byte_count;
	data[idx].flags = f->acc.flags;

	hwdb_flow_acc_reset(f);
	f->clone |= HWDB_FLOW_ACC_EXPORTED;

	*index += 1; /* increment ht_export's item counter */

	if (*index >= count) {
		dbg("[%s] stopped: already exported %u items (out of %u)\n", 
		__FUNCTION__, *index, count);
		return *index; /* causes ht_export to return */
	}
	return 0;
}

int hwdb_flow_export_details(struct ht_node *node, void *aux, size_t *index,
	size_t count) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
	struct __hwdb_flow *data = (struct __hwdb_flow *) aux;
	size_t idx;
	u8 i;
	if (f->first.packets <= 0) {
		f->clone |= HWDB_FLOW_FNP_EXPORTED; /* nothing to export */
		return 0;
	}
	
	if (!hwdb_flow_finished(f))
		return 0;

	dbg("[%s] flow finished\n", __FUNCTION__);
	for(i = 0; i < K+1; i++) {
		if (f->first.packet[i].bytes > 0) {
			idx = *index;
			dbg("[%s] data @%p index %d\n", __FUNCTION__, &data[idx], idx);
			data[idx].key.sa = f->key.src_addr;
			data[idx].key.da = f->key.dst_addr;
			data[idx].key.sp = f->key.src_port;
			data[idx].key.dp = f->key.dst_port;
			data[idx].key.protocol = f->key.protocol;
			data[idx].key.tos = f->key.tos;
			data[idx].stamp = f->first.packet[i].stamp;
			data[idx].packets = (i == K) ? (f->first.packets - K) : 1;
			data[idx].bytes = f->first.packet[i].bytes;
			data[idx].flags = f->first.packet[i].flags;

			hwdb_flow_first_reset_packet(f, i);

			*index += 1;
			
			if (*index >= count) {
				dbg("[%s] stopped: already exported %u items (out of %u)\n", 
				__FUNCTION__, *index, count);
				/* has flow `f` finished? */
				idx = (f->first.packets < K) ? f->first.packets -1 : K;
				if (f->first.packet[idx].bytes == 0) {
					dbg("[%s] last packet (at %u) exported; reset...\n", 
						__FUNCTION__, idx);
					hwdb_flow_first_reset(f);
					f->clone |= HWDB_FLOW_FNP_EXPORTED;
				}
				return *index;
			}
		}
	} /* at this point, all packets have been copied */
	hwdb_flow_first_reset(f);
	f->clone |= HWDB_FLOW_FNP_EXPORTED;
	return 0;
}

/* 
 * |aux______|aux+index_______________________|aux+count)
 */
int hwdb_flow_export_requests(struct ht_node *node, void *aux, size_t *index,
	size_t count) {
	struct __hwdb_request req;
	char *pos;
	struct hwdb_flow *f = hwdb_flow_cast(node);
	char *data = (char *) aux;
	size_t idx = *index;
	
	dbg("[%s] http len %u fin %u\n", 
	__FUNCTION__, f->request.len, f->request.fin);
	if (f->request.len == 0 && f->request.fin == 1) { /* non-http */
		f->clone |= HWDB_FLOW_REQ_EXPORTED;
		return 0;
	}
	
	if (!(f->request.len > 0 && f->request.fin == 1))
		return 0;
	
	memset(&req, 0, sizeof(struct __hwdb_request));

	dbg("[%s] index %u count %u\n", __FUNCTION__, idx, count);
	
	if (idx + sizeof(struct __hwdb_request) + f->request.len > count) {
		dbg("[%s] not enough space available\n", __FUNCTION__);
		/* copy `crash test dummy` */
		req.len = count - idx - sizeof(struct __hwdb_request);
		dbg("[%s] dummy write\n", __FUNCTION__);
		pos = data + idx;
		memcpy(pos, &req, sizeof(struct __hwdb_request));
		*index += (sizeof(struct __hwdb_request) + req.len);
	} else {
		req.key.sa = f->key.src_addr;
		req.key.da = f->key.dst_addr;
		req.key.sp = f->key.src_port;
		req.key.dp = f->key.dst_port;
		req.key.protocol = f->key.protocol;
		req.key.tos = f->key.tos;
		req.len = f->request.len;
		/* copy */
		pos = data + idx;
		memcpy(pos, &req, sizeof(struct __hwdb_request));
		pos += sizeof(struct __hwdb_request);
		memcpy(pos, f->request.header, f->request.len);
		*index += (sizeof(struct __hwdb_request) + f->request.len);
		hwdb_flow_request_reset(f);
		f->clone |= HWDB_FLOW_REQ_EXPORTED;
	}
	return 0;
}

int hwdb_flow_ht_node_cmp(const struct ht_node *node, void *k) {
	const struct hwdb_flow_key *a = &hwdb_flow_cast(node)->key;
	const struct hwdb_flow_key *b = k;
	return !memcmp(a, b, sizeof(struct hwdb_flow_key));
}

bool hwdb_flow_ht_node_exported(struct ht_node *node) {
	struct hwdb_flow *f = hwdb_flow_cast(node);
#ifdef HWDB_VERBOSE
	static char  acc_d [] = "ACC!";
	static char _acc_d [] = "¬ACC";
	static char  fnp_d [] = "FNP!";
	static char _fnp_d [] = "¬FNP";
	static char  req_d [] = "REQ!";
	static char _req_d [] = "¬REQ";
	dbg("[%s] %s:%s:%s\n", __FUNCTION__, 
		(f->clone & HWDB_FLOW_ACC_EXPORTED ? acc_d : _acc_d),
		(f->clone & HWDB_FLOW_FNP_EXPORTED ? fnp_d : _fnp_d),
		(f->clone & HWDB_FLOW_REQ_EXPORTED ? req_d : _req_d)
	);
#endif
	return (
		(f->clone & HWDB_FLOW_ACC_EXPORTED)
		&&
		(f->clone & HWDB_FLOW_FNP_EXPORTED)
		&&	
		(f->clone & HWDB_FLOW_REQ_EXPORTED)
	);
	
	/* return true; */
}

