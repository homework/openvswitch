#ifndef HWDB_KLOGGER_H
#define HWDB_KLOGGER_H

#include <linux/skbuff.h>
#include <linux/cdev.h>

#include "khwdb.h"

/* called from openvswitch (cf. datapath/actions.c) */
extern int klog(struct sk_buff *skb, gfp_t priority);

struct klog_dev {
	wait_queue_head_t rq, wq;
	char *data, *fin;
	size_t size;
	char *rp, *wp;
	int nr, nw;
	struct semaphore sem;
	struct cdev cdev;
};

#endif

