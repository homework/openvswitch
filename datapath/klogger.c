#include <linux/module.h>

#include <linux/kernel.h> /* printk() */
#include <linux/slab.h>	/* kmalloc; kfree */

#include <linux/init.h>
#include <linux/workqueue.h>

#include <linux/sched.h> /* current */
/* klogger as a device driver */
#include <linux/fs.h>

#include <linux/types.h>
#include <asm/uaccess.h> /* copy_to_user */

#include <linux/unistd.h>
#include <linux/rcupdate.h>

#include <linux/if_packet.h> /* PACKET_LOOPBACK */

#include <linux/mutex.h>
//#include <asm/semaphore.h>

#include "klogger.h"

#include "hashtable.h"
#include "hwdbflow.h"

#include "debug.h"

#ifndef OVS_HWDB
/* netfilter hooks */
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexandros Koliousis");

/* Hash table for Flows */
struct ht *flows;
/* and helper functions */
static int flows_expand(void);
static int flows_export(void);

static u32 incalls = 0; /* or, number of packets processed */
static u32 dropped = 0;

static int major = 0;

static int devnum = HWDB_DEVNUM;
static int cbsize = HWDB_CBSIZE;

static struct klog_dev *devs;

/* count of circular buffer's free space */
static int hwdb_dev_void(struct klog_dev *);
/* wait for circular buffer's free space */
static int hwdb_dev_wait(struct klog_dev *, bool);

static size_t hwdb_dev_write_records(struct klog_dev *, unsigned int,
	int (*func)(struct ht_node *, void *, size_t *, size_t));

static size_t hwdb_dev_write_buffers(struct klog_dev *, unsigned int,
	int (*func)(struct ht_node *, void *, size_t *, size_t));

/* Exports, as a periodic task */
#ifdef HWDB_VERBOSE
static u32 ninterrupts = 0;
#endif
static int die = 0;
static void intrpt_handler(struct work_struct *);
static struct workqueue_struct *workq;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
static struct work_struct Task;
static DECLARE_WORK(Task, intrpt_handler, NULL);
#else
static DECLARE_DELAYED_WORK(Task, intrpt_handler);
#endif
static unsigned long delay = 1 * HZ; /* export every 1 second */

#ifndef OVS_HWDB
static struct nf_hook_ops egrs; /* egress and ingress netfilter backdoor */
static struct nf_hook_ops igrs;

static char *lbi = "lo"; /* ignore loopback interface */

unsigned int watchdog(unsigned int hooknum, struct sk_buff *skb, const struct 
net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	int x = 0;
	/* dbg("[%s] in %s out %s\n", 
		__FUNCTION__, in ? in->name : "[null]", out ? out->name : "[null]"); */
	if ( in)
		if (strcmp( in->name, lbi) == 0) 
			x = 1;
	if (out)
		if (strcmp(out->name, lbi) == 0) 
			x = 1;
	if (skb->pkt_type == PACKET_LOOPBACK)
			x = 1;
	
	if (!x)
		klog(skb_clone(skb, GFP_ATOMIC), GFP_ATOMIC);

	return NF_ACCEPT;
}
#endif

static void intrpt_handler(struct work_struct *aux) {
	unsigned int nf = 0, np = 0, nr = 0;
	struct ht *table = rcu_dereference(flows);

	ht_foreach(table, hwdb_flow_f_count, &nf);
	ht_foreach(table, hwdb_flow_p_count, &np);
	ht_foreach(table, hwdb_flow_r_count, &nr);
	
	dbg("[%06u] timer fired (%u nf %u np; %u nr)\n", ++ninterrupts, nf, np, nr);
#ifdef HWDB_VERBOSE
	ht_foreach(table, hwdb_flow_ht_node_dump, NULL);
#endif
	
	hwdb_dev_write_records(&devs[0], nf, hwdb_flow_export_cumulative);
	hwdb_dev_write_records(&devs[1], np,    hwdb_flow_export_details);
	hwdb_dev_write_buffers(&devs[2], nr,   hwdb_flow_export_requests);
	
	/* If device(s) not open, delete on export */
	if (devs[0].size == 0) ht_foreach(table, hwdb_flow_fake_f_export, NULL);
	if (devs[1].size == 0) ht_foreach(table, hwdb_flow_fake_p_export, NULL);
	if (devs[2].size == 0) ht_foreach(table, hwdb_flow_fake_r_export, NULL);
	
	flows_export();

	if (die == 0) /* reschedule task */
		queue_delayed_work(workq, &Task, delay);
}

static int flow_accumulator(struct sk_buff *skb) {
	int r;

	struct ht *t;

	struct hwdb_flow_key key;

	struct hwdb_flow *flow;
	struct ht_node *node;
	
	r = hwdb_flow_extract(skb, &key);
	if (unlikely(r)) {
		return r;
	}
	
	t = rcu_dereference(flows);

	node = ht_lookup(t, &key, hwdb_flow_hash(&key), hwdb_flow_ht_node_cmp);
	if (!node) {
		if (ht_count(t) >= ht_capacity(t)) { /* expand table flows */
			r = flows_expand();
			if (r)
				return r;
			t = rcu_dereference(flows);
		}
		flow = hwdb_flow_alloc();
		if (IS_ERR(flow)) { return PTR_ERR(flow); }
		flow->key = key;
		r = ht_insert(t, &flow->ht_node, hwdb_flow_hash(&flow->key));
		if (r) {
			hwdb_flow_free(flow); /* free newly allocated flow */
			return r;
		}
	} else 
		flow = hwdb_flow_cast(node);
	
	/* increament counters */
	hwdb_flow_update(flow, skb);

	return 0;
}

/* assumes rcu_read_lock; 
priority is GFP_ATOMIC */

int klog(struct sk_buff *skb, gfp_t priority) {
	int r;

	dbg("[%u] skb message of %d bytes\n", ++incalls, skb->len);
	
	if (skb_is_nonlinear(skb)) {
		r = skb_linearize(skb);
		if(r)
			return r;
	}

	r = flow_accumulator(skb);
	
	if (r) {
		dbg("Accumulation error\n");
		return 1;
	}

	kfree_skb(skb);
	
	return 0;
}
EXPORT_SYMBOL(klog);

int hwdb_open(struct inode *inode, struct file *f) {
	struct klog_dev *dev;
	dev = container_of(inode->i_cdev, struct klog_dev, cdev);
	f->private_data = dev;
	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	if (!dev->data) {
		/* dev->data = (char *) __get_free_pages(GFP_KERNEL, HWDB_ORDER); */
		dev->data = kmalloc(cbsize, GFP_ATOMIC);
		if (!dev->data) {
			up(&dev->sem);
			return -ENOMEM;
		}
		memset(dev->data, 0, cbsize);
	}
	dev->size = cbsize;
	dev->fin = dev->data + dev->size;
	dev->rp = dev->wp = dev->data;
	if (f->f_mode &  FMODE_READ) dev->nr++;
	if (f->f_mode & FMODE_WRITE) dev->nw++;
	up(&dev->sem);
	return nonseekable_open(inode, f);
}

int hwdb_release(struct inode *inode, struct file *f) {
	struct klog_dev *dev;
	dev = f->private_data;
	down(&dev->sem);
	if (f->f_mode &  FMODE_READ) dev->nr--;
	if (f->f_mode & FMODE_WRITE) dev->nw--;
	if (dev->nr + dev->nw == 0) {
		/* free_pages((unsigned long) (dev->data), HWDB_ORDER); */
		kfree(dev->data);
		dev->data = NULL;
		dev->size = 0;
	}
	up(&dev->sem);
	dbg("[%s]\n", __FUNCTION__);
	return 0;
}

ssize_t hwdb_read(struct file *f, char __user *b, size_t count, 
	loff_t *pos) {
	struct klog_dev *dev = f->private_data;
	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	while (dev->rp == dev->wp) {
		up(&dev->sem);
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		dbg("%s sleeps\n", current->comm);
		if (wait_event_interruptible(dev->rq, (dev->rp != dev->wp)))
			return -ERESTARTSYS;
		if (down_interruptible(&dev->sem))
			return -ERESTARTSYS;
	}
	/* read data */
	if (dev->wp > dev->rp) count = min(count, (size_t) (dev->wp - dev->rp));
	else /* write pointer has wrapped */
		count = min(count, (size_t) (dev->fin - dev->rp));
	
	if (copy_to_user(b, dev->rp, count)) {
		up (&dev->sem);
		return -EFAULT;
	}
	dev->rp += count;
	if (dev->rp == dev->fin)
		dev->rp = dev->data; /* device buffer wrapped */
	up (&dev->sem);
	wake_up_interruptible(&dev->wq);
	dbg("%s reads %li bytes\n",current->comm, (long) count);
	return count;
}

ssize_t hwdb_write(struct file *f, const char __user *b, size_t count, 
	loff_t *pos) {
	return count;
}

struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = hwdb_open,
	.release = hwdb_release,
	.read = hwdb_read,
	.write = hwdb_write,
};

static int __init klogger_init(void) {
	int r, i, n;
	dev_t dev = MKDEV(major, 0);
	if (major)
		r = register_chrdev_region(dev, devnum, "hwdb");
	else {
		r = alloc_chrdev_region(&dev, 0, devnum, "hwdb");
		major = MAJOR(dev);
	}
	if (r < 0) {
		dbg("device region error %d\n", r);
		return r;
	}
	devs = kmalloc(devnum * sizeof(struct klog_dev), GFP_KERNEL);
	if (!devs) {
		unregister_chrdev_region(dev, devnum);
		return -ENOMEM;
	}
	memset(devs, 0, devnum * sizeof(struct klog_dev));
	for (i = 0; i < devnum; i++) {
		init_waitqueue_head(&(devs[i].rq));
		init_waitqueue_head(&(devs[i].wq));
		sema_init(&devs[i].sem, 1);
		//init_MUTEX(&devs[i].sem);		
		n = MKDEV(major, i); /* device setup */
		cdev_init(&devs[i].cdev, &fops);
		devs[i].cdev.owner = THIS_MODULE;
		devs[i].cdev.ops = &fops;
		r = cdev_add(&devs[i].cdev, n, 1);
		if (r)
			printk(KERN_NOTICE "Error (%d) adding hwdb%d\n", r, i);
	}
	
	/* init workqueue */
	workq = create_workqueue("hwdbwq");
	queue_delayed_work(workq, &Task, delay);
	
	/* init flow accumulator */
	flows = ht_create(0);
	if (flows)
		dbg("%d buckets in hash table flows\n", ht_capacity(flows));
	hwdb_flow_init();
#ifndef OVS_HWDB
	egrs.hook = watchdog;
	egrs.pf = PF_INET;
	egrs.priority = NF_IP_PRI_FIRST;
	egrs.hooknum = NF_INET_POST_ROUTING;
	nf_register_hook(&egrs);
	
	igrs.hook = watchdog;
	igrs.pf = PF_INET;
	igrs.priority = NF_IP_PRI_FIRST;
	igrs.hooknum = NF_INET_PRE_ROUTING;
	nf_register_hook(&igrs);	
#endif
	printk(KERN_INFO "init klogger\n");
	return 0;
}

static void __exit klogger_exit(void) {
	int i;
	for (i = 0; i < devnum; i++) {
		cdev_del(&devs[i].cdev);
		kfree(devs[i].data);
	}
	kfree(devs);
	unregister_chrdev_region(MKDEV(major, 0), devnum);
	devs = NULL;
	/* shutdown workqueue */
	die = 1;
	cancel_delayed_work(&Task);
	flush_workqueue(workq);
	destroy_workqueue(workq);
	
	/* destroy accumulators */
	ht_destroy(flows, hwdb_flow_ht_node_free);
	hwdb_flow_exit();
#ifndef OVS_HWDB	
	nf_unregister_hook(&egrs);
	nf_unregister_hook(&igrs);
#endif
	printk(KERN_INFO "exit klogger (incalls %u dropped %u)\n", 
		incalls, dropped);
	return;
}

static int hwdb_dev_void(struct klog_dev *dev) { /* returns free space */
	if (dev->rp == dev->wp)
		return dev->size -1;
	return ((dev->rp + dev->size - dev->wp) % dev->size) -1;
}

static int hwdb_dev_wait(struct klog_dev *dev, bool block) {
	/* wait for free space */
	while (hwdb_dev_void(dev) == 0) {
		DEFINE_WAIT(wait);
		up(&dev->sem);
		if (!block)
			return -EAGAIN;
		prepare_to_wait(&dev->wq, &wait, TASK_INTERRUPTIBLE);
		if (hwdb_dev_void(dev) == 0) /* wait for reader */
			schedule();
		finish_wait(&dev->wq, &wait);
		if (signal_pending(current))
			return -ERESTARTSYS;
		if (down_interruptible(&dev->sem))
			return -ERESTARTSYS;
	}
	return 0;
}

static size_t hwdb_dev_write_records(struct klog_dev *dev, unsigned int n,
	int (*export)(struct ht_node *, void *, size_t *, size_t)) {

	int r;
	
	size_t count, prev;
	
	struct __hwdb_flow *data;
	
	int len;
	
	if (n <= 0)
		return 1; /* nothing to write */

	if (dev->size == 0 || dev->nr == 0)
		return 1; /* device was released; or no readers are present */

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	r = hwdb_dev_wait(dev, true); /* a writer may block (true) */
	if (r)
		return r;
	
	count = (size_t) hwdb_dev_void(dev);
	if (dev->wp >= dev->rp) count = min(count, (size_t) (dev->fin - dev->wp));
	else
		count = min(count, (size_t) (dev->rp - dev->wp -1));
	dbg("[%s] %li bytes available (out of %li)\n", __FUNCTION__,
	(long) count, (long) dev->size);
	prev = count;
	count /= sizeof(struct __hwdb_flow);
	dbg("[%s] %li elements fit; %u required\n", __FUNCTION__, (long) count, n);
	
	if (unlikely(count <= 0)) {
		up (&dev->sem);
		return -EFAULT;
	}
	
	count = min(count, n);	
	data = kmalloc(count * sizeof(struct __hwdb_flow), GFP_ATOMIC);
	if (!data) {
		up (&dev->sem);
		return -ENOMEM;
	}
	memset(data, 0, count * sizeof(struct __hwdb_flow));

	count = ht_export(rcu_dereference(flows), export, data, count);
	len = count * sizeof(struct __hwdb_flow);
	if (len <= 0) {
		dbg("[%s] warning: no elements exported\n", __FUNCTION__);
		if (data)
			kfree(data);
		up (&dev->sem);
		return -EFAULT;
	}
	
	dbg("[%s] write %li elements (%d bytes)\n", __FUNCTION__, (long) count, 
		len);
	memcpy(dev->wp, (void *) data, len);
	if (data)
		kfree(data);

	dev->wp += len;
	if (dev->wp == dev->fin) dev->wp = dev->data; /* device buffer wrapped */
	
	up(&dev->sem);
	/* awake readers */
	wake_up_interruptible(&dev->rq);
	return len;
}

static size_t hwdb_dev_write_buffers(struct klog_dev *dev, unsigned int n, 
	int (*export)(struct ht_node *, void *, size_t *, size_t)) {
	
	int r;
	
	size_t count;
	
	char *data;
	
	int len;
	
	if (n <= 0)
		return 1; /* nothing to write */
	
	if (dev->size == 0 || dev->nr == 0)
		return 1; /* device was released; or no readers are present */
	
	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	
	r = hwdb_dev_wait(dev, true); /* writer may block (true) or not (false) */
	if (r)
		return r;
	
	count = (size_t) hwdb_dev_void(dev);
	if (dev->wp >= dev->rp) count = min(count, (size_t) (dev->fin - dev->wp));
	else
		count = min(count, (size_t) (dev->rp - dev->wp -1));
	dbg("[%s] %li bytes available (out of %li) - %u required\n", 
	__FUNCTION__, (long) count, (long) dev->size, n);

	if (unlikely(count <= 0)) {
		up (&dev->sem);
		return -EFAULT;
	}

	count = min(count, n);
	data = kmalloc(count, GFP_ATOMIC);
	if (!data) {
		up (&dev->sem);
		return -ENOMEM;
	}
	memset(data, 0, count);

	len = ht_export(rcu_dereference(flows), export, data, count);
	if (!len) {
		dbg("[%s] warning: no requests exported\n", __FUNCTION__);
		if (data)
			kfree(data);
		
		up (&dev->sem);
		return -EFAULT;
	}
	dbg("[%s] write %d bytes (out of %u)\n", __FUNCTION__, len, count);
	memcpy(dev->wp, (void *) data, len);
	if (data)
		kfree(data);

	dev->wp += len;
	if (dev->wp == dev->fin)
		dev->wp = dev->data; /* device bufffer wrapped */
	
	up(&dev->sem);
	/* awake readers */
	wake_up_interruptible(&dev->rq);
	return len;
}

static int flows_expand(void) {
	struct ht *prev = rcu_dereference(flows);
	struct ht *next = ht_expand(prev, 2);
	if (IS_ERR(next))
		return PTR_ERR(next);
	rcu_assign_pointer(flows, next);
	ht_deferred_destroy(prev, NULL);
	return 0;
}

static int insert_flow(struct ht_node *n, void *aux) { 
	struct hwdb_flow *f = hwdb_flow_cast(n);
	struct ht *t = aux;
	struct ht *table = rcu_dereference(t);
	struct hwdb_flow *flow;
	int error;
	if (hwdb_flow_ht_node_exported(n)) {
		dbg("[%s] node @%p (flow @%p) exported\n", __FUNCTION__, n, f);
		return 0;
	}
	dbg("[%s] node @%p (flow @%p) not fully exported\n", 
		__FUNCTION__, n, f);
	flow = hwdb_flow_alloc();
	if (IS_ERR(flow)) { return PTR_ERR(flow); }
	hwdb_flow_copy(flow, f); /* deep copy */
	error = ht_insert(table, &flow->ht_node, hwdb_flow_hash(&flow->key));
	if (error) {
		hwdb_flow_free(flow);
		return error;
	}
	dbg("[%s] flow @%p copy of %p)\n", __FUNCTION__, flow, f);
	return 0;
}

static int flows_export(void) {
	struct ht *prev = rcu_dereference(flows);
	struct ht *next;
	if (ht_count(prev) == 0)
		return 1;
	next = ht_create(0);
	if (!next)
		return -ENOMEM;
	ht_foreach(prev, insert_flow, rcu_dereference(next));
	rcu_assign_pointer(flows, next);
	dbg("[%s] hash table contains %u elements\n", __FUNCTION__, 
		ht_count(rcu_dereference(flows)));
#ifdef HWDB_VERBOSE
	ht_foreach(rcu_dereference(flows), hwdb_flow_ht_node_dump, NULL);
#endif
	ht_deferred_destroy(prev, hwdb_flow_ht_node_free);
	return 0;
}

module_init(klogger_init);
module_exit(klogger_exit);

/*
 * Acknowledgements
 *
 * The character device code is based on scull/pipe of
 * ``Linux Device Drivers'' by J. Corbet and A. Rubini
 */

