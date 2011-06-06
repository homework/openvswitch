#ifndef HWDB_HASH_TABLE_H
#define HWDB_HASH_TABLE_H

//struct ht;

struct ht_bucket;

struct ht_node { u32 hash; };

struct ht {
	struct rcu_head rcu;
	unsigned int capacity;
	struct ht_bucket ***buckets;
	unsigned int count;
	void (*destructor)(struct ht_node *);
};

#define TBL_L2_BITS (PAGE_SHIFT - ilog2(sizeof(struct ht_bucket  *)))
#define TBL_L2_SIZE (1 << TBL_L2_BITS)
#define TBL_L2_SHIFT 0

#define TBL_L1_BITS (PAGE_SHIFT - ilog2(sizeof(struct ht_bucket **)))
#define TBL_L1_SIZE (1 << TBL_L1_BITS)
#define TBL_L1_SHIFT TBL_L2_BITS

#define TBL_MAX_BUCKETS (TBL_L1_SIZE * TBL_L2_SIZE)

struct ht *ht_create(unsigned int n);

void ht_destroy(struct ht *, void (*destructor)(struct ht_node *));

/* rcu call */
void ht_deferred_destroy(struct ht *, void (*destructor)(struct ht_node *));

struct ht_node *ht_lookup(struct ht *, void *, u32 hash, 
	int (*cmp)(const struct ht_node *, void *));

int ht_insert(struct ht *, struct ht_node *, u32 hash);

int ht_remove(struct ht *, struct ht_node *);

int ht_foreach(struct ht *, int (*callback)(struct ht_node *, void *), void *);

/* returns a table copy `times` the size */
struct ht *ht_expand(struct ht *, int times);

int ht_export(struct ht *, 
	int (*func)(struct ht_node *, void *, size_t *, size_t), void *, size_t);

unsigned int ht_count(struct ht *);

int ht_capacity(struct ht *);

#endif /* hashtable.h */
