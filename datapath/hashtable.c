#include <linux/mm.h> /* pgd_lock */
#include <asm/pgtable.h>

#include <linux/slab.h> /* kmalloc */
#include <linux/gfp.h>

#include <linux/rcupdate.h>

#include "hashtable.h"

#include "debug.h"

#include "khwdb.h"

static gfp_t priority = GFP_ATOMIC;

/* struct ht { */
/* 	struct rcu_head rcu; */
/* 	unsigned int capacity; */
/* 	struct ht_bucket ***buckets; */
/* 	unsigned int count; */
/* 	void (*destructor)(struct ht_node *); */
/* }; */

struct ht_bucket {
	struct rcu_head rcu;
	unsigned int n; /* number of objects */
	struct ht_node *objects[];
};

static struct ht_bucket *bucket_alloc(int n) {
	int bytes = sizeof(struct ht_bucket) + sizeof(struct ht_node *) * n;
	dbg("[%s] bytes %d\n", bytes);
	if (bytes > 0)
		return kmalloc(bytes, priority);
	else
		return NULL;
}

static void buckets_free(struct ht_bucket ***l1, unsigned int n, 
	void (*func) (struct ht_node *)) {
	/* `n` is the capacity of the hash table */
	unsigned int i;
	for (i = 0; i < n >> TBL_L1_BITS; i++) {
		struct ht_bucket **l2 = l1[i];
		unsigned int j;
		for (j = 0; j < TBL_L1_SIZE; j++) {
			struct ht_bucket *bucket = l2[j];
			if (!bucket)
				continue;
			if (func) { /* object destructor */
				unsigned int k;
				for (k = 0; k < bucket->n; k++)
					func(bucket->objects[k]);
			}
			kfree(bucket);
		}
		free_page((unsigned long) l2);
	}
	kfree(l1);
}

static struct ht_bucket ***buckets_alloc(unsigned int n) {
	struct ht_bucket ***l1;
	unsigned int i;
	l1 = kmalloc((n >> TBL_L1_BITS) * sizeof(struct ht_bucket **), priority);
	if (!l1)
		return NULL;
	for (i = 0; i < n >> TBL_L1_BITS; i++) {
		l1[i] = (struct ht_bucket **) get_zeroed_page(priority);
		if (!l1[i]) {
			buckets_free(l1, i << TBL_L1_BITS, 0);
			return NULL;
		}
	}
	return l1;
}

static struct ht_bucket **find(struct ht *table, u32 hash) {
	unsigned int l1 = (hash & (table->capacity - 1)) >> TBL_L1_SHIFT;
	unsigned int l2 = hash & ((1 << TBL_L2_BITS) - 1);
	return &table->buckets[l1][l2];
}

static int search(const struct ht_bucket *bucket, void *target, u32 hash, 
	int (*cmp)(const struct ht_node *, void *)) {
	int i;
	for (i = 0; i < bucket->n; i++) {
		struct ht_node *obj = rcu_dereference(bucket->objects[i]);
		if (obj->hash == hash && likely(cmp(obj, target)))
			return i;
	}
	return -1;
}

static int insert(struct ht_node *node, void *table) { /* cf. ht_expand */
	struct ht *t = table;
	return ht_insert(t, node, node->hash);
}

struct ht *ht_create(unsigned int n) {
	struct ht *table;
	if (!n) 
		n = TBL_L1_SIZE;
	table = kzalloc(sizeof *table, priority);
	if (!table)
		return NULL;
	table->capacity = n;
	table->count = 0;
	table->buckets = buckets_alloc(n);
	if (!table->buckets) {
		kfree(table);
		return NULL;
	}
	return table;
}

void ht_destroy(struct ht *table, void (*destructor)(struct ht_node *)) {
	if (!table)
		return;
	buckets_free(table->buckets, table->capacity, destructor);
	kfree(table);
}

static void ht_rcu_call(struct rcu_head *rcu) {
	struct ht *t = container_of(rcu, struct ht, rcu);
	ht_destroy(t, t->destructor);
}

void ht_deferred_destroy(struct ht *t, void (*func)(struct ht_node *)) {
	if (!t)
		return;
	t->destructor = func;
	call_rcu(&t->rcu, ht_rcu_call);
}

struct ht_node *ht_lookup(struct ht *table, void *target, u32 hash,
	int (*cmp)(const struct ht_node *, void *)) {
	struct ht_bucket **b = find(table, hash);
	struct ht_bucket *bucket = rcu_dereference(*b);
	int index;
	if (!bucket)
		return NULL;
	index = search(bucket, target, hash, cmp);
	if (index < 0)
		return NULL;
	return bucket->objects[index];
}

int ht_foreach(struct ht *table, 
	int (*callback)(struct ht_node *, void *aux), void *aux) {
	unsigned int i, j, k;
	for (i = 0; i < table->capacity >> TBL_L1_BITS; i++) {
		struct ht_bucket **l2 = table->buckets[i];
		for (j = 0; j < TBL_L1_SIZE; j++) {
			struct ht_bucket *bucket = rcu_dereference(l2[j]);
			if (!bucket)
				continue;
			for (k = 0; k < bucket->n; k++) {
				int error = (*callback)(bucket->objects[k], aux);
				if (error)
					return error;
			}
		}
	}
	return 0;
}

int ht_export(struct ht *table, 
	int (*func)(struct ht_node *, void *, size_t *, size_t), void *aux, 
	size_t count) {
	unsigned int i, j, k;
	size_t idx = 0;
	dbg("[%s] auxiliary data @%p\n", __FUNCTION__, aux);
	for (i = 0; i < table->capacity >> TBL_L1_BITS; i++) {
		struct ht_bucket **l2 = table->buckets[i];
		for (j = 0; j < TBL_L1_SIZE; j++) {
			struct ht_bucket *bucket = rcu_dereference(l2[j]);
			if (!bucket)
				continue;
			for (k = 0; k < bucket->n; k++) {
				int error = (*func)(bucket->objects[k], aux, &idx, count);
				if (error)
					return error;
			}
		}
	}
	dbg("[%s] returns count %li\n", __FUNCTION__, (long) idx);
	return idx;
}

struct ht *ht_expand(struct ht *table, int times) {
	int n = table->capacity * times;
	struct ht *newtable;
	if (n >= TBL_MAX_BUCKETS) {
		return ERR_PTR(-ENOSPC);
	}
	newtable = ht_create(n);
	if (!newtable)
		return ERR_PTR(-ENOMEM);
	if (ht_foreach(table, insert, newtable)) {
		ht_destroy(newtable, NULL);
		return ERR_PTR(-ENOMEM);
	}
	return newtable;
}

static void ht_bucket_rcu_call(struct rcu_head *rcu) {
	struct ht_bucket *bucket = container_of(rcu, struct ht_bucket, rcu);
	kfree(bucket);
}

int ht_insert(struct ht *table, struct ht_node *target, u32 hash) {
	struct ht_bucket **p = find(table, hash);
	struct ht_bucket *old = *rcu_dereference(p);
	unsigned int n = (old != NULL) ? old->n : 0;
	struct ht_bucket *new = bucket_alloc(n + 1);
	if (!new)
		return -ENOMEM;
	target->hash = hash;
	new->n = n + 1;
	if (old)
		memcpy(new->objects, old->objects, n * sizeof(struct ht_node *));
	new->objects[n] = target;
	rcu_assign_pointer(*p, new);
	if (old)
		call_rcu(&old->rcu, ht_bucket_rcu_call);
	table->count++;
	return 0;
}

int ht_remove(struct ht *table, struct ht_node *target) {
	struct ht_bucket **p = find(table, target->hash);
	struct ht_bucket *old = *rcu_dereference(p);
	unsigned int n = old->n;
	struct ht_bucket *new;
	if (n > 1) {
		unsigned int i;
		new = bucket_alloc(n - 1);
		if (!new)
			return -ENOMEM;
		new->n = 0;
		for (i = 0; i < n; i++) {
			struct ht_node *obj = old->objects[i];
			if (obj != target)
				new->objects[new->n++] = obj;
		}
		WARN_ON_ONCE(new->n != n - 1);
	} else {
		new = NULL;
	}
	rcu_assign_pointer(*p, new);
	call_rcu(&old->rcu, ht_bucket_rcu_call);
	table->count--;
	return 0;
}

int ht_capacity(struct ht *table) { return table->capacity; }

unsigned int ht_count(struct ht *table) { return table->count; }

/*
 * Acknowledgements
 *
 * The hash table code is based on table.{h,c}
 * located at <openvswitch>/datapath/
 */
