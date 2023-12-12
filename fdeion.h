/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FDEION Memory Allocator kernel interface header
 *
 * Copyright (C) 2011 Google, Inc.
 */

#ifndef _FDEION_H
#define _FDEION_H

#include <linux/device.h>
#include <linux/dma-direction.h>
#include <linux/kref.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <linux/miscdevice.h>


#include "uapi_ion.h"
#include "./dc_include/x100_display_drv.h"

#define x100_vendor 0x1db7
#define x100_device 0xdc22
/**
 * struct fdeion_buffer - metadata for a particular buffer
 * @list:		element in list of deferred freeable buffers
 * @dev:		back pointer to the fdeion_device
 * @heap:		back pointer to the heap the buffer came from
 * @flags:		buffer specific flags
 * @private_flags:	internal buffer specific flags
 * @size:		size of the buffer
 * @priv_virt:		private data to the buffer representable as
 *			a void *
 * @lock:		protects the buffers cnt fields
 * @kmap_cnt:		number of times the buffer is mapped to the kernel
 * @vaddr:		the kernel mapping if kmap_cnt is not zero
 * @sg_table:		the sg table for the buffer
 * @attachments:	list of devices attached to this buffer
 */
struct fdeion_buffer
{
    struct list_head list;
    struct fdeion_device *dev;
    struct fdeion_heap *heap;
    unsigned long flags;
    unsigned long private_flags;
    size_t size;
    void *priv_virt;
    struct mutex lock;
    int kmap_cnt;
    void *vaddr;
    phys_addr_t phys_addr;
    struct sg_table *sg_table;
    struct list_head attachments;
    struct x100_display *display;
};

void fdeion_buffer_destroy(struct fdeion_buffer *buffer);

/**
 * struct fdeion_device - the metadata of the fdeion device node
 * @dev:		the actual misc device
 * @lock:		rwsem protecting the tree of heaps and clients
 */
struct fdeion_device
{
    struct miscdevice dev;
    struct rw_semaphore lock;
    struct plist_head heaps;
    struct dentry *debug_root;
    int heap_cnt;
};

/**
 * struct fdeion_heap_ops - ops to operate on a given heap
 * @allocate:		allocate memory
 * @free:		free memory
 * @map_kernel		map memory to the kernel
 * @unmap_kernel	unmap memory to the kernel
 * @map_user		map memory to userspace
 *
 * allocate, phys, and map_user return 0 on success, -errno on error.
 * map_dma and map_kernel return pointer on success, ERR_PTR on
 * error. @free will be called with FDEION_PRIV_FLAG_SHRINKER_FREE set in
 * the buffer's private_flags when called from a shrinker. In that
 * case, the pages being free'd must be truly free'd back to the
 * system, not put in a page pool or otherwise cached.
 */
struct fdeion_heap_ops
{
    int (*allocate)(struct fdeion_heap *heap,
                    struct fdeion_buffer *buffer, unsigned long len,
                    unsigned long flags);
    void (*free)(struct fdeion_buffer *buffer);
    void *(*map_kernel)(struct fdeion_heap *heap, struct fdeion_buffer *buffer);
    void (*unmap_kernel)(struct fdeion_heap *heap, struct fdeion_buffer *buffer);
    int (*map_user)(struct fdeion_heap *mapper, struct fdeion_buffer *buffer,
                    struct vm_area_struct *vma);
    int (*shrink)(struct fdeion_heap *heap, gfp_t gfp_mask, int nr_to_scan);
};

typedef bool (*fde_cma_release_t)(struct cma *cma, const struct page *pages, unsigned int count);
typedef int (*fde_cma_for_each_area_t)(int (*it)(struct cma *cma, void *data), void *data);
typedef void (*fde_plist_add_t)(struct plist_node *node, struct plist_head *head);
typedef const char * (*fde_cma_get_name_t)(const struct cma *cma);
typedef struct page *(*fde_cma_alloc_t)(struct cma *cma, size_t count, unsigned int align, bool no_warn);

extern fde_cma_release_t fde_cma_release;
extern fde_plist_add_t fde_plist_add;
extern fde_cma_for_each_area_t fde_cma_for_each_area;
extern fde_cma_get_name_t fde_cma_get_name;
extern fde_cma_alloc_t fde_cma_alloc;

int fdeion_memory_pool_alloc(struct x100_display *d, void **pvaddr,
					phys_addr_t *phys_addr, uint64_t size);
void fdeion_memory_pool_free(struct x100_display *d, void *vaddr, uint64_t size);
/**
 * heap flags - flags between the heaps and core fdeion code
 */
#define FDEION_HEAP_FLAG_DEFER_FREE BIT(0)

/**
 * private flags - flags internal to fdeion
 */
/*
 * Buffer is being freed from a shrinker functfdeion. Skip any possible
 * heap-specific caching mechanism (e.g. page pools). Guarantees that
 * any buffer storage that came from the system allocator will be
 * returned to the system allocator.
 */
#define FDEION_PRIV_FLAG_SHRINKER_FREE BIT(0)

/**
 * struct fdeion_heap - represents a heap in the system
 * @node:		rb node to put the heap on the device's tree of heaps
 * @dev:		back pointer to the fdeion_device
 * @type:		type of heap
 * @ops:		ops struct as above
 * @flags:		flags
 * @id:			id of heap, also indicates priority of this heap when
 *			allocating.  These are specified by platform data and
 *			MUST be unique
 * @name:		used for debugging
 * @shrinker:		a shrinker for the heap
 * @free_list:		free list head if deferred free is used
 * @free_list_size	size of the deferred free list in bytes
 * @lock:		protects the free list
 * @waitqueue:		queue to wait on from deferred free thread
 * @task:		task struct of deferred free thread
 * @num_of_buffers	the number of currently allocated buffers
 * @num_of_alloc_bytes	the number of allocated bytes
 * @alloc_bytes_wm	the number of allocated bytes watermark
 *
 * Represents a pool of memory from which buffers can be made.  In some
 * systems the only heap is regular system memory allocated via vmalloc.
 * On others, some blocks might require large physically contiguous buffers
 * that are allocated from a specially reserved heap.
 */
struct fdeion_heap
{
    struct plist_node node;
    struct fdeion_device *dev;
    enum fdeion_heap_type type;
    struct fdeion_heap_ops *ops;
    unsigned long flags;
    unsigned int id;
    const char *name;

    /* deferred free support */
    struct shrinker shrinker;
    struct list_head free_list;
    size_t free_list_size;
    spinlock_t free_lock;
    wait_queue_head_t waitqueue;
    struct task_struct *task;

    /* heap statistics */
    u64 num_of_buffers;
    u64 num_of_alloc_bytes;
    u64 alloc_bytes_wm;

    /* protect heap statistics */
    spinlock_t stat_lock;
};

/**
 * fdeion_device_add_heap - adds a heap to the fdeion device
 * @heap:		the heap to add
 */
void fdeion_device_add_heap(struct fdeion_heap *heap);

/**
 * some helpers for common operations on buffers using the sg_table
 * and vaddr fields
 */
void *fdeion_heap_map_kernel(struct fdeion_heap *heap, struct fdeion_buffer *buffer);
void fdeion_heap_unmap_kernel(struct fdeion_heap *heap, struct fdeion_buffer *buffer);
int fdeion_heap_map_user(struct fdeion_heap *heap, struct fdeion_buffer *buffer,
                         struct vm_area_struct *vma);
int fdeion_heap_buffer_zero(struct fdeion_buffer *buffer);
int fdeion_heap_pages_zero(struct page *page, size_t size, pgprot_t pgprot);

/**
 * fdeion_heap_init_shrinker
 * @heap:		the heap
 *
 * If a heap sets the FDEION_HEAP_FLAG_DEFER_FREE flag or defines the shrink op
 * this functfdeion will be called to setup a shrinker to shrink the freelists
 * and call the heap's shrink op.
 */
int fdeion_heap_init_shrinker(struct fdeion_heap *heap);

/**
 * fdeion_heap_init_deferred_free -- initialize deferred free functfdeionality
 * @heap:		the heap
 *
 * If a heap sets the FDEION_HEAP_FLAG_DEFER_FREE flag this functfdeion will
 * be called to setup deferred frees. Calls to free the buffer will
 * return immediately and the actual free will occur some time later
 */
int fdeion_heap_init_deferred_free(struct fdeion_heap *heap);

/**
 * fdeion_heap_freelist_add - add a buffer to the deferred free list
 * @heap:		the heap
 * @buffer:		the buffer
 *
 * Adds an item to the deferred freelist.
 */
void fdeion_heap_freelist_add(struct fdeion_heap *heap, struct fdeion_buffer *buffer);

/**
 * fdeion_heap_freelist_drain - drain the deferred free list
 * @heap:		the heap
 * @size:		amount of memory to drain in bytes
 *
 * Drains the indicated amount of memory from the deferred freelist immediately.
 * Returns the total amount freed.  The total freed may be higher depending
 * on the size of the items in the list, or lower if there is insufficient
 * total memory on the freelist.
 */
size_t fdeion_heap_freelist_drain(struct fdeion_heap *heap, size_t size);

/**
 * fdeion_heap_freelist_shrink - drain the deferred free
 *				list, skipping any heap-specific
 *				pooling or caching mechanisms
 *
 * @heap:		the heap
 * @size:		amount of memory to drain in bytes
 *
 * Drains the indicated amount of memory from the deferred freelist immediately.
 * Returns the total amount freed.  The total freed may be higher depending
 * on the size of the items in the list, or lower if there is insufficient
 * total memory on the freelist.
 *
 * Unlike with @fdeion_heap_freelist_drain, don't put any pages back into
 * page pools or otherwise cache the pages. Everything must be
 * genuinely free'd back to the system. If you're free'ing from a
 * shrinker you probably want to use this. Note that this relies on
 * the heap.ops.free callback honoring the FDEION_PRIV_FLAG_SHRINKER_FREE
 * flag.
 */
size_t fdeion_heap_freelist_shrink(struct fdeion_heap *heap,
                                   size_t size);

/**
 * fdeion_heap_freelist_size - returns the size of the freelist in bytes
 * @heap:		the heap
 */
size_t fdeion_heap_freelist_size(struct fdeion_heap *heap);

/**
 * functfdeions for creating and destroying a heap pool -- allows you
 * to keep a pool of pre allocated memory to use from your heap.  Keeping
 * a pool of memory that is ready for dma, ie any cached mapping have been
 * invalidated from the cache, provides a significant performance benefit on
 * many systems
 */

/**
 * struct fdeion_page_pool - pagepool struct
 * @high_count:		number of highmem items in the pool
 * @low_count:		number of lowmem items in the pool
 * @high_items:		list of highmem items
 * @low_items:		list of lowmem items
 * @mutex:		lock protecting this struct and especially the count
 *			item list
 * @gfp_mask:		gfp_mask to use from alloc
 * @order:		order of pages in the pool
 * @list:		plist node for list of pools
 *
 * Allows you to keep a pool of pre allocated pages to use from your heap.
 * Keeping a pool of pages that is ready for dma, ie any cached mapping have
 * been invalidated from the cache, provides a significant performance benefit
 * on many systems
 */
struct fdeion_page_pool
{
    int high_count;
    int low_count;
    struct list_head high_items;
    struct list_head low_items;
    struct mutex mutex;
    gfp_t gfp_mask;
    unsigned int order;
    struct plist_node list;
};

struct fdeion_page_pool *fdeion_page_pool_create(gfp_t gfp_mask, unsigned int order);
void fdeion_page_pool_destroy(struct fdeion_page_pool *pool);
struct page *fdeion_page_pool_alloc(struct fdeion_page_pool *pool);
void fdeion_page_pool_free(struct fdeion_page_pool *pool, struct page *page);

/** fdeion_page_pool_shrink - shrinks the size of the memory cached in the pool
 * @pool:		the pool
 * @gfp_mask:		the memory type to reclaim
 * @nr_to_scan:		number of items to shrink in pages
 *
 * returns the number of items freed in pages
 */
int fdeion_page_pool_shrink(struct fdeion_page_pool *pool, gfp_t gfp_mask,
                            int nr_to_scan);

#endif /* _FDEION_H */
