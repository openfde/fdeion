// SPDX-License-Identifier: GPL-2.0
/*
 * FDEION Memory Allocator system heap exporter
 *
 * Copyright (C) 2023 OpenFDE
 */

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "fdeion.h"

#define NUM_ORDERS ARRAY_SIZE(orders)

static gfp_t high_order_gfp_flags = (GFP_HIGHUSER | __GFP_ZERO | __GFP_NOWARN |
                                     __GFP_NORETRY) &
                                    ~__GFP_RECLAIM;
static gfp_t low_order_gfp_flags = GFP_HIGHUSER | __GFP_ZERO;
static const unsigned int orders[] = {8, 4, 0};

static int order_to_index(unsigned int order)
{
    int i;

    for (i = 0; i < NUM_ORDERS; i++)
        if (order == orders[i])
            return i;
    BUG();
    return -1;
}

static inline unsigned int order_to_size(int order)
{
    return PAGE_SIZE << order;
}

struct fdeion_system_heap
{
    struct fdeion_heap heap;
    struct fdeion_page_pool *pools[NUM_ORDERS];
};

static struct page *alloc_buffer_page(struct fdeion_system_heap *heap,
                                      struct fdeion_buffer *buffer,
                                      unsigned long order)
{
    struct fdeion_page_pool *pool = heap->pools[order_to_index(order)];

    return fdeion_page_pool_alloc(pool);
}

static void free_buffer_page(struct fdeion_system_heap *heap,
                             struct fdeion_buffer *buffer, struct page *page)
{
    struct fdeion_page_pool *pool;
    unsigned int order = compound_order(page);

    /* go to system */
    if (buffer->private_flags & FDEION_PRIV_FLAG_SHRINKER_FREE)
    {
        __free_pages(page, order);
        return;
    }

    pool = heap->pools[order_to_index(order)];

    fdeion_page_pool_free(pool, page);
}

static struct page *alloc_largest_available(struct fdeion_system_heap *heap,
                                            struct fdeion_buffer *buffer,
                                            unsigned long size,
                                            unsigned int max_order)
{
    struct page *page;
    int i;

    for (i = 0; i < NUM_ORDERS; i++)
    {
        if (size < order_to_size(orders[i]))
            continue;
        if (max_order < orders[i])
            continue;

        page = alloc_buffer_page(heap, buffer, orders[i]);
        if (!page)
            continue;

        return page;
    }

    return NULL;
}

static int fdeion_system_heap_allocate(struct fdeion_heap *heap,
                                    struct fdeion_buffer *buffer,
                                    unsigned long size,
                                    unsigned long flags)
{
    struct fdeion_system_heap *sys_heap = container_of(heap,
                                                    struct fdeion_system_heap,
                                                    heap);
    struct sg_table *table;
    struct scatterlist *sg;
    struct list_head pages;
    struct page *page, *tmp_page;
    int i = 0;
    unsigned long size_remaining = PAGE_ALIGN(size);
    unsigned int max_order = orders[0];

    if (size / PAGE_SIZE > totalram_pages() / 2)
        return -ENOMEM;

    INIT_LIST_HEAD(&pages);
    while (size_remaining > 0)
    {
        page = alloc_largest_available(sys_heap, buffer, size_remaining,
                                       max_order);
        if (!page)
            goto free_pages;
        list_add_tail(&page->lru, &pages);
        size_remaining -= page_size(page);
        max_order = compound_order(page);
        i++;
    }
    table = kmalloc(sizeof(*table), GFP_KERNEL);
    if (!table)
        goto free_pages;

    if (sg_alloc_table(table, i, GFP_KERNEL))
        goto free_table;

    sg = table->sgl;
    list_for_each_entry_safe(page, tmp_page, &pages, lru)
    {
        sg_set_page(sg, page, page_size(page), 0);
        sg = sg_next(sg);
        list_del(&page->lru);
    }

    buffer->sg_table = table;
    return 0;

free_table:
    kfree(table);
free_pages:
    list_for_each_entry_safe(page, tmp_page, &pages, lru)
        free_buffer_page(sys_heap, buffer, page);
    return -ENOMEM;
}

static void fdeion_system_heap_free(struct fdeion_buffer *buffer)
{
    struct fdeion_system_heap *sys_heap = container_of(buffer->heap,
                                                    struct fdeion_system_heap,
                                                    heap);
    struct sg_table *table = buffer->sg_table;
    struct scatterlist *sg;
    int i;

    /* zero the buffer before goto page pool */
    if (!(buffer->private_flags & FDEION_PRIV_FLAG_SHRINKER_FREE))
        fdeion_heap_buffer_zero(buffer);

    for_each_sg(table->sgl, sg, table->nents, i)
        free_buffer_page(sys_heap, buffer, sg_page(sg));
    sg_free_table(table);
    kfree(table);
}

static int fdeion_system_heap_shrink(struct fdeion_heap *heap, gfp_t gfp_mask,
                                  int nr_to_scan)
{
    struct fdeion_page_pool *pool;
    struct fdeion_system_heap *sys_heap;
    int nr_total = 0;
    int i, nr_freed;
    int only_scan = 0;

    sys_heap = container_of(heap, struct fdeion_system_heap, heap);

    if (!nr_to_scan)
        only_scan = 1;

    for (i = 0; i < NUM_ORDERS; i++)
    {
        pool = sys_heap->pools[i];

        if (only_scan)
        {
            nr_total += fdeion_page_pool_shrink(pool,
                                             gfp_mask,
                                             nr_to_scan);
        }
        else
        {
            nr_freed = fdeion_page_pool_shrink(pool,
                                            gfp_mask,
                                            nr_to_scan);
            nr_to_scan -= nr_freed;
            nr_total += nr_freed;
            if (nr_to_scan <= 0)
                break;
        }
    }
    return nr_total;
}

static struct fdeion_heap_ops system_heap_ops = {
    .allocate = fdeion_system_heap_allocate,
    .free = fdeion_system_heap_free,
    .map_kernel = fdeion_heap_map_kernel,
    .unmap_kernel = fdeion_heap_unmap_kernel,
    .map_user = fdeion_heap_map_user,
    .shrink = fdeion_system_heap_shrink,
};

static void fdeion_system_heap_destroy_pools(struct fdeion_page_pool **pools)
{
    int i;

    for (i = 0; i < NUM_ORDERS; i++)
        if (pools[i])
            fdeion_page_pool_destroy(pools[i]);
}

static int fdeion_system_heap_create_pools(struct fdeion_page_pool **pools)
{
    int i;

    for (i = 0; i < NUM_ORDERS; i++)
    {
        struct fdeion_page_pool *pool;
        gfp_t gfp_flags = low_order_gfp_flags;

        if (orders[i] > 4)
            gfp_flags = high_order_gfp_flags;

        pool = fdeion_page_pool_create(gfp_flags, orders[i]);
        if (!pool)
            goto err_create_pool;
        pools[i] = pool;
    }

    return 0;

err_create_pool:
    fdeion_system_heap_destroy_pools(pools);
    return -ENOMEM;
}

static struct fdeion_heap *__fdeion_system_heap_create(void)
{
    struct fdeion_system_heap *heap;

    heap = kzalloc(sizeof(*heap), GFP_KERNEL);
    if (!heap)
        return ERR_PTR(-ENOMEM);
    heap->heap.ops = &system_heap_ops;
    heap->heap.type = FDEION_HEAP_TYPE_SYSTEM;
    heap->heap.flags = FDEION_HEAP_FLAG_DEFER_FREE;

    if (fdeion_system_heap_create_pools(heap->pools))
        goto free_heap;

    return &heap->heap;

free_heap:
    kfree(heap);
    return ERR_PTR(-ENOMEM);
}

int fdeion_system_heap_create(void)
{
    struct fdeion_heap *heap;

    heap = __fdeion_system_heap_create();
    if (IS_ERR(heap))
        return PTR_ERR(heap);
    heap->name = "fdeion_system_heap";

    fdeion_device_add_heap(heap);

    return 0;
}
// device_initcall(fdeion_system_heap_create);

static int fdeion_system_contig_heap_allocate(struct fdeion_heap *heap,
                                           struct fdeion_buffer *buffer,
                                           unsigned long len,
                                           unsigned long flags)
{
    int order = get_order(len);
    struct page *page;
    struct sg_table *table;
    unsigned long i;
    int ret;

    page = alloc_pages(low_order_gfp_flags | __GFP_NOWARN, order);
    if (!page)
        return -ENOMEM;

    split_page(page, order);

    len = PAGE_ALIGN(len);
    for (i = len >> PAGE_SHIFT; i < (1 << order); i++)
        __free_page(page + i);

    table = kmalloc(sizeof(*table), GFP_KERNEL);
    if (!table)
    {
        ret = -ENOMEM;
        goto free_pages;
    }

    ret = sg_alloc_table(table, 1, GFP_KERNEL);
    if (ret)
        goto free_table;

    sg_set_page(table->sgl, page, len, 0);

    buffer->sg_table = table;

    return 0;

free_table:
    kfree(table);
free_pages:
    for (i = 0; i < len >> PAGE_SHIFT; i++)
        __free_page(page + i);

    return ret;
}

static void fdeion_system_contig_heap_free(struct fdeion_buffer *buffer)
{
    struct sg_table *table = buffer->sg_table;
    struct page *page = sg_page(table->sgl);
    unsigned long pages = PAGE_ALIGN(buffer->size) >> PAGE_SHIFT;
    unsigned long i;

    for (i = 0; i < pages; i++)
        __free_page(page + i);
    sg_free_table(table);
    kfree(table);
}

static struct fdeion_heap_ops kmalloc_ops = {
    .allocate = fdeion_system_contig_heap_allocate,
    .free = fdeion_system_contig_heap_free,
    .map_kernel = fdeion_heap_map_kernel,
    .unmap_kernel = fdeion_heap_unmap_kernel,
    .map_user = fdeion_heap_map_user,
};

static struct fdeion_heap *__fdeion_system_contig_heap_create(void)
{
    struct fdeion_heap *heap;

    heap = kzalloc(sizeof(*heap), GFP_KERNEL);
    if (!heap)
        return ERR_PTR(-ENOMEM);
    heap->ops = &kmalloc_ops;
    heap->type = FDEION_HEAP_TYPE_SYSTEM_CONTIG;
    heap->name = "fdeion_system_contig_heap";

    return heap;
}

int fdeion_system_contig_heap_create(void)
{
    struct fdeion_heap *heap;

    heap = __fdeion_system_contig_heap_create();
    if (IS_ERR(heap))
        return PTR_ERR(heap);

    fdeion_device_add_heap(heap);

    return 0;
}

