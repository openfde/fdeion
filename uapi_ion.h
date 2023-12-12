/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * drivers/staging/android/uapi/fdeion.h
 *
 * Copyright (C) 2011 Google, Inc.
 */

#ifndef _UAPI_LINUX_FDEION_H
#define _UAPI_LINUX_FDEION_H

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * enum fdeion_heap_types - list of all possible types of heaps
 * @FDEION_HEAP_TYPE_SYSTEM:	 memory allocated via vmalloc
 * @FDEION_HEAP_TYPE_SYSTEM_CONTIG: memory allocated via kmalloc
 * @FDEION_HEAP_TYPE_CARVEOUT:	 memory allocated from a prereserved
 *				 carveout heap, allocatfdeions are physically
 *				 contiguous
 * @FDEION_HEAP_TYPE_DMA:		 memory allocated via DMA API
 * @FDEION_NUM_HEAPS:		 helper for iterating over heaps, a bit mask
 *				 is used to identify the heaps, so only 32
 *				 total heap types are supported
 */
enum fdeion_heap_type
{
    FDEION_HEAP_TYPE_SYSTEM,
    FDEION_HEAP_TYPE_SYSTEM_CONTIG,
    FDEION_HEAP_TYPE_CARVEOUT,
    FDEION_HEAP_TYPE_CHUNK,
    FDEION_HEAP_TYPE_DMA,
    FDEION_HEAP_TYPE_CUSTOM, /*
                           * must be last so device specific heaps always
                           * are at the end of this enum
                           */
};

#define FDEION_NUM_HEAP_IDS (sizeof(unsigned int) * 8)

/**
 * allocatfdeion flags - the lower 16 bits are used by core fdeion, the upper 16
 * bits are reserved for use by the heaps themselves.
 */

/*
 * mappings of this buffer should be cached, fdeion will do cache maintenance
 * when the buffer is mapped for dma
 */
#define FDEION_FLAG_CACHED 1

/**
 * DOC: Ion Userspace API
 *
 * create a client by opening /dev/fdeion
 * most operations handled via following ioctls
 *
 */

/**
 * struct fdeion_allocatfdeion_data - metadata passed from userspace for allocatfdeions
 * @len:		size of the allocatfdeion
 * @heap_id_mask:	mask of heap ids to allocate from
 * @flags:		flags passed to heap
 * @handle:		pointer that will be populated with a cookie to use to
 *			refer to this allocatfdeion
 *
 * Provided by userspace as an argument to the ioctl
 */
struct fdeion_allocatfdeion_data
{
    __u64 len;
    __u32 heap_id_mask;
    __u32 flags;
    __u32 fd;
    __u32 unused;
};

#define MAX_HEAP_NAME 32

/**
 * struct fdeion_heap_data - data about a heap
 * @name - first 32 characters of the heap name
 * @type - heap type
 * @heap_id - heap id for the heap
 */
struct fdeion_heap_data
{
    char name[MAX_HEAP_NAME];
    __u32 type;
    __u32 heap_id;
    __u32 reserved0;
    __u32 reserved1;
    __u32 reserved2;
};

/**
 * struct fdeion_heap_query - collectfdeion of data about all heaps
 * @cnt - total number of heaps to be copied
 * @heaps - buffer to copy heap data
 */
struct fdeion_heap_query
{
    __u32 cnt;       /* Total number of heaps to be copied */
    __u32 reserved0; /* align to 64bits */
    __u64 heaps;     /* buffer to be populated */
    __u32 reserved1;
    __u32 reserved2;
};

#define FDEION_IOC_MAGIC 'I'

/**
 * DOC: FDEION_IOC_ALLOC - allocate memory
 *
 * Takes an fdeion_allocatfdeion_data struct and returns it with the handle field
 * populated with the opaque handle for the allocatfdeion.
 */
#define FDEION_IOC_ALLOC _IOWR(FDEION_IOC_MAGIC, 0, \
                            struct fdeion_allocatfdeion_data)

/**
 * DOC: FDEION_IOC_HEAP_QUERY - informatfdeion about available heaps
 *
 * Takes an fdeion_heap_query structure and populates informatfdeion about
 * available Ion heaps.
 */
#define FDEION_IOC_HEAP_QUERY _IOWR(FDEION_IOC_MAGIC, 8, \
                                 struct fdeion_heap_query)

#endif /* _UAPI_LINUX_FDEION_H */