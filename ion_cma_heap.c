// SPDX-License-Identifier: GPL-2.0
/*
 * FDEION Memory Allocator CMA heap exporter
 *
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cma.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/cma.h>
#include <linux/plist.h>

#include "fdeion.h"

struct fdeion_cma_heap
{
    struct fdeion_heap heap;
    struct cma *cma;
};

#define to_cma_heap(x) container_of(x, struct fdeion_cma_heap, heap)

/* FDEION CMA heap operatfdeions functfdeions */
static void fdeion_cma_free(struct fdeion_buffer *buffer)
{
    struct x100_display *display = buffer->display;

    /* release memory */
    if (buffer->vaddr)
    {
        fdeion_memory_pool_free(display, buffer->vaddr, buffer->size);
    }
    /* release sg table */
    sg_free_table(buffer->sg_table);
    kfree(buffer->sg_table);
}

static int fdeion_cma_allocate(struct fdeion_heap *heap, struct fdeion_buffer *buffer,
                            unsigned long len,
                            unsigned long flags)
{
    struct sg_table *sgt;
    struct page *page;
    int ret;
    struct x100_display *display = buffer->display;

    fdeion_memory_pool_alloc(display, &buffer->vaddr, &buffer->phys_addr, buffer->size);
    sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
    if (!sgt)
        goto err;

    ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
    if (ret)
        goto free_mem;

    page = phys_to_page(buffer->phys_addr);
    sg_set_page(sgt->sgl, page, PAGE_ALIGN(buffer->size), 0);

    buffer->priv_virt = page;
    buffer->sg_table = sgt;
    return 0;

free_mem:
    kfree(sgt);
err:
    display->mem_state[X100_MEM_VRAM_ALLOC] -= buffer->size;
    fdeion_cma_free(buffer);
    return -ENOMEM;
}

int fdeion_cma_heap_map_user(struct fdeion_heap *heap, struct fdeion_buffer *buffer,
                      struct vm_area_struct *vma)
{

    int ret = 0;
    unsigned long pfn;
    vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_page_prot = pgprot_writecombine(vm_get_page_prot(vma->vm_flags));
    vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);

    pfn = PHYS_PFN(buffer->phys_addr);

    /* not dumb buffer, map the whole buffer. */
    vma->vm_flags &= ~VM_PFNMAP;
    vma->vm_pgoff = 0;
    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
    ret = remap_pfn_range(vma, vma->vm_start, pfn,
            vma->vm_end - vma->vm_start, vma->vm_page_prot);
    return ret;
}

void *fdeion_cma_heap_map_kernel(struct fdeion_heap *heap,
                          struct fdeion_buffer *buffer)
{

    return buffer->vaddr;
}

void fdeion_cma_heap_unmap_kernel(struct fdeion_heap *heap,
                           struct fdeion_buffer *buffer)
{

}

static struct fdeion_heap_ops fdeion_cma_ops = {
    .allocate = fdeion_cma_allocate,
    .free = fdeion_cma_free,
    .map_user = fdeion_cma_heap_map_user,
    .map_kernel = fdeion_cma_heap_map_kernel,
    .unmap_kernel = fdeion_cma_heap_unmap_kernel,
};

static struct fdeion_heap *__fdeion_cma_heap_create(struct cma *cma)
{
    struct fdeion_cma_heap *cma_heap;

    cma_heap = kzalloc(sizeof(*cma_heap), GFP_KERNEL);

    if (!cma_heap)
        return ERR_PTR(-ENOMEM);

    cma_heap->heap.ops = &fdeion_cma_ops;
    cma_heap->cma = cma;
    cma_heap->heap.type = FDEION_HEAP_TYPE_DMA;
    return &cma_heap->heap;
}

static int __fdeion_add_cma_heaps(struct cma *cma, void *data)
{
    struct fdeion_heap *heap;

    heap = __fdeion_cma_heap_create(cma);
    if (IS_ERR(heap))
        return PTR_ERR(heap);

    heap->name = fde_cma_get_name(cma);


    fdeion_device_add_heap(heap);
    return 0;
}

int fdeion_add_cma_heaps(void)
{
    fde_cma_for_each_area(__fdeion_add_cma_heaps, NULL);
    return 0;
}

// device_initcall(fdeion_add_cma_heaps);
