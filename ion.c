// SPDX-License-Identifier: GPL-2.0
/*
 * FDEION Memory Allocator
 *
 * Copyright (C) 2023 OpenFDE
 */

#include <linux/module.h>

#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <linux/kallsyms.h>
#include <linux/pci.h>
#include <drm/drm_drv.h>
#include <linux/genalloc.h>

#include "fdeion.h"

static struct fdeion_device *internal_dev;
static int heap_id;
static struct x100_display *idis;

/* this functfdeion should only be called while dev->lock is held */
static struct fdeion_buffer *fdeion_buffer_create(struct fdeion_heap *heap,
                                                  struct fdeion_device *dev,
                                                  unsigned long len,
                                                  unsigned long flags)
{
    struct fdeion_buffer *buffer;
    int ret;

    buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
    if (!buffer)
        return ERR_PTR(-ENOMEM);

    buffer->heap = heap;
    buffer->flags = flags;
    buffer->dev = dev;
    buffer->size = len;
    buffer->display= idis;

    ret = heap->ops->allocate(heap, buffer, len, flags);

    if (ret)
    {
        if (!(heap->flags & FDEION_HEAP_FLAG_DEFER_FREE))
            goto err2;

        fdeion_heap_freelist_drain(heap, 0);
        ret = heap->ops->allocate(heap, buffer, len, flags);
        if (ret)
            goto err2;
    }

    if (!buffer->sg_table)
    {
        WARN_ONCE(1, "This heap needs to set the sgtable");
        ret = -EINVAL;
        goto err1;
    }

    spin_lock(&heap->stat_lock);
    heap->num_of_buffers++;
    heap->num_of_alloc_bytes += len;
    idis->mem_state[X100_MEM_VRAM_ALLOC] += len;
    if (heap->num_of_alloc_bytes > heap->alloc_bytes_wm)
        heap->alloc_bytes_wm = heap->num_of_alloc_bytes;
    spin_unlock(&heap->stat_lock);

    INIT_LIST_HEAD(&buffer->attachments);
    mutex_init(&buffer->lock);
    return buffer;

err1:
    heap->ops->free(buffer);
err2:
    kfree(buffer);
    return ERR_PTR(ret);
}

void fdeion_buffer_destroy(struct fdeion_buffer *buffer)
{
    if (buffer->kmap_cnt > 0)
    {
        pr_warn_once("%s: buffer still mapped in the kernel\n",
                     __func__);
        buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
    }
    buffer->heap->ops->free(buffer);
    spin_lock(&buffer->heap->stat_lock);
    buffer->heap->num_of_buffers--;
    buffer->heap->num_of_alloc_bytes -= buffer->size;
    idis->mem_state[X100_MEM_VRAM_ALLOC] -= buffer->size;
    spin_unlock(&buffer->heap->stat_lock);

    kfree(buffer);
}

static void _fdeion_buffer_destroy(struct fdeion_buffer *buffer)
{
    struct fdeion_heap *heap = buffer->heap;

    if (heap->flags & FDEION_HEAP_FLAG_DEFER_FREE)
        fdeion_heap_freelist_add(heap, buffer);
    else
        fdeion_buffer_destroy(buffer);
}

static void *fdeion_buffer_kmap_get(struct fdeion_buffer *buffer)
{
    void *vaddr;

    if (buffer->kmap_cnt)
    {
        if (buffer->kmap_cnt == INT_MAX)
            return ERR_PTR(-EOVERFLOW);

        buffer->kmap_cnt++;
        return buffer->vaddr;
    }
    vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
    if (WARN_ONCE(!vaddr,
                  "heap->ops->map_kernel should return ERR_PTR on error"))
        return ERR_PTR(-EINVAL);
    if (IS_ERR(vaddr))
        return vaddr;
    buffer->vaddr = vaddr;
    buffer->kmap_cnt++;
    return vaddr;
}

static void fdeion_buffer_kmap_put(struct fdeion_buffer *buffer)
{
    buffer->kmap_cnt--;
    if (!buffer->kmap_cnt)
    {
        buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
    }
}

static struct sg_table *dup_sg_table(struct sg_table *table)
{
    struct sg_table *new_table;
    int ret, i;
    struct scatterlist *sg, *new_sg;

    new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
    if (!new_table)
        return ERR_PTR(-ENOMEM);

    ret = sg_alloc_table(new_table, table->nents, GFP_KERNEL);
    if (ret)
    {
        kfree(new_table);
        return ERR_PTR(-ENOMEM);
    }

    new_sg = new_table->sgl;
    for_each_sg(table->sgl, sg, table->nents, i)
    {
        memcpy(new_sg, sg, sizeof(*sg));
        new_sg->dma_address = 0;
        new_sg = sg_next(new_sg);
    }

    return new_table;
}

static void free_duped_table(struct sg_table *table)
{
    sg_free_table(table);
    kfree(table);
}

struct fdeion_dma_buf_attachment
{
    struct device *dev;
    struct sg_table *table;
    struct list_head list;
};

static int fdeion_dma_buf_attach(struct dma_buf *dmabuf,
                                 struct dma_buf_attachment *attachment)
{
    struct fdeion_dma_buf_attachment *a;
    struct sg_table *table;
    struct fdeion_buffer *buffer = dmabuf->priv;

    a = kzalloc(sizeof(*a), GFP_KERNEL);
    if (!a)
        return -ENOMEM;

    table = dup_sg_table(buffer->sg_table);
    if (IS_ERR(table))
    {
        kfree(a);
        return -ENOMEM;
    }

    a->table = table;
    a->dev = attachment->dev;
    INIT_LIST_HEAD(&a->list);

    attachment->priv = a;

    mutex_lock(&buffer->lock);
    list_add(&a->list, &buffer->attachments);
    mutex_unlock(&buffer->lock);

    return 0;
}

static void fdeion_dma_buf_detatch(struct dma_buf *dmabuf,
                                   struct dma_buf_attachment *attachment)
{
    struct fdeion_dma_buf_attachment *a = attachment->priv;
    struct fdeion_buffer *buffer = dmabuf->priv;

    mutex_lock(&buffer->lock);
    list_del(&a->list);
    mutex_unlock(&buffer->lock);
    free_duped_table(a->table);

    kfree(a);
}

static struct sg_table *fdeion_map_dma_buf(struct dma_buf_attachment *attachment,
                                           enum dma_data_direction direction)
{
    struct fdeion_dma_buf_attachment *a = attachment->priv;
    struct sg_table *table;

    table = a->table;

    if (!dma_map_sg(attachment->dev, table->sgl, table->nents,
                    direction))
        return ERR_PTR(-ENOMEM);

    return table;
}

static void fdeion_unmap_dma_buf(struct dma_buf_attachment *attachment,
                                 struct sg_table *table,
                                 enum dma_data_direction direction)
{
    dma_unmap_sg(attachment->dev, table->sgl, table->nents, direction);
}

static int fdeion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
    struct fdeion_buffer *buffer = dmabuf->priv;
    int ret = 0;

    if (!buffer->heap->ops->map_user)
    {
        pr_err("%s: this heap does not define a method for mapping to userspace\n",
               __func__);
        return -EINVAL;
    }

    if (!(buffer->flags & FDEION_FLAG_CACHED))
        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

    mutex_lock(&buffer->lock);
    /* now map it to userspace */
    ret = buffer->heap->ops->map_user(buffer->heap, buffer, vma);
    mutex_unlock(&buffer->lock);

    if (ret)
        pr_err("%s: failure mapping buffer to userspace\n",
               __func__);

    return ret;
}

static void fdeion_dma_buf_release(struct dma_buf *dmabuf)
{
    struct fdeion_buffer *buffer = dmabuf->priv;

    _fdeion_buffer_destroy(buffer);
}

static void *fdeion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
    struct fdeion_buffer *buffer = dmabuf->priv;

    return buffer->vaddr + offset * PAGE_SIZE;
}

static void fdeion_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
                                  void *ptr)
{
    /* no handle */
}

static int fdeion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
                                           enum dma_data_direction direction)
{
    struct fdeion_buffer *buffer = dmabuf->priv;
    void *vaddr;
    struct fdeion_dma_buf_attachment *a;
    int ret = 0;

    /*
     * TODO: Move this elsewhere because we don't always need a vaddr
     */
    if (buffer->heap->ops->map_kernel)
    {
        mutex_lock(&buffer->lock);
        vaddr = fdeion_buffer_kmap_get(buffer);
        if (IS_ERR(vaddr))
        {
            ret = PTR_ERR(vaddr);
            goto unlock;
        }
        mutex_unlock(&buffer->lock);
    }

    mutex_lock(&buffer->lock);
    list_for_each_entry(a, &buffer->attachments, list)
    {
        dma_sync_sg_for_cpu(a->dev, a->table->sgl, a->table->nents,
                            direction);
    }

unlock:
    mutex_unlock(&buffer->lock);
    return ret;
}

static int fdeion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
                                         enum dma_data_direction direction)
{
    struct fdeion_buffer *buffer = dmabuf->priv;
    struct fdeion_dma_buf_attachment *a;

    if (buffer->heap->ops->map_kernel)
    {
        mutex_lock(&buffer->lock);
        fdeion_buffer_kmap_put(buffer);
        mutex_unlock(&buffer->lock);
    }

    mutex_lock(&buffer->lock);
    list_for_each_entry(a, &buffer->attachments, list)
    {
        dma_sync_sg_for_device(a->dev, a->table->sgl, a->table->nents,
                               direction);
    }
    mutex_unlock(&buffer->lock);

    return 0;
}

static const struct dma_buf_ops dma_buf_ops = {
    .map_dma_buf = fdeion_map_dma_buf,
    .unmap_dma_buf = fdeion_unmap_dma_buf,
    .mmap = fdeion_mmap,
    .release = fdeion_dma_buf_release,
    .attach = fdeion_dma_buf_attach,
    .detach = fdeion_dma_buf_detatch,
    .begin_cpu_access = fdeion_dma_buf_begin_cpu_access,
    .end_cpu_access = fdeion_dma_buf_end_cpu_access,
    .map = fdeion_dma_buf_kmap,
    .unmap = fdeion_dma_buf_kunmap,
};

static int fdeion_alloc(size_t len, unsigned int heap_id_mask, unsigned int flags)
{
    struct fdeion_device *dev = internal_dev;
    struct fdeion_buffer *buffer = NULL;
    struct fdeion_heap *heap;
    DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
    int fd;
    struct dma_buf *dmabuf;

    pr_debug("%s: len %zu heap_id_mask %u flags %x\n", __func__,
             len, heap_id_mask, flags);
    /*
     * traverse the list of heaps available in this system in priority
     * order.  If the heap type is supported by the client, and matches the
     * request of the caller allocate from it.  Repeat until allocate has
     * succeeded or all heaps have been tried
     */
    len = PAGE_ALIGN(len);

    if (!len)
        return -EINVAL;

    down_read(&dev->lock);
    plist_for_each_entry(heap, &dev->heaps, node)
    {
        /* if the caller didn't specify this heap id */
        if (!((1 << heap->id) & heap_id_mask))
            continue;
        buffer = fdeion_buffer_create(heap, dev, len, flags);
        if (!IS_ERR(buffer))
            break;
    }
    up_read(&dev->lock);

    if (!buffer)
        return -ENODEV;

    if (IS_ERR(buffer))
        return PTR_ERR(buffer);

    exp_info.ops = &dma_buf_ops;
    exp_info.size = buffer->size;
    exp_info.flags = O_RDWR;
    exp_info.priv = buffer;

    dmabuf = dma_buf_export(&exp_info);
    if (IS_ERR(dmabuf))
    {
        _fdeion_buffer_destroy(buffer);
        return PTR_ERR(dmabuf);
    }

    fd = dma_buf_fd(dmabuf, O_CLOEXEC);
    if (fd < 0)
        dma_buf_put(dmabuf);

    return fd;
}

static int fdeion_query_heaps(struct fdeion_heap_query *query)
{
    struct fdeion_device *dev = internal_dev;
    struct fdeion_heap_data __user *buffer = u64_to_user_ptr(query->heaps);
    int ret = -EINVAL, cnt = 0, max_cnt;
    struct fdeion_heap *heap;
    struct fdeion_heap_data hdata;

    memset(&hdata, 0, sizeof(hdata));

    down_read(&dev->lock);
    if (!buffer)
    {
        query->cnt = dev->heap_cnt;
        ret = 0;
        goto out;
    }

    if (query->cnt <= 0)
        goto out;

    max_cnt = query->cnt;

    plist_for_each_entry(heap, &dev->heaps, node)
    {
        strncpy(hdata.name, heap->name, MAX_HEAP_NAME);
        hdata.name[sizeof(hdata.name) - 1] = '\0';
        hdata.type = heap->type;
        hdata.heap_id = heap->id;

        if (copy_to_user(&buffer[cnt], &hdata, sizeof(hdata)))
        {
            ret = -EFAULT;
            goto out;
        }

        cnt++;
        if (cnt >= max_cnt)
            break;
    }

    query->cnt = cnt;
    ret = 0;
out:
    up_read(&dev->lock);
    return ret;
}

union fdeion_ioctl_arg
{
    struct fdeion_allocatfdeion_data allocatfdeion;
    struct fdeion_heap_query query;
};

static int validate_ioctl_arg(unsigned int cmd, union fdeion_ioctl_arg *arg)
{
    switch (cmd)
    {
    case FDEION_IOC_HEAP_QUERY:
        if (arg->query.reserved0 ||
            arg->query.reserved1 ||
            arg->query.reserved2)
            return -EINVAL;
        break;
    default:
        break;
    }

    return 0;
}

static long fdeion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    union fdeion_ioctl_arg data;

    if (_IOC_SIZE(cmd) > sizeof(data))
        return -EINVAL;

    /*
     * The copy_from_user is unconditfdeional here for both read and write
     * to do the validate. If there is no write for the ioctl, the
     * buffer is cleared
     */
    if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
        return -EFAULT;

    ret = validate_ioctl_arg(cmd, &data);
    if (ret)
    {
        pr_warn_once("%s: ioctl validate failed\n", __func__);
        return ret;
    }

    if (!(_IOC_DIR(cmd) & _IOC_WRITE))
        memset(&data, 0, sizeof(data));

    switch (cmd)
    {
    case FDEION_IOC_ALLOC:
    {
        int fd;

        fd = fdeion_alloc(data.allocatfdeion.len,
                          data.allocatfdeion.heap_id_mask,
                          data.allocatfdeion.flags);
        if (fd < 0)
            return fd;

        data.allocatfdeion.fd = fd;

        break;
    }
    case FDEION_IOC_HEAP_QUERY:
        ret = fdeion_query_heaps(&data.query);
        break;
    default:
        return -ENOTTY;
    }

    if (_IOC_DIR(cmd) & _IOC_READ)
    {
        if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd)))
            return -EFAULT;
    }
    return ret;
}

static const struct file_operations fdeion_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = fdeion_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = fdeion_ioctl,
#endif
};

static int debug_shrink_set(void *data, u64 val)
{
    struct fdeion_heap *heap = data;
    struct shrink_control sc;
    int objs;

    sc.gfp_mask = GFP_HIGHUSER;
    sc.nr_to_scan = val;

    if (!val)
    {
        objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
        sc.nr_to_scan = objs;
    }

    heap->shrinker.scan_objects(&heap->shrinker, &sc);
    return 0;
}

static int debug_shrink_get(void *data, u64 *val)
{
    struct fdeion_heap *heap = data;
    struct shrink_control sc;
    int objs;

    sc.gfp_mask = GFP_HIGHUSER;
    sc.nr_to_scan = 0;

    objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
    *val = objs;
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_shrink_fops, debug_shrink_get,
                        debug_shrink_set, "%llu\n");

void fdeion_device_add_heap(struct fdeion_heap *heap)
{
    struct fdeion_device *dev = internal_dev;
    int ret;
    struct dentry *heap_root;
    char debug_name[64];

    if (!heap->ops->allocate || !heap->ops->free)
        pr_err("%s: can not add heap with invalid ops struct.\n",
               __func__);

    spin_lock_init(&heap->free_lock);
    spin_lock_init(&heap->stat_lock);
    heap->free_list_size = 0;

    if (heap->flags & FDEION_HEAP_FLAG_DEFER_FREE)
        fdeion_heap_init_deferred_free(heap);

    if ((heap->flags & FDEION_HEAP_FLAG_DEFER_FREE) || heap->ops->shrink)
    {
        ret = fdeion_heap_init_shrinker(heap);
        if (ret)
            pr_err("%s: Failed to register shrinker\n", __func__);
    }

    heap->dev = dev;
    heap->num_of_buffers = 0;
    heap->num_of_alloc_bytes = 0;
    heap->alloc_bytes_wm = 0;

    heap_root = debugfs_create_dir(heap->name, dev->debug_root);
    debugfs_create_u64("num_of_buffers",
                       0444, heap_root,
                       &heap->num_of_buffers);
    debugfs_create_u64("num_of_alloc_bytes",
                       0444,
                       heap_root,
                       &heap->num_of_alloc_bytes);
    debugfs_create_u64("alloc_bytes_wm",
                       0444,
                       heap_root,
                       &heap->alloc_bytes_wm);

    if (heap->shrinker.count_objects &&
        heap->shrinker.scan_objects)
    {
        snprintf(debug_name, 64, "%s_shrink", heap->name);
        debugfs_create_file(debug_name,
                            0644,
                            heap_root,
                            heap,
                            &debug_shrink_fops);
    }

    down_write(&dev->lock);
    heap->id = heap_id++;
    /*
     * use negative heap->id to reverse the priority -- when traversing
     * the list later attempt higher id numbers first
     */
    plist_node_init(&heap->node, -heap->id);
    fde_plist_add(&heap->node, &dev->heaps);

    dev->heap_cnt++;
    up_write(&dev->lock);
}
EXPORT_SYMBOL(fdeion_device_add_heap);

static int fdeion_device_create(void)
{
    struct fdeion_device *idev;
    int ret;

    idev = kzalloc(sizeof(*idev), GFP_KERNEL);
    if (!idev)
        return -ENOMEM;

    idev->dev.minor = MISC_DYNAMIC_MINOR;
    idev->dev.name = "fdeion";
    idev->dev.fops = &fdeion_fops;
    idev->dev.parent = NULL;
    ret = misc_register(&idev->dev);
    if (ret)
    {
        pr_err("fdeion: failed to register misc device.\n");
        kfree(idev);
        return ret;
    }

    idev->debug_root = debugfs_create_dir("fdeion", NULL);
    init_rwsem(&idev->lock);
    plist_head_init(&idev->heaps);
    internal_dev = idev;
    return 0;
}

// subsys_initcall(fdeion_device_create);

int fdeion_add_cma_heaps(void);
int fdeion_system_heap_create(void);
int fdeion_system_contig_heap_create(void);

fde_cma_release_t fde_cma_release = NULL;
fde_plist_add_t fde_plist_add = NULL;
fde_cma_for_each_area_t fde_cma_for_each_area = NULL;
fde_cma_get_name_t fde_cma_get_name = NULL;
fde_cma_alloc_t fde_cma_alloc = NULL;

void fdeion_memory_pool_free(struct x100_display *d, void *vaddr, uint64_t size)
{
    gen_pool_free(d->memory_pool, (unsigned long)vaddr, size);
}

int fdeion_memory_pool_alloc(struct x100_display *d, void **pvaddr,
					phys_addr_t *phys_addr, uint64_t size)
{
    unsigned long vaddr;

    size = PAGE_ALIGN(size);
    vaddr = gen_pool_alloc(d->memory_pool, size);
    if (!vaddr)
        return -ENOMEM;

    *phys_addr = gen_pool_virt_to_phys(d->memory_pool, vaddr);

    *pvaddr = (void *)vaddr;
    return 0;
}

static int __init fdeion_init(void)
{
    int ret;
    /* get pci dc data */
    struct pci_dev *pci;
    struct drm_device *dev;
    struct x100_display *d;
    pci = pci_get_device(x100_vendor, x100_device, NULL);
    if(!pci) {
        printk(KERN_ERR "Failed to get dc pci device!\n");
        return -EFAULT;
    }
    dev  = pci_get_drvdata(pci);
    d = dev->dev_private;
    idis = d;
    pr_debug("memory_pool = %p vram_addr = %p", d->memory_pool, d->b2);

    fde_cma_release = (fde_cma_release_t)(kallsyms_lookup_name("cma_release"));
    if (!fde_cma_release)
    {
        printk(KERN_ERR "Failed to find cma_release function address\n");
        return -EFAULT;
    }

    // 获取 cma_for_each_area
    fde_cma_for_each_area = (fde_cma_for_each_area_t)(kallsyms_lookup_name("cma_for_each_area"));
    if (!fde_cma_for_each_area)
    {
        printk(KERN_ERR "Failed to find cma_for_each_area function address\n");
        return -EFAULT;
    }

    // 获取 plist_add 
    fde_plist_add = (fde_plist_add_t)(kallsyms_lookup_name("plist_add"));
    if (!fde_plist_add)
    {
        printk(KERN_ERR "Failed to find plist_add function address\n");
        return -EFAULT;
    }

    // 获取 cma_get_name
    fde_cma_get_name = (fde_cma_get_name_t)(kallsyms_lookup_name("cma_get_name"));
    if (!fde_cma_get_name)
    {
        printk(KERN_ERR "Failed to find cma_get_name function address\n");
        return -EFAULT;
    }

    // 获取 cma_alloc
    fde_cma_alloc = (fde_cma_alloc_t)(kallsyms_lookup_name("cma_alloc"));
    if (!fde_cma_alloc)
    {
        printk(KERN_ERR "Failed to find cma_alloc function address\n");
        return -EFAULT;
    }


    ret = fdeion_device_create();
    if (ret != 0){
        printk(KERN_ERR "Failed to create fdeion device %d\n", ret);
        return ret;
    }

    fdeion_add_cma_heaps();
    //fdeion_system_heap_create();
    //fdeion_system_contig_heap_create();

    return 0;
}

static void __exit fdeion_exit(void)
{
    misc_deregister(&internal_dev->dev);
    if (internal_dev->debug_root) {
        debugfs_remove_recursive(internal_dev->debug_root);
    }
}

module_init(fdeion_init);
module_exit(fdeion_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenFDE");
MODULE_DESCRIPTION("A fdeion driver for reading/writing page table entries");
MODULE_VERSION("2.1");
