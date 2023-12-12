#ifndef __X100_DISPLAY_DRV_H__
#define __X100_DISPLAY_DRV_H__

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#include <drm/drmP.h>
#endif
#include <drm/drm_print.h>
#include <drm/drm_fb_helper.h>

#define DEBUG_LOG 0


enum x100_mem_state_type {
	X100_MEM_VRAM_TOTAL = 0,
	X100_MEM_VRAM_ALLOC,
	X100_MEM_SYSTEM_CARVEOUT_TOTAL,
	X100_MEM_SYSTEM_CARVEOUT_ALLOC,
	X100_MEM_SYSTEM_UNIFIED_ALLOC,
	X100_MEM_STATE_TYPE_COUNT,
};

struct rese {
	unsigned char preserved[5];
	unsigned int reserved[4];
	unsigned long areserved;
};

struct x100_display {
	void __iomem *r[2];
	struct rese in;
	char st;
	char reserve[3];
	uint32_t unknown_b[13];

	struct drm_device *dev;
	int re;

	struct drm_fb_helper fbdev_helper;
	struct x100_gem_object *fbdev_x100_gem;

	int sg[3];
	struct list_head gem_list_head;

	struct work_struct hounkown_work;
	spinlock_t hounknown_lock;

	void (*v)(struct x100_display *d);

	void (*sunknown)(struct drm_device *dev);
	int (*suunknown[2])(struct drm_device *dev);

	void (*cunknown)(struct x100_display *d, uint32_t phys_pipe);
	int (*chunknown)(const struct drm_mode_fb_cmd2 *mode_cmd, int count);

	struct gen_pool *memory_pool;
	resource_size_t pu[2];
	void *pr;
	uint64_t mem_state[X100_MEM_STATE_TYPE_COUNT];
};



#endif /* __X100_DISPLAY_DRV_H__ */
