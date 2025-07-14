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

struct rese{
       unsigned char a1;
       unsigned char a2;
       unsigned char a3;
       unsigned char a4;
       unsigned char a5;
       bool b1;
       unsigned char b2[2];
       unsigned int b3;
       unsigned int a6;
       unsigned int a7;
       unsigned int a8;
       unsigned int a9;
       unsigned long a10;
       int *hold;
};

struct x100_display {
	void __iomem *b1;
	void __iomem *b2;
	struct rese b3;
	char b4;
	char b5[3];
	uint32_t b6[3];
	uint32_t b7[3];
	uint32_t b8[3];
	uint32_t b9;
	uint32_t b10[3];

	struct drm_device *dev;
	int b11;

	struct drm_fb_helper fbdev_helper;
	struct x100_gem_object *fbdev_x100_gem;

	int b12[3];
	struct list_head gem_list_head;

	struct work_struct b13;
	spinlock_t b14;

	void (*b15)(struct x100_display *d);

	void (*b16)(struct drm_device *dev);
	int (*b17)(struct drm_device *dev);
	int (*b18)(struct drm_device *dev);

	void (*b19)(struct x100_display *d, uint32_t phys_pipe);
	int (*b20)(const struct drm_mode_fb_cmd2 *mode_cmd, int count);

	struct gen_pool *memory_pool;
	resource_size_t b21;
	resource_size_t b22;
	void *b23;
	uint64_t mem_state[X100_MEM_STATE_TYPE_COUNT];
};



#endif /* __X100_DISPLAY_DRV_H__ */
