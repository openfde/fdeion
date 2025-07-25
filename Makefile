
CURRENT = $(shell uname -r )
KERN_DIR = /lib/modules/$(CURRENT)/build
KERNEL_VERSION_SIMPLE = $(shell uname -r | cut -d'-' -f1)
KERNEL_VERSION = $(shell echo $(KERNEL_VERSION_SIMPLE) | cut -d'.' -f1-3)
$(info KERNEL_VERSION: $(KERNEL_VERSION))
PATCH_VERSION = $(shell echo $(KERNEL_VERSION_SIMPLE) | cut -d'.' -f4)
$(info PATCH_VERSION: $(PATCH_VERSION))
COMPILE_INDEX_UOS = $(shell uname -a | cut -d ' ' -f 4  )
HASH := \#
COMPILE_INDEX = $(shell echo "$(COMPILE_INDEX_UOS)" |awk -F "$(HASH)" '{print $$2}')
$(info COMPILE_INDEX_UOS: $(COMPILE_INDEX))


ifeq ($(KERNEL_VERSION_SIMPLE),4.19.0)
$(info it is uos )
	ifeq ($(shell test $(COMPILE_INDEX) -gt 7020 && echo true),true)
$(info greate than 7020)
		CFLAG = -DNEW_DC
	else
$(info less than and equal  7300)
		CFLAG =
	endif
else ifeq ($(KERNEL_VERSION),5.4.18)
$(info it is kylin os )
	ifeq ($(shell test $(PATCH_VERSION) -ge 125 && echo true),true)
$(info patch number great than 125, define NEW DC)
		CFLAG = -DNEW_DC
	else
$(info patch number less and equal 125)
		CFLAG =
	endif
endif

all:
	make -C $(KERN_DIR) M=`pwd` EXTRA_CFLAGS="$(CFLAG)" modules

clean:
	make -C $(KERN_DIR) M=`pwd` modules clean
	rm -rf modules.order

obj-m += fdeion.o
fdeion-objs := ion_page_pool.o ion_cma_heap.o ion_system_heap.o ion.o ion-ioctl.o ion_heap.o 
