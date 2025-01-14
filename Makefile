
CURRENT = $(shell uname -r )
KERN_DIR = /lib/modules/$(CURRENT)/build

all:
	make -C $(KERN_DIR) M=`pwd` modules

clean:
	make -C $(KERN_DIR) M=`pwd` modules clean
	rm -rf modules.order

obj-m += fdeion.o
fdeion-objs := ion.o ion_cma_heap.o ion_heap.o ion_page_pool.o ion_system_heap.o
