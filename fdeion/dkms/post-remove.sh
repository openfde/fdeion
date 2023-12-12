#!/bin/bash

lspci |grep X100 |grep GPU_DMA 1>/dev/null 2>&1
if [ $? = 0 ];then
	sudo sed -i "/GLDMA=14/d" /etc/powervr.ini
	sudo sed -i "/fdeion/d" /etc/modules 1>/dev/null 2>&1
fi
