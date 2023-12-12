#!/bin/bash

lspci |grep X100 |grep GPU_DMA 1>/dev/null 2>&1
if [ $? = 0 ];then
	if [ ! -e "/etc/powervr.ini" ];then
		echo '[default]' >> /etc/powervr.ini
	fi
	sudo sed -i "/GLDMA=14/d" /etc/powervr.ini
	sudo sed -i "/\[default\]/a \GLDMA=14" /etc/powervr.ini
	sudo depmod
	sudo modprobe fdeion
	sudo sed -i "/fdeion/d" /etc/modules 1>/dev/null 2>&1
	sudo sed -i '$a \fdeion' /etc/modules
fi	
