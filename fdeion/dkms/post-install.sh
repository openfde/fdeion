#!/bin/bash

config_path="/etc/phytivumvr.ini"
lspci |grep X100 |grep GPU_DMA 1>/dev/null 2>&1
if [ $? = 0 ];then
	sudo depmod
	sudo modprobe fdeion
	sudo sed -i "/fdeion/d" /etc/modules 1>/dev/null 2>&1
	sudo sed -i '$a \fdeion' /etc/modules
fi	
