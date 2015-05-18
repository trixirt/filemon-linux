#
#  Copyright (c) 2013-2015, Juniper Networks, Inc.
#  All rights reserved.
#
#  You may distribute under the terms of any of:
# 
#  the BSD 2-Clause license, or
#  the GNU General Public License version 2 only.
# 
#  Any patches released for this software are to be released under these
#  same license terms.
# 
#  BSD 2-Clause license:
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# 
#  GPL license:
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; version 2 only of
#  the License.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see
#  https://www.kernel.org/pub/linux/kernel/COPYING
#

# Run with make V=1 to get verbose output
obj-m += filemon.o
filemon-objs += syscalls.o mfilemon.o

MODFNAME := filemon.ko
KDIR	 := /lib/modules/$(shell uname -r)/build
PWD	 := $(shell pwd)

all: modules

# WARNING
# udev rules dir is distro dependent
# The below rule is only been tested on
# Ubuntu 12.04 i386
udev:
	- sudo rm /lib/udev/rules.d/50-filemon.rules
	sudo touch /lib/udev/rules.d/50-filemon.rules
	sudo chmod 666 /lib/udev/rules.d/50-filemon.rules
	/bin/echo "KERNEL==\"filemon\", MODE=\"0666\"" >> /lib/udev/rules.d/50-filemon.rules
	sudo chmod 644 /lib/udev/rules.d/50-filemon.rules

clean:
	make -C $(KDIR) M=$(PWD) $@
	- sudo rm /lib/udev/rules.d/50-filemon.rules

modules: udev
	make -C $(KDIR) M=$(PWD) $@

load: clean unload modules
	sudo insmod $(MODFNAME)

unload:
	- sudo rmmod $(MODFNAME)

install: all
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

depend:
	rm -f $(depfiles)
	make /dev/null
