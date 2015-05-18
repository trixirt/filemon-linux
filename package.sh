#!/bin/sh
#
#  Copyright (c) 2013-2105, Juniper Networks, Inc.
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
set -x
set -e

PACKAGE=filemon
# The version needs to be ##.##.##
# Just numbers, no alpha's
VERSION=12.5.9

if [ ! -d /usr/src ]; then
    echo "Expected /usr/src does not exist"
    exit 1
fi
# Delete the old dir
if [ -d /usr/src/${PACKAGE}-${VERSION} ]; then
    sudo rm -rf /usr/src/${PACKAGE}-${VERSION}
fi
# Create a fresh dir
sudo mkdir /usr/src/${PACKAGE}-${VERSION}
D=/usr/src/${PACKAGE}-${VERSION}
sudo chmod 777 ${D}

# Make the dkms.conf file
echo "PACKAGE_VERSION=\"${VERSION}\""             > ${D}/dkms.conf
echo "PACKAGE_NAME=${PACKAGE}"                   >> ${D}/dkms.conf
echo "MAKE[0]=\"make all KVERSION=\$kernelver\"" >> ${D}/dkms.conf
echo "BUILT_MODULE_NAME[0]=${PACKAGE}"           >> ${D}/dkms.conf
echo "DEST_MODULE_LOCATION[0]=\"/extra\""        >> ${D}/dkms.conf
echo "AUTOINSTALL=yes"                           >> ${D}/dkms.conf
# Stage the files
F="Makefile syscalls.c mfilemon.c filemon.h syscalls_ia32.h"
for f in $F; do
    cp $f ${D}/
done

# Test
# cd ${D}
# make
# exit

# Remove old copy
sudo dkms remove -m ${PACKAGE} -v ${VERSION} --all || true

# dkms add
sudo dkms add -m ${PACKAGE} -v ${VERSION}

# build
sudo dkms build -m ${PACKAGE} -v ${VERSION}

# Package
if [ -f /etc/redhat-release ]; then
    # Check if redhat-ish
    sudo dkms mkrpm -m ${PACKAGE} -v ${VERSION} --source-only
    P="/var/lib/dkms/${PACKAGE}/${VERSION}/rpm/${PACKAGE}-${VERSION}-1dkms.noarch.rpm /var/lib/dkms/${PACKAGE}/${VERSION}/rpm/${PACKAGE}-${VERSION}-1dkms.src.rpm"
else
    # Assume debian/ubuntu
    sudo dkms mkdeb -m ${PACKAGE} -v ${VERSION} --source-only
    P=/var/lib/dkms/${PACKAGE}/${VERSION}/deb/${PACKAGE}-dkms_${VERSION}_all.deb
fi

for p in ${P}; do
    if [ ! -f $p ]; then
	echo "Could not find package"
	echo "${p}"
	exit 1
    else
	cp ${p} .
    fi
done

echo ${VERSION}
