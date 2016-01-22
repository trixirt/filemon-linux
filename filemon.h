/*
 * Copyright (c) 2013-2016, Juniper Networks, Inc.
 * All rights reserved.
 *
 * You may distribute under the terms of any of:
 *
 * the BSD 2-Clause license, or
 * the GNU General Public License version 2 only.
 *
 * Any patches released for this software are to be released under these
 * same license terms.
 *
 * BSD 2-Clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * GPL license:
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see
 * https://www.kernel.org/pub/linux/kernel/COPYING
 *
 */
#ifndef FILEMON_H
#define FILEMON_H

/* When making changes to this file, remember that it's shared by both
 * userland and kernel code.  Use #ifdef __KERNEL__ as needed. */

#include <linux/ioctl.h>
#include <linux/posix_types.h>

#ifdef __KERNEL__
/* These macros handle some changes to a few parts of the kernel
 * between versions. */

/* Sometime after 2.6.32, but by 2.6.38, the prototype for
 * register_trace_##name changed: a second parameter, a
 * void *data argument, was added.  This is unrelated to
 * DECLARE_TRACE_NOARGS, but that was added within that same
 * window, so that's what we use to test whether the data argument
 * is required. */
#include <linux/tracepoint.h>
#ifdef DECLARE_TRACE_NOARGS
#define TRACE_CTX_FUNC(...) __VA_ARGS__, NULL
#define TRACE_ARGS(...) void *filemon_trace_args_data __maybe_unused, __VA_ARGS__
#else
#define TRACE_CTX_FUNC(...) __VA_ARGS__
#define TRACE_ARGS(...) __VA_ARGS__
#endif

#endif /* __KERNEL__ */

/* _PATH_FILEMON, FILEMON_SET_FD, and FILEMON_SET_PID are the UI
 * constants defined by NetBSD filemon.  Juniper filemon doesn't
 * set _PATH_FILEMON. */
#define FILEMON_DEVICE_NAME "filemon"
#ifndef _PATH_FILEMON
#define _PATH_FILEMON "/dev/" FILEMON_DEVICE_NAME
#endif

/* NetBSD filemon uses 'S' for its ioctl group, which is used for cdrom
 * ioctls on Linux.  As of this writing, 0xf1 is unused; see
 * Documentation/ioctl/ioctl-number.txt for the list. */
#define FILEMON_IOCTL_GROUP 0xf1
#define FILEMON_SET_FD		_IOW(FILEMON_IOCTL_GROUP, 1, int)
#define FILEMON_SET_PID		_IOW(FILEMON_IOCTL_GROUP, 2, __kernel_pid_t)

/* Juniper filemon defines the FILEMON_VERSION variable to denote the
 * output format.  This implementation is based on Juniper's version 4. */
#define FILEMON_VERSION 4

#ifdef __KERNEL__

#define FILEMON_MAJOR 0		/* Dynamic */
#define FILEMON_MAX_MINORS 1

#include <linux/list.h>

/* Uncomment for debug messages */
/* #define FILEMON_DEBUG */
/* Uncomment to trace system calls */
/* #define FILEMON_TRACE_CALLS */
/* Uncomment to print user's fd to syslog */
/* #define FILEMON_PRINT_USER_FD */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
/*
  commit 9115eac2c788c17b57c9256cb322fa7371972ddf
  Author: Jeff Layton <jlayton@redhat.com>
  Date:   Mon Jan 27 13:33:28 2014 -0500

  vfs: unexport the getname() symbol
    
  Leaving getname() exported when putname() isn't is a bad idea.
  
  Signed-off-by: Jeff Layton <jlayton@redhat.com>
  Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
*/

/* Doing our own thing now.. */
#define FILEMON_GETNAME_TYPE const char *
#define FILEMON_GETNAME(f) _filemon_getname(f)
#define FILEMON_GETNAME_NAME(f) (f)
#define FILEMON_PUTNAME(f) (f)

static inline char * _filemon_getname(const char *ptr) {
  /*
   * There are at most 2 outstanding calls to getname at a time
   * Instead of allocating memory, rotate through the array;
   */
  static unsigned int index;
  static char f[2][PATH_MAX];
  index++;
  index &= 1;
  f[index][0] = '\0';
  strncpy_from_user(f[index], ptr, PATH_MAX);
  return &f[index][0];
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
/*
   commit 91a27b2a756784714e924e5e854b919273082d26
   Author: Jeff Layton <jlayton@redhat.com>
   Date:   Wed Oct 10 15:25:28 2012 -0400

   vfs: define struct filename and have getname() return it

   getname() is intended to copy pathname strings from userspace into a
   kernel buffer. The result is just a string in kernel space. It would
   however be quite helpful to be able to attach some ancillary info to
   the string.

   For instance, we could attach some audit-related info to reduce the
   amount of audit-related processing needed. When auditing is enabled,
   we could also call getname() on the string more than once and not
   need to recopy it from userspace.

   This patchset converts the getname()/putname() interfaces to return
   a struct instead of a string. For now, the struct just tracks the
   string in kernel space and the original userland pointer for it.

   Later, we'll add other information to the struct as it becomes
   convenient.

   struct filename {
   const char *name;		/ * pointer to actual string * /
   const __user char *uptr;	/ * original userland pointer * /
   };
*/
#define FILEMON_GETNAME_TYPE struct filename *
#define FILEMON_GETNAME(f) getname(f)
#define FILEMON_GETNAME_NAME(f) ((f)->name)
/* putname is undefined on 12.04 3.8.0, use __putname instead */
#define FILEMON_PUTNAME(f) __putname(f)
#else
#define FILEMON_GETNAME_TYPE const char *
#define FILEMON_GETNAME(f) getname(f)
#define FILEMON_GETNAME_NAME(f) (f)
#define FILEMON_PUTNAME(f) putname(f)
#endif

struct fm_pids {
	struct pid *pid;
	struct list_head list;
};

struct filemon {
	struct file *of; /* file that opened the device */
	struct file *fp; /* file that stats are written to */
	struct fm_pids *shead;
	struct list_head list;
	void   *write_buf;
	size_t write_buf_size;
	size_t write_buf_used;
	void   *msg_buf;
};

#define LIST_ADD list_add
#define LIST_DEL list_del

void __printf(2, 3) filemon_printf(struct filemon *fm, const char *fmt, ...);
void syscall_enter(struct filemon *fm, struct pt_regs *regs, long id);
void syscall_exit(struct filemon *fm, struct pt_regs *regs, long id);
int syscall_enter_check(struct pt_regs *regs);
int syscall_exit_check(struct pt_regs *regs);

#define FILEMON_PERFORMANCE_NO_STAT
#define FILEMON_PERFORMANCE_NO_FORK_FM
#ifdef FILEMON_PERFORMANCE_NO_FORK_FM
#define FILEMON_PERFORMANCE_RW_LOCK
#endif /* FILEMON_PERFORMANCE_NO_FORK_FM */

/*
 * The use of RW lock may be the cause of
 * a difficult to reproduce hang.  For now
 * disable its use.
 */
#undef FILEMON_PERFORMANCE_RW_LOCK

#endif /* __KERNEL__ */
#endif
