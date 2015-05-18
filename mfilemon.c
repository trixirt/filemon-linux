/*
 * Copyright (c) 2013-2015, Juniper Networks, Inc.
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <trace/syscall.h>
#include <trace/events/syscalls.h>
#include <trace/events/sched.h>
#include <linux/semaphore.h>

#include "filemon.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Rix <trix@juniper.net>");
MODULE_VERSION("12.5.9");

static struct class *filemon_class;
static int filemon_major = -ENODEV;
static struct cdev filemon_cdev;
static struct device *filemon_device;

#ifdef FILEMON_PERFORMANCE_RW_LOCK
#error "RW Lock under analysis as cause of hang, do not use"
static DECLARE_RWSEM(dev_lock);
#define DEV_READ_LOCK()    down_read(&dev_lock)
#define DEV_READ_UNLOCK()  up_read(&dev_lock)
#define DEV_WRITE_LOCK()   down_write(&dev_lock)
#define DEV_WRITE_UNLOCK() up_write(&dev_lock)
#else
static DEFINE_MUTEX(dev_lock);
#define DEV_READ_LOCK() mutex_lock(&dev_lock)
#define DEV_READ_UNLOCK() mutex_unlock(&dev_lock)
#define DEV_WRITE_LOCK() mutex_lock(&dev_lock)
#define DEV_WRITE_UNLOCK() mutex_unlock(&dev_lock)
#define DEV_TRYLOCK() mutex_trylock(&dev_lock)
#endif
static int dev_number_open;

static LIST_HEAD(dev_list);

#define MSG_BUF_SIZE 4096
/* What to limp along with */
#define STACK_MSG_BUF_SIZE 512
/*
 * BUF_SIZE
 * Determines the size of the write buffer, that accumulates writes
 *
 * 128k causing memory allocation errors when 100+ filemon's active
 * Reduce BUF_SIZE to just 8k.  Anything above 1k should be an
 * exceptionally large message.
 */
#define WRITE_BUF_SIZE (2 * MSG_BUF_SIZE)

/* Similar to write(2), but called from the kernel. */
static ssize_t
filemon_kernel_write(struct file *file, const char *buf, size_t count)
{
	/* From /usr/src/linux/fs/splice.c; see also Linux Magazine,
	 * "Kernel System Calls" by Alessandro Rubini. */
	mm_segment_t old_fs;
	ssize_t res;
	loff_t pos;

	old_fs = get_fs();
	set_fs(get_ds());
	/* FIXME We don't handle partial writes (such as -EINTR).  Since
	 * we don't lock the filemon, we can't just resume the write at
	 * the point of the interruption, or we'd get interleaved data if
	 * two processes in the same filemon both do a simultaneous write.
	 * (Note that the NetBSD reference implementation also doesn't
	 * protect against partial writes.  It does, however, lock its
	 * filemons.) */
	/* We read and then rewrite the position instead of pointing
	 * vfs_write straight to the f_pos member because that's what the
	 * write syscall does.  Not sure why, though. */
	pos = file->f_pos;
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(file, (const char __user *)buf, count, &pos);
	file->f_pos = pos;
	set_fs(old_fs);

	return res;
}

/* documented in filemon.h */
static void __printf(2, 0)
	filemon_vprintf(struct filemon *fm, const char *fmt, va_list ap)
{
	char fallback_msgbuf[STACK_MSG_BUF_SIZE];
	char *msgbuf;
	size_t msg_buf_size;
	int buflen;

	if (fm->fp == NULL) {
#ifdef FILEMON_DEBUG
		printk(KERN_DEBUG "ERROR %s %d", __func__, __LINE__);
#endif
		return;
	}

	/*
	 * Handle allocation error in write buffer by falling back
	 * on a smaller stack implementation
	 */
	if (fm->msg_buf == NULL) {
		msgbuf = &fallback_msgbuf[0];
		msg_buf_size = STACK_MSG_BUF_SIZE;
	} else {
		msgbuf = (char *)fm->msg_buf;
		msg_buf_size = MSG_BUF_SIZE;
	}

	/*
	 * size is the number size of the buffer to include message
	 * and a null terminator.  return is the number of character
	 * written.  When the size is not enough, the result is
	 * truncated and the null terminator is not written.
	 * Because we always want to concatenate a '\n' to the end of
	 * of message and want it to be null terminated, reserver 2
	 * bytes with - 2.
	 */
	buflen = vscnprintf(&msgbuf[0], msg_buf_size - 2, fmt, ap);

	if (buflen <= 0) {
#ifdef FILEMON_DEBUG
		printk(KERN_DEBUG "ERROR %s %d", __func__, __LINE__);
#endif
	} else {
		ssize_t res;

		/*
		 * Because 2 bytes are reserved, a check is not necessary
		 * to see if buflen is at the end of the buffer.
		 *
		 * Append a newline.
		 * Because memcpy is use below, do not append a null
		 */
		msgbuf[buflen + 0] = '\n';
		buflen++;

		if (fm->write_buf_size - fm->write_buf_used >= buflen) {
			memcpy(fm->write_buf + fm->write_buf_used, &msgbuf[0],
			       buflen);
			fm->write_buf_used += buflen;
		} else {
			if (fm->write_buf_used) {
				/*
				 * filemon_kernel_write uses vfs_write
				 * vfs_write writes a page's worth of
				 * data at a time.  So loop over buffer.
				 */
				ssize_t bytes_to_write = fm->write_buf_used;
				do {
					const char *buf = fm->write_buf +
						(fm->write_buf_used -
						 bytes_to_write);
					res = filemon_kernel_write(
						fm->fp,	buf, bytes_to_write);
					if (res > 0)
						bytes_to_write -= res;
				} while (res > 0);
#ifdef FILEMON_DEBUG
				if (res != 0) {
					printk(KERN_DEBUG "ERROR %s %d : expected to write %ld, wrote %ld",
					       __func__, __LINE__, fm->write_buf_used, fm->write_buf_used - bytes_to_write);
				}
#endif
				fm->write_buf_used = 0;

			}

			if (buflen > fm->write_buf_size) {
				/* Happens if error allocating buf */
				res = filemon_kernel_write(fm->fp, msgbuf,
							   buflen);
#ifdef FILEMON_DEBUG
				if (res != buflen) {
					printk(KERN_DEBUG "ERROR %s %d",
					       __func__, __LINE__);
				}
#endif
			} else {
				/* buf is empty, just memcpy msg into buf */
				memcpy(fm->write_buf, &msgbuf[0], buflen);
				fm->write_buf_used += buflen;
			}
		}
	}
}

/* documented in filemon.h */
void __printf(2, 3)
	filemon_printf(struct filemon *fm, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	filemon_vprintf(fm, fmt, args);
	va_end(args);
}

static void
filemon_header(struct filemon *fm)
{
	struct timespec t;
	pid_t curpid;

	getnstimeofday(&t);

	/* Note that we log "Target pid" as current.  That's in line with
	 * NetBSD filemon. */
	curpid = task_tgid_nr(current);

	filemon_printf(fm,
		       ("# buildmon version %d\n"
			"# Target pid %d\n"
			"# Start %llu.%06llu\n"
			"V %d"),
		       FILEMON_VERSION, curpid,
		       (unsigned long long) t.tv_sec,
		       (unsigned long long) (t.tv_nsec / 1000),
		       FILEMON_VERSION);
}

static void
filemon_footer(struct filemon *fm) {
	struct timespec t;
	getnstimeofday(&t);
	filemon_printf(fm,
		       ("# Stop %llu.%06llu\n"
			"# Bye bye"),
		       (unsigned long long) t.tv_sec,
		       (unsigned long long) (t.tv_nsec / 1000));
}

struct fm_pids *
find_fm_pids(struct list_head *head) {
	struct fm_pids *ret = NULL;
	struct task_struct *gtask = current->group_leader;
	struct list_head *p;
	int done = 0;
	list_for_each(p, head) {
		struct fm_pids *s;
		s = list_entry(p, struct fm_pids, list);
		if (s && s->pid) {
			struct task_struct *try_task;
			do_each_pid_task(s->pid, PIDTYPE_PID, try_task) {
				struct task_struct *try_gtask =
					try_task->group_leader;
				struct task_struct *lgtask = gtask;
				while (1) {
					if (try_gtask == lgtask) {
						ret = s;
						done = 1;
						break;
					} else if (lgtask->parent == NULL) {
						break;
					} else if (lgtask->parent == lgtask) {
						break;
					} else {
						lgtask = lgtask->parent;
						lgtask = lgtask->group_leader;
					}
				}
				if (done)
					break;

			} while_each_pid_task(s->pid, PIDTYPE_PID, try_task);
		}
		if (done)
			break;
	}
	return ret;
}

void
filemon_handle_sys_enter(TRACE_ARGS(struct pt_regs *regs, long id))
{
	struct filemon *fb = NULL;
	struct list_head *p;
	int found = 0;

	if (syscall_enter_check(regs)) {
		DEV_READ_LOCK();
		list_for_each(p, &dev_list) {
			struct filemon *b = list_entry(p, struct filemon, list);
			if (b->fp) {
				struct fm_pids *s = NULL;
				s = find_fm_pids(&b->shead->list);
				if (s) {
					fb = b;
					found = 1;
				}
			}
			if (found)
				break;
		}
		if (found)
			syscall_enter(fb, regs, id);

		DEV_READ_UNLOCK();
	}
}

void
filemon_handle_sys_exit(TRACE_ARGS(struct pt_regs *regs, long id))
{
	struct filemon *fb = NULL;
	struct list_head *p;
	int found = 0;

	if (syscall_exit_check(regs)) {
		DEV_READ_LOCK();
		list_for_each(p, &dev_list) {
			struct filemon *b = list_entry(p, struct filemon, list);
			if (b->fp) {
				struct fm_pids *s = NULL;
				s = find_fm_pids(&b->shead->list);
				if (s) {
					fb = b;
					found = 1;
				}
			}
			if (found)
				break;
		}
		if (found)
			syscall_exit(fb, regs, id);

		DEV_READ_UNLOCK();
	}
}

void
filemon_handle_sched_process_exit(TRACE_ARGS(struct task_struct *task))
{
}

static int
dev_open(struct inode *ino, struct file *fp)
{
	int ret = -1;
	struct filemon *b = NULL;

	DEV_WRITE_LOCK();

	b = kmalloc(sizeof(struct filemon), GFP_KERNEL);
	if (b != NULL) {
		b->of = fp;
		b->fp = NULL;
		b->write_buf_size = 0;
		b->write_buf_used = 0;
		b->msg_buf = NULL;
		/* Allocate the write buffer and the msg buffer together */
		b->write_buf = kmalloc(WRITE_BUF_SIZE + MSG_BUF_SIZE,
				       GFP_KERNEL);

		/*
		 * Testing code
		 * Free the write buffer and set to pointer to NULL
		 * The backup stack based buffer should take over
		 *
		 * Uncomment for the next two lines testing
		 * Testing code start
		 *
		 * kfree(b->write_buf);
		 * b->write_buf = NULL;
		 *
		 * Testing code end
		 */

		if (b->write_buf) {
			b->write_buf_size = WRITE_BUF_SIZE;
			/* msg_buf is at the end of the write buf */
			b->msg_buf = b->write_buf + WRITE_BUF_SIZE;

			b->shead = kmalloc(sizeof(struct fm_pids), GFP_KERNEL);
			if (NULL == b->shead) {
			    kfree(b->write_buf);
			    kfree(b);
			    b = NULL;
			} else {
			    INIT_LIST_HEAD(&b->shead->list);
			    LIST_ADD(&b->list, &dev_list);
			    dev_number_open++;
			    ret = 0;
			}
		} else {
		    kfree(b);
		    b = NULL;
		}
	}
	fp->private_data = b;

	DEV_WRITE_UNLOCK();
	return ret;
}

static int
dev_release(struct inode *ino, struct file *fp)
{
	int ret = -1;
	DEV_WRITE_LOCK();

	if (NULL != fp->private_data) {
		struct filemon *b = fp->private_data;
		struct list_head *p;
		struct list_head *tp;
		int d = 0;
		if (b->fp) {
			filemon_footer(b);
			if (b->write_buf_used)
				filemon_kernel_write(b->fp, b->write_buf,
						     b->write_buf_used);
			fput(b->fp);
		}
		list_for_each_safe(p, tp, &b->shead->list) {
			struct fm_pids *s = list_entry(p, struct fm_pids, list);
			LIST_DEL(p);
			if (s) {
				put_pid(s->pid);
				kfree(s);
				d++;
			}
		}
		LIST_DEL(&b->list);
		kfree(b->shead);
		kfree(b->write_buf);
		kfree(b);
		fp->private_data = NULL;
		dev_number_open--;
		ret = 0;
	}

	DEV_WRITE_UNLOCK();
	return ret;
}

static long
dev_unlocked_ioctl(struct file *fp,
		   unsigned int ioctl_num,
		   unsigned long ioctl_param)
{
	int ret = -1;
	DEV_WRITE_LOCK();

	if (NULL != fp->private_data) {
		struct filemon *b = fp->private_data;
		switch (ioctl_num) {

		case FILEMON_SET_FD:
			if (!b->fp) {
				int fd;
				if (!get_user(fd, (int *)ioctl_param)) {
					struct file *fp;
#ifdef FILEMON_PRINT_USER_FD
					printk(KERN_DEBUG "User fd %d", fd);
#endif
					fp = fget(fd);
					if (fp >= 0) {
						b->fp = fp;
						filemon_header(b);
						ret = 0;
					}
				}
			}
			break;

		case FILEMON_SET_PID:
			if (b->shead) {
				pid_t pid_nr;
				if (!get_user(pid_nr, (int *)ioctl_param)) {
					struct pid *pid;
					pid = find_get_pid(pid_nr);
					if (pid >= 0) {
						struct fm_pids *s;
						s = kmalloc(sizeof(struct fm_pids),
							    GFP_KERNEL);
						if (s) {
							s->pid = pid;
							LIST_ADD(&s->list,
								 &b->shead->list);
							ret = 0;
						}
					}
				}
			}
			break;

		default:
			break;
		}
	}

	DEV_WRITE_UNLOCK();
	return ret;
}

static const struct file_operations
filemon_fops = {
	.unlocked_ioctl = dev_unlocked_ioctl,
	.open           = dev_open,
	.release        = dev_release,
};

/* init / cleanup */

static void filemon_exit(void)
{
	dev_t dev;
	DEV_WRITE_LOCK();

	dev = MKDEV(filemon_major, 0);
	unregister_trace_sys_enter(TRACE_CTX_FUNC(filemon_handle_sys_enter));
	unregister_trace_sys_exit(TRACE_CTX_FUNC(filemon_handle_sys_exit));
	tracepoint_synchronize_unregister();
	device_destroy(filemon_class, dev);
	filemon_device = NULL;
	cdev_del(&filemon_cdev);
	unregister_chrdev_region(dev, FILEMON_MAX_MINORS);
	filemon_major = -ENODEV;
	class_destroy(filemon_class);

	DEV_WRITE_UNLOCK();
}

static int __init filemon_init(void)
{
	int ret = -1;
	dev_t dev;

	filemon_class = class_create(THIS_MODULE, FILEMON_DEVICE_NAME);
	if (IS_ERR(filemon_class)) {
		ret = PTR_ERR(filemon_class);
		printk(KERN_ERR "filemon: can not register filemon class\n");
		goto err_filemon_class;
	}

	ret = alloc_chrdev_region(&dev, 0, FILEMON_MAX_MINORS,
				  FILEMON_DEVICE_NAME);
	if (ret) {
		printk(KERN_ERR "filemon: can not register region\n");
		goto err_alloc_chrdev_region;
	}
	filemon_major = MAJOR(dev);

	cdev_init(&filemon_cdev, &filemon_fops);
	ret = cdev_add(&filemon_cdev, dev, FILEMON_MAX_MINORS);
	if (ret) {
		printk(KERN_ERR "filemon: can not add device\n");
		goto err_cdev_add;
	}

	filemon_device = device_create(filemon_class, NULL, dev, NULL,
				       FILEMON_DEVICE_NAME);
	if (IS_ERR(filemon_device)) {
		ret = PTR_ERR(filemon_device);
		printk(KERN_ERR "filemon: can not create device\n");
		goto err_device_create;
	}

	ret = register_trace_sys_enter(
		TRACE_CTX_FUNC(filemon_handle_sys_enter));
	if (ret != 0) {
		printk(KERN_INFO "filemon error registering sys_enter\n");
		goto err_register_trace_sys_enter;
	}

	ret = register_trace_sys_exit(TRACE_CTX_FUNC(filemon_handle_sys_exit));
	if (ret != 0) {
		printk(KERN_INFO "filemon error registering sys_exit\n");
		goto err_register_trace_sys_exit;

	}

	/* Everything is ok */
#ifdef FILEMON_DEBUG
	printk(KERN_INFO "filemon OK\n");
#endif
	ret = 0;
end:
#ifdef FILEMON_DEBUG
	printk(KERN_INFO "filemon registered device number %i", filemon_major);
#endif
	return ret;

err_register_trace_sys_exit:
	unregister_trace_sys_enter(TRACE_CTX_FUNC(filemon_handle_sys_enter));

err_register_trace_sys_enter:
	device_destroy(filemon_class, dev);
	filemon_device = NULL;

err_device_create:
	cdev_del(&filemon_cdev);

err_cdev_add:
	unregister_chrdev(filemon_major, FILEMON_DEVICE_NAME);
	filemon_major = -ENODEV;

err_alloc_chrdev_region:
	class_destroy(filemon_class);

err_filemon_class:
	goto end;
}

module_init(filemon_init);
module_exit(filemon_exit);
