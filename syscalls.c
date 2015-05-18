/*
 * Copyright (c) 2013-2014, Juniper Networks, Inc.
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
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <trace/events/syscalls.h>

#include <asm/unistd.h>		/* For syscall numbers */

#include "filemon.h"
#ifdef CONFIG_X86_64
/* A map of 32 bit to 64 calls */
#include "syscalls_ia32.h"
#endif

#ifdef DEFINE_SEMAPHORE
#define FILEMON_MUTEX(x) DEFINE_SEMAPHORE(x)
#else
#define FILEMON_MUTEX(x) DECLARE_MUTEX(x)
#endif

/* Most of this file consists of functions to extract the appropriate
 * arguments from a system call and log them.
 *
 * A typical example:
 *   handle_name_arg(struct filemon *filemon, char op, is_at_enum is_at,
 *                   struct pt_regs *regs)
 *
 * This expects the system call to have a single filename argument as
 * the first argument (second if is_at is set; see below).  The "op"
 * argument is the character to use to mark the operation.  For
 * example, when handle_name_arg is called for a chdir the op is C,
 * for stat it's S, and for unlink it's D.
 *
 * Similar functions exist for system calls that take two filename
 * arguments or one integer argument.  Special-purpose functions exist
 * to handle a few things like open and clone that require more
 * processing.
 */

/* is_at_enum is used to distinguish between foo and fooat.
 *
 * is_at_false means the foo() system call was used.
 *
 * is_at_true means that fooat() was used.  In NetBSD and Juniper
 * filemon, fooat isn't logged (except linkat; read below).  However,
 * in Linux, some system calls are changed from foo to fooat (with
 * AT_FDCWD) in glibc.  Since the filemon API doesn't have a format to
 * log fooat system calls, then fooat will get logged if the fd
 * argument is AT_FDCWD, and not otherwise.
 *
 * is_at_ignore means log without considering the fd argument.  This
 * is how Juniper filemon logs linkat: the fd argument isn't logged,
 * but the filename parameters are logged regardless of their values.
 * (Note that is_at_ignore is only implemented for handle_2name_arg.)
 */
typedef enum { is_at_false = 0, is_at_true, is_at_ignore } is_at_enum;

/* Note: Useful file to check arguments to filesystem syscalls:
 * /usr/src/linux/fs/read_write.c */

/* filemon_log: Log an operation through the given filemon.
 *
 * "op" is the code that indicates the type of operation (for
 * instance, 'W' if a file is opened for writing).  The remainder is
 * as with printf.  Note that fmt must be a constant.
 */
/* This is implemented as a macro instead of a function so that the
 * format string can be computed at compile-time and still properly
 * argument-checked by the compile. */
#define FL_GET_PID_NR (task_pid_nr (current))
#define FL_GUARD_0_PID (pid_nr != 0)

#define filemon_log(filemon, op, fmt, ...)				\
	do {								\
		int pid_nr = FL_GET_PID_NR;				\
		if (FL_GUARD_0_PID)					\
			filemon_printf(filemon, "%c %i " fmt,		\
				       op, pid_nr, __VA_ARGS__);	\
	} while (0)

static long _fm_syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	long ret = -1;
#ifdef CONFIG_X86_64
	/* Check if this is a 32 bit process running on 64 bit kernel */
	int ia32 = test_tsk_thread_flag(task, TIF_IA32);
	if (ia32) {
		long ia32_id = syscall_get_nr(task, regs);
		if (ia32_id >= 0 && ia32_id < FILEMON_SYSCALLS_IA32_SIZE)
			ret = _ia32_to_syscall_map[ia32_id];
	} else {
		ret = syscall_get_nr(task, regs);
	}
#else
	ret = syscall_get_nr(task, regs);
#endif
	return ret;
}

/* Log an open(2) system call. */
static void
handle_open(struct filemon *filemon,
	    char op __maybe_unused, /* We substitute 'R', 'W', or both */
	    is_at_enum is_at,
	    struct pt_regs *regs)
{
	struct {
		union {
			int val;
			unsigned long padding;
		} dirfd;
		union {
			const char * __user val;
			unsigned long padding;
		} ufname;
		unsigned long flags;
	} args = { { 0 }, { 0 } };

	FILEMON_GETNAME_TYPE fname;
	int accmode;

	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      is_at ? 3 : 2, /* number of args */
			      ((unsigned long *)&args) + (is_at ? 0 : 1));
	if (is_at && args.dirfd.val != AT_FDCWD)
		return;
	fname = FILEMON_GETNAME(args.ufname.val);
	if (IS_ERR(fname)) {
#ifdef FILEMON_DEBUG
		printk(KERN_WARNING "filemon: can't happen: bad but acceptable filename at %p: (WR:errno: %li)\n",
		       args.ufname.val, PTR_ERR(fname));
#endif
		return;
	}
	accmode = (args.flags & O_ACCMODE);
	/* Changed in filemon log format 4: a file opened read/write emits
	 * two lines. */
	if (accmode == O_RDONLY || accmode == O_RDWR)
		filemon_log(filemon, 'R', "%s",
			    FILEMON_GETNAME_NAME(fname) ? FILEMON_GETNAME_NAME(fname) :
			    "null");
	if (accmode == O_WRONLY || accmode == O_RDWR)
		filemon_log(filemon, 'W', "%s",
			    FILEMON_GETNAME_NAME(fname) ? FILEMON_GETNAME_NAME(fname) :
			    "null");

	FILEMON_PUTNAME(fname);
}

/* Log a system call that takes one integer as its first argument
 * (or second, if is_at is set). */
static void
handle_int_arg(struct filemon *filemon, char op, is_at_enum is_at,
	       struct pt_regs *regs)
{
	struct {
		union {
			int val;
			unsigned long padding;
		} dirfd;
		union {
			long val;
			unsigned long padding;
		} arg;
	} args = { { 0 }, { 0 } };

	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      is_at ? 2 : 1, /* number of args */
			      ((unsigned long *)&args) + (is_at ? 0 : 1));
	if (is_at && args.dirfd.val != AT_FDCWD)
		return;
	filemon_log(filemon, op, "%li", args.arg.val);
}

static void
handle_exit(struct filemon *fm, char op, is_at_enum is_at,
	    struct pt_regs *regs)
{
	/*
	 * Break out exit here because it is important
	 * sometimes to know when a process is finishing
	 */
	handle_int_arg(fm, op, is_at, regs);
}

/* Log a system call that takes one filename as its first argument
 * (or second, if is_at is set). */
static void
handle_name_arg(struct filemon *filemon, char op, is_at_enum is_at,
		struct pt_regs *regs)
{
	struct {
		union {
			int val;
			unsigned long padding;
		} dirfd;
		union {
			const char * __user val;
			unsigned long padding;
		} ufname;
	} args = { { 0 }, { 0 } };
	FILEMON_GETNAME_TYPE fname;

	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      is_at ? 2 : 1, /* number of args */
			      ((unsigned long *)&args) + (is_at ? 0 : 1));
	if (is_at && args.dirfd.val != AT_FDCWD)
		return;
	fname = FILEMON_GETNAME(args.ufname.val);
	if (IS_ERR(fname)) {
#ifdef FILEMON_DEBUG
		printk(KERN_WARNING "filemon: bad but acceptable filename?(%c:errno: %li)\n",
		       op, PTR_ERR(fname));
#endif
		return;
	}
	filemon_log(filemon, op, "%s",
		    FILEMON_GETNAME_NAME(fname) ? FILEMON_GETNAME_NAME(fname) :
		    "null");
	FILEMON_PUTNAME(fname);
}

/* Log a system call that takes two filenames as its first two arguments
 * (or second and fourth arguments, if is_at is set). */
static void
handle_2name_arg(struct filemon *filemon, char op, is_at_enum is_at,
		 struct pt_regs *regs)
{
	union {
		int intval;
		const char * __user charval;
		unsigned long padding;
	} args[4] = { { 0 }, { 0 }, { 0 }, { 0 } };
	FILEMON_GETNAME_TYPE fnames[2];

	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      is_at ? 4 : 2, /* number of args */
			      (unsigned long *)&args);
	switch (is_at) {
	case is_at_true:
		/* In NetBSD filemon, linkat doesn't get logged.  In Juniper
		 * filemon, it gets logged just as link, without regard to the
		 * fd args.  We adopt the Juniper behavior. */
		if (args[0].intval != AT_FDCWD)
			return;
		if (args[2].intval != AT_FDCWD)
			return;
		/* FALLTHRU */
	case is_at_ignore:
		fnames[0] = FILEMON_GETNAME(args[1].charval);
		fnames[1] = FILEMON_GETNAME(args[3].charval);
		break;
	case is_at_false:
		fnames[0] = FILEMON_GETNAME(args[0].charval);
		fnames[1] = FILEMON_GETNAME(args[1].charval);
		break;
	default:
		BUG();
	}

	if (IS_ERR(fnames[0]) || IS_ERR(fnames[1])) {
#ifdef FILEMON_DEBUG
		printk(KERN_WARNING "filemon: bad but acceptable filename? (%c:errno: %li/%li)\n",
		       op, PTR_ERR(fnames[0]), PTR_ERR(fnames[1]));
#endif
		return;
	}
	filemon_log(filemon, op, "'%s' '%s'",
		    FILEMON_GETNAME_NAME(fnames[0]) ?
		    FILEMON_GETNAME_NAME(fnames[0]) :
		    "null",
		    FILEMON_GETNAME_NAME(fnames[1]) ?
		    FILEMON_GETNAME_NAME(fnames[1]) :
		    "null");
	FILEMON_PUTNAME(fnames[0]);
	FILEMON_PUTNAME(fnames[1]);
}

/* Log a fork system call.
 *
 * This will log the return value, but only if it's not 0 (i.e., is in
 * the parent). */
static void
handle_fork(struct filemon *fm, char op,
	    is_at_enum is_at __maybe_unused, struct pt_regs *regs)
{
#ifndef FILEMON_PERFORMANCE_NO_FORK_FM
	struct pid *pid;
#endif
	int scrv;
	scrv = syscall_get_return_value(current, regs);
	if (scrv == 0)		/* The < 0 case was already handled. */
		return;
	filemon_log(fm, op, "%i", scrv);

#ifndef FILEMON_PERFORMANCE_NO_FORK_FM
	/* List is already locked */
	pid = find_get_pid(scrv);
	if (pid >= 0) {
		struct fm_pids *s;
		s = kmalloc(sizeof(struct fm_pids), GFP_KERNEL);
		if (s) {
			s->pid = pid;
			LIST_ADD(&s->list, &fm->shead->list);
		}
	}
#endif
}

/* Handle symlinkat.
 *
 * This differs from handle_2name_arg in that the latter expects there
 * to be to fd arguments for both filenames, while symlink only has
 * one fd argument.
 */
static void
handle_symlinkat(struct filemon *filemon, char op,
		 is_at_enum is_at __maybe_unused, struct pt_regs *regs)
{
	union {
		int intval;
		const char * __user charval;
		unsigned long padding;
	} args[3] = { { 0 }, { 0 }, { 0 } };
	FILEMON_GETNAME_TYPE fnames[2];

	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      3, /* number of args */
			      (unsigned long *)&args);
	if (args[1].intval != AT_FDCWD)
		return;
	fnames[0] = FILEMON_GETNAME(args[0].charval);
	fnames[1] = FILEMON_GETNAME(args[2].charval);

	if (IS_ERR(fnames[0]) || IS_ERR(fnames[1])) {
#ifdef FILEMON_DEBUG
		printk(KERN_WARNING "filemon: bad but acceptable filename? (%c:errno: %li/%li)\n",
		       op, PTR_ERR(fnames[0]), PTR_ERR(fnames[1]));
#endif
		return;
	}
	filemon_log(filemon, op, "'%s' '%s'",
		    FILEMON_GETNAME_NAME(fnames[0]) ?
		    FILEMON_GETNAME_NAME(fnames[0]) :
		    "null",
		    FILEMON_GETNAME_NAME(fnames[1]) ?
		    FILEMON_GETNAME_NAME(fnames[1]) :
		    "null");
	FILEMON_PUTNAME(fnames[0]);
	FILEMON_PUTNAME(fnames[1]);
}

/* Regarding exec:
 *
 * We can't get argv[0] from syscall_get_arguments at system call
 * exit, since the user memory has been replaced by this point.  But
 * we need to verify that the execve succeeds before we log it.
 * Here's some ways we can deal with this.
 *
 * 1. On system call entry, squirrel away the filename.  (This is the
 * typical way dtrace users handle it.)  This needs to be held
 * per-thread (or at least per-process), so there's some work to be
 * done there.
 *
 * 2. Pull out argv[0] from the now-initialized process.
 *
 * 2.1. When the ELF handler sets up a process, it puts argc, argv,
 * and envp on the stack, so we could read off the top of the stack.
 * However, in some formats, that's not the case: in the flat
 * executable format it's optional, in the script format it gets
 * replaced with the interpreter, and in the misc formats it depends
 * on the handler.
 *
 * 2.2. On the x86, ecx points to argv.  Of course, this is
 * architecture-specific.
 *
 * 3. Get the executable and use its filename.  This is how procfs
 * handles it.  Getting the executable is an interesting problem, and
 * it may have been deleted, renamed, etc. by the time we're called.
 * It's not as big of a problem here as it is in procfs, since ld.so
 * hasn't started yet to map in a lot of other executable bits, but
 * it's still a bit unreliable, and doesn't work with scripts.
 *
 * We currently choose option 1.  It's the most complicated
 * implementation, but it's also the most robust.
 */
struct exec_data {
	struct task_struct *task;
	FILEMON_GETNAME_TYPE argv0;
	struct list_head linkage;
};
static LIST_HEAD(exec_data_list);
static FILEMON_MUTEX(exec_data_mutex);

/* Handle the entry side of execve: log the exec to exec_data_list. */
static void
handle_execve_enter(struct filemon *filemon __maybe_unused,
		    char op __maybe_unused,
		    is_at_enum is_at,
		    struct pt_regs *regs)
{
	struct {
		union {
			int val;
			unsigned long padding;
		} dirfd;
		union {
			const char * __user val;
			unsigned long padding;
		} ufname;
	} args = { { 0 }, { 0 } };
	struct exec_data *entry;
	int down_rv;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		/* We can't save the data.  It's unlikely that the syscall will
		 * succeed, if we can't allocate a few words. */
		return;
	entry->task = current;
	syscall_get_arguments(current, regs,
			      0, /* first argument number to get */
			      is_at ? 2 : 1, /* number of args */
			      ((unsigned long *)&args) + (is_at ? 0 : 1));
	entry->argv0 = FILEMON_GETNAME(args.ufname.val);
	/* At this stage, argv0 might be an error code.  That's ok.  We'll
	 * put it on the list, so in case do_execve returns success, we
	 * can log an error. */

	down_rv = down_interruptible(&exec_data_mutex);
	if (down_rv == 0) {
		list_add(&(entry->linkage), &exec_data_list);
		up(&exec_data_mutex);
	} else {
		/* We got a signal.  If the remainder of the syscall handler
		 * will notice this and aborts the syscall, then that's fine;
		 * we didn't need a log entry.  If it doesn't notice, we'll be
		 * missing a log entry, and that's sad.  But we can't do
		 * anything about it at this point anyway. */
		kfree(entry);
	}
}

/* Handle the exit side of execve: remove the entry from
 * exec_data_list, and log if necessary.
 *
 * FIXME Make sure that the entry is removed, even if the process is
 * no longer being monitored.  This can be done by cleaning out the
 * entries when a filemon is destroyed (be sure to check the filemon
 * not the pid).  We could also keep the filemon in task_data, and
 * call handle_execve_exit on ALL execve returns, but that's rather
 * complicated.
 */
static void
handle_execve_exit(struct filemon *fm,
		   char op,
		   is_at_enum is_at __maybe_unused,
		   struct pt_regs *regs)
{
	int scrv;
	struct list_head *pos;
	struct exec_data *found_entry;
	FILEMON_GETNAME_TYPE argv0;

	/* It'd be nice to be able to use down_interruptable, but what
	 * would we do in the case of EINTR? */
	down(&exec_data_mutex);
	found_entry = NULL;
	list_for_each(pos, &exec_data_list) {
		struct exec_data *find_entry =
			list_entry(pos, struct exec_data, linkage);
		if (find_entry->task == current) {
			found_entry = find_entry;
			break;
		}
	}
	if (found_entry == NULL) {
		/* This can happen if a process starts its monitoring between
		 * when exec is called, and when it returns.  In that case,
		 * the monitoring process isn't safe against that race in the
		 * first place, so it's ok to not log this. */
		up(&exec_data_mutex);
		return;
	}
	list_del(&(found_entry->linkage));
	up(&exec_data_mutex);

	argv0 = found_entry->argv0;
	kfree(found_entry);
	scrv = syscall_get_return_value(current, regs);
	if (scrv == 0) {
		if (IS_ERR(argv0)) {
#ifdef FILEMON_DEBUG
			printk(KERN_WARNING "filemon: bad but acceptable filename? (E:errno: %li)\n",
			       PTR_ERR(found_entry->argv0));
#endif
		} else {
			filemon_log(fm, op, "%s",
				    FILEMON_GETNAME_NAME(argv0) ? FILEMON_GETNAME_NAME(argv0) :
				    "null");
		}
	}
	if (!IS_ERR(argv0)) {
		FILEMON_PUTNAME(argv0);
	}
}

/* Log a clone system call.
 *
 * The filemon API doesn't have a way to transmit information about
 * CLONE_FILES, CLONE_FS, CLONE_THREAD, CLONE_PID, or clone.  We fake
 * it by acting like either a fork or no-op in the common cases.  (We
 * can't just ignore it, since later glibc implemements fork by
 * calling clone.)
 *
 * In particular, we can look at the clone flags.  Here's how they're set:
 *   fork: SIGCHLD (kernel 2.6.32)
 *   vfork: CLONE_VFORK | CLONE_VM | SIGCHLD (kernel 2.6.32)
 *   pthread_create: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
 *                   CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID |
 *                   CLONE_CHILD_CLEARTID | CLONE_SYSVSEM | CLONE_DETACHED
 *                   (GNU glibc 2.14, Debian eglibc 2.11.2)
 *     Note that pthread_create only sometimes sets CLONE_DETACHED,
 *     depending on its availability on the system.  (It was removed
 *     in 2.6.mumble.)  Also note (if you're reading the glibc
 *     sources) that CLONE_SIGNAL is #define'd (in the .c file) as
 *     CLONE_SIGHAND | CLONE_THREAD.
 *
 * The above is for reference.  In this implementation, handle_clone
 * looks at what can be TREATED as a fork for filemon purposes,
 * instead of what was CALLED as one.  That makes it a bit more robust
 * to changes.
 */
static void
handle_clone(struct filemon *fm,
	     char op __maybe_unused,
	     is_at_enum is_at __maybe_unused,
	     struct pt_regs *regs)
{
#ifndef FILEMON_PERFORMANCE_NO_FORK_FM
	struct pid *pid;
#endif
	int scrv;
	scrv = syscall_get_return_value(current, regs);
	if (scrv == 0)		/* The < 0 case was already handled. */
		return;
	filemon_log(fm, op, "%i", scrv);
#ifndef FILEMON_PERFORMANCE_NO_FORK_FM
	/* List is already locked */
	pid = find_get_pid(scrv);
	if (pid >= 0) {
		struct fm_pids *s;
		s = kmalloc(sizeof(struct fm_pids), GFP_KERNEL);
		if (s) {
			s->pid = pid;
			LIST_ADD(&s->list, &fm->shead->list);
		}
	}
#endif
}

/* Used to pass around information pertaining to a system call through
 * the filemon iterator. */
struct syscall_data {
	char op;
	is_at_enum is_at;
	struct pt_regs *regs;
	void (*fn)(struct filemon *filemon, char op, is_at_enum is_at,
		   struct pt_regs *regs);
};

/* The callback to unpack the syscall_data structure to call a
 * handle_* function more conveniently. */
static void
syscall_callback(struct filemon *filemon, void *void_data)
{
	struct syscall_data *data = void_data;
#ifdef FILEMON_TRACE_CALLS
	printk(KERN_DEBUG "Found op %c (%pS, %i) on filemon %p regs %p",
	       data->op == 0 ? '_' : data->op, data->fn, data->is_at,
	       filemon, data->regs);
#endif
	data->fn(filemon, data->op, data->is_at, data->regs);
}

#define ENTER_CHECK_SIZE 256
static int _enter_check[ENTER_CHECK_SIZE] = {
	[__NR_execve] = 1,
	[__NR_exit] = 1,
	[__NR_exit_group] = 1,
};
int
syscall_enter_check(struct pt_regs *regs) {
	int ret = 0;
	long i = _fm_syscall_get_nr(current, regs);
	if (0 <= i && i < ENTER_CHECK_SIZE && _enter_check[i])
		ret = 1;
	return 1;
}

/*
 * id : The syscall number.
 */
void
syscall_enter(struct filemon *fm, struct pt_regs *regs, long id)
{
	struct syscall_data data = { .op = 0,
				     .is_at = false,
				     .regs = regs,
				     .fn = NULL
	};
	switch (_fm_syscall_get_nr(current, regs)) {
	case __NR_execve:		/* E pid name */
		/* On entry, we need it to store argv[0] so we can test
		 * success or failure on exit, and log it. */
		data.op = 'E';
		data.fn = handle_execve_enter;
		break;
	case __NR_exit:		/* X pid exitval */
	case __NR_exit_group:	/* X pid exitval */
		/* Can't fail, and doesn't return, so log it on entry. */
		data.op = 'X';
		data.fn = handle_exit;
		break;
	default:
	    return;
	}
	BUG_ON(data.fn == NULL);
	syscall_callback(fm, &data);
}

/* blame __NR_stat64 = 1038 */
#define EXIT_CHECK_SIZE 1040
static int _exit_check[EXIT_CHECK_SIZE] = {
	[__NR_openat] = 1,
	[__NR_open] = 1,
	[__NR_chdir] = 1,
	[__NR_execve] = 1,
/*
 * stat and similar account for about 1/4 of output in typical compile
 * This data is less important that file open and file reads
 */
#ifndef FILEMON_PERFORMANCE_NO_STAT
#ifdef __NR_oldstat
	[__NR_oldstat] = 1,
#endif
#ifdef __NR_stat64
	[__NR_stat64] = 1,
#endif
	[__NR_stat] = 1,
#endif /* FILEMON_PERFORMANCE_NO_STAT */
	[__NR_unlinkat] = 1,
	[__NR_unlink] = 1,
	[__NR_fork] = 1,
	[__NR_vfork] = 1,
	[__NR_clone] = 1,
	[__NR_renameat] = 1,
	[__NR_rename] = 1,
	[__NR_linkat] = 1,
	[__NR_link] = 1,
	[__NR_symlink] = 1,
	[__NR_symlinkat] = 1,
};
int
syscall_exit_check(struct pt_regs *regs) {
	int ret = 0;
	long i = _fm_syscall_get_nr(current, regs);
	if (0 <= i && i < EXIT_CHECK_SIZE && _exit_check[i])
		ret = 1;
	return ret;
}

/* We hook on the exit so we can see the return value and skip errors.
 * Note that most system call trace facilities don't provide access to
 * the arguments on exit.  The system calls we hook into leave user
 * memory alone, and won't mess with the registers, so the arguments
 * are still fine. */
void
syscall_exit(struct filemon *fm, struct pt_regs *regs, long id)
{
	struct syscall_data data = { .op = 0,
				     .is_at = is_at_false,
				     .regs = regs,
				     .fn = NULL
	};
	/* Fast path return: don't even search the filemon tree for failed
	 * calls (except execve, which may need to do some cleanup). */
	if (syscall_get_return_value(current, regs) < 0 &&
	    _fm_syscall_get_nr(current, regs) != __NR_execve)
		return;

	/* Slightly slower path: don't search the filemon tree unless it's
	 * a call we're logging. */
	switch (_fm_syscall_get_nr(current, regs)) {
	case __NR_openat:		/* [WR] pid fname */
		data.is_at = is_at_true;
		/* FALLTHRU */
	case __NR_open:		/* [WR] pid fname */
		/* This will ignore the op, and set it based on the flags. */
		data.fn = handle_open;
		break;
	case __NR_chdir:		/* C pid name */
		data.op = 'C';
		data.fn = handle_name_arg;
		break;
	case __NR_execve:		/* E pid name */
		data.op = 'E';
		data.fn = handle_execve_exit;
		break;
#ifdef __NR_oldstat		/* Not on new arches, e.g. x86_64 */
	case __NR_oldstat:		/* S pid name */
#endif
#ifdef __NR_stat64		/* Not on 64-bit arches, natch */
	case __NR_stat64:		/* S pid name */
#endif
	case __NR_stat:		/* S pid name */
		data.op = 'S';
		data.fn = handle_name_arg;
		break;
	case __NR_unlinkat:		/* D pid name */
		data.is_at = is_at_true;
		/* FALLTHRU */
	case __NR_unlink:		/* D pid name */
		data.op = 'D';
		data.fn = handle_name_arg;
		break;
	case __NR_fork:		/* F pid rv */
	case __NR_vfork:		/* F pid rv */
		data.op = 'F';
		data.fn = handle_fork;
		break;
	case __NR_clone:	/* F pid rv (fork), or nothing (thread) */
		data.op = 'F';
		data.fn = handle_clone;
		break;
	case __NR_renameat:		/* M pid 'name' 'name' */
		data.is_at = is_at_true;
		/* FALLTHRU */
	case __NR_rename:		/* M pid 'name' 'name' */
		data.op = 'M';
		data.fn = handle_2name_arg;
		break;
	case __NR_linkat:		/* L pid 'name' 'name' */
		data.is_at = is_at_ignore;
		/* FALLTHRU */
	case __NR_link:		/* L pid 'name' 'name' */
	case __NR_symlink:		/* L pid 'name' 'name' */
		data.op = 'L';
		data.fn = handle_2name_arg;
		break;
	case __NR_symlinkat:        /* L pid 'name' 'name' */
		data.is_at = is_at_true;
		data.op = 'L';
		data.fn = handle_symlinkat;
		break;

		/* FIXME There's lots of stuff that perhaps should be logged,
		 * but isn't.
		 *
		 * The following are similar to calls that are logged, and
		 * probably can be logged in the existing code:
		 *   *{32,64}, old*
		 *
		 * Most of the remaining calls don't have log formats in the
		 * filemon API.  (A few, such as creat, are similar enough
		 * that they could be logged as other calls.  They aren't
		 * logged in the NetBSD reference code, so aren't logged
		 * here.)
		 *
		 * The NetBSD reference code doesn't log stat, but the version
		 * we use inside Juniper does, as does this version.  None of
		 * these log lstat.
		 *
		 * The following aren't handled, but can alter the
		 * interpretation of future calls:
		 *   chroot, fchdir, clone with certain flags
		 * to make a container
		 * The following can make new file descriptors but are not
		 * logged:
		 *   creat, dup, dup2, dup3 (Linux-specific), fcntl
		 * The following can modify files but aren't logged:
		 *   mknod, chmod, [l]chown, truncate
		 * The following can get file information but aren't logged:
		 *   lstat, access, readlink
		 * The following fall into one or more categories:
		 *   fexecve, *at (some are handled already),
		 *   [l]{list,get,set,remove}xattr (Linux-specific)
		 * The following probably aren't worth logging, even though
		 * they theoretically could generate file dependencies:
		 *   statfs, mount, unmount
		 *
		 * Also, on FreeBSD, consider:
		 *   jail_attach, jail_set, mkfifo[at], chflags,
		 *   extattr_{list,get,set,delete}_{file,link},
		 *   mac_{get,set}_file
		 *
		 * IPC (pipe, socket, shmget, etc) doesn't get logged, but can
		 * still generate dependencies.  Note that LOMAC is designed
		 * to follow information flow already, so may be useful to
		 * base something on.  It's a standard part of FreeBSD as
		 * mac_lomac.  Linux LOMAC is dead, but an MLS system like
		 * SELinux could be used for a similar starting point, or just
		 * the LSM hooks could be used for something totally original.
		 */
		/* FIXME Exactly what is restart_syscall (syscall #0 in
		 * <asm/unistd.h>)?  The manpage is rather unhelpful.  From
		 * what I've found, it doesn't look like it can be a system
		 * call in the return, but I'm not sure.  Also see if it
		 * perturbs the registers. */
	default:
		return;
	}
	/* At this point, we need to search the active list against the
	 * process's ancestors. */
	BUG_ON(data.fn == NULL);
	syscall_callback(fm, &data);
}
