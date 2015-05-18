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
#ifndef _FILEMON_SYSCALLS_IA32_H
#define _FILEMON_SYSCALLS_IA32_H

#define FILEMON_SYSCALLS_IA32_SIZE 349

/* If the names are not exactly the same, just set to -1 */
static long _ia32_to_syscall_map[FILEMON_SYSCALLS_IA32_SIZE] = {
	[0] = __NR_restart_syscall,
	[1] = __NR_exit,
	[2] = __NR_fork,
	[3] = __NR_read,
	[4] = __NR_write,
	[5] = __NR_open,
	[6] = __NR_close,
	[7] = -1, /* __NR_waitpid, */
	[8] = __NR_creat,
	[9] = __NR_link,
	[10] = __NR_unlink,
	[11] = __NR_execve,
	[12] = __NR_chdir,
	[13] = __NR_time,
	[14] = __NR_mknod,
	[15] = __NR_chmod,
	[16] = __NR_lchown,
	[17] = -1, /* __NR_break, */
	[18] = -1, /* __NR_oldstat, */
	[19] = __NR_lseek,
	[20] = __NR_getpid,
	[21] = __NR_mount,
	[22] = -1, /* __NR_umount, */
	[23] = __NR_setuid,
	[24] = __NR_getuid,
	[25] = -1, /* __NR_stime, */
	[26] = __NR_ptrace,
	[27] = __NR_alarm,
	[28] = -1, /* __NR_oldfstat, */
	[29] = __NR_pause,
	[30] = __NR_utime,
	[31] = -1, /* __NR_stty, */
	[32] = -1, /* __NR_gtty, */
	[33] = __NR_access,
	[34] = -1, /* __NR_nice, */
	[35] = -1, /* __NR_ftime, */
	[36] = __NR_sync,
	[37] = __NR_kill,
	[38] = __NR_rename,
	[39] = __NR_mkdir,
	[40] = __NR_rmdir,
	[41] = __NR_dup,
	[42] = __NR_pipe,
	[43] = __NR_times,
	[44] = -1, /* __NR_prof, */
	[45] = __NR_brk,
	[46] = __NR_setgid,
	[47] = __NR_getgid,
	[48] = -1, /* __NR_signal, */
	[49] = __NR_geteuid,
	[50] = __NR_getegid,
	[51] = __NR_acct,
	[52] = __NR_umount2,
	[53] = -1, /* __NR_lock, */
	[54] = __NR_ioctl,
	[55] = __NR_fcntl,
	[56] = -1, /* __NR_mpx, */
	[57] = __NR_setpgid,
	[58] = -1, /* __NR_ulimit, */
	[59] = __NR_execve, /* This is the 64 bit value .. exec start as 64 bit */
	[60] = __NR_umask,
	[61] = __NR_chroot,
	[62] = __NR_ustat,
	[63] = __NR_dup2,
	[64] = __NR_getppid,
	[65] = __NR_getpgrp,
	[66] = __NR_setsid,
	[67] = -1, /* __NR_sigaction, */
	[68] = -1, /* __NR_sgetmask, */
	[69] = -1, /* __NR_ssetmask, */
	[70] = __NR_setreuid,
	[71] = __NR_setregid,
	[72] = -1, /* __NR_sigsuspend, */
	[73] = -1, /* __NR_sigpending, */
	[74] = __NR_sethostname,
	[75] = __NR_setrlimit,
	[76] = __NR_getrlimit,
	[77] = __NR_getrusage,
	[78] = __NR_gettimeofday,
	[79] = __NR_settimeofday,
	[80] = __NR_getgroups,
	[81] = __NR_setgroups,
	[82] = __NR_select,
	[83] = __NR_symlink,
	[84] = -1, /* __NR_oldlstat, */
	[85] = __NR_readlink,
	[86] = __NR_uselib,
	[87] = __NR_swapon,
	[88] = __NR_reboot,
	[89] = -1, /* __NR_readdir, */
	[90] = __NR_mmap,
	[91] = __NR_munmap,
	[92] = __NR_truncate,
	[93] = __NR_ftruncate,
	[94] = __NR_fchmod,
	[95] = __NR_fchown,
	[96] = __NR_getpriority,
	[97] = __NR_setpriority,
	[98] = -1, /* __NR_profil, */
	[99] = __NR_statfs,
	[100] = __NR_fstatfs,
	[101] = __NR_ioperm,
	[102] = -1, /* __NR_socketcall, */
	[103] = __NR_syslog,
	[104] = __NR_setitimer,
	[105] = __NR_getitimer,
	[106] = __NR_stat,
	[107] = __NR_lstat,
	[108] = __NR_fstat,
	[109] = -1, /* __NR_olduname, */
	[110] = __NR_iopl,
	[111] = __NR_vhangup,
	[112] = -1, /* __NR_idle, */
	[113] = -1, /* __NR_vm86old, */
	[114] = __NR_wait4,
	[115] = __NR_swapoff,
	[116] = __NR_sysinfo,
	[117] = -1, /* __NR_ipc, */
	[118] = __NR_fsync,
	[119] = -1, /* __NR_sigreturn, */
	[120] = __NR_clone,
	[121] = __NR_setdomainname,
	[122] = __NR_uname,
	[123] = __NR_modify_ldt,
	[124] = __NR_adjtimex,
	[125] = __NR_mprotect,
	[126] = -1, /* __NR_sigprocmask, */
	[127] = __NR_create_module,
	[128] = __NR_init_module,
	[129] = __NR_delete_module,
	[130] = __NR_get_kernel_syms,
	[131] = __NR_quotactl,
	[132] = __NR_getpgid,
	[133] = __NR_fchdir,
	[134] = -1, /* __NR_bdflush, */
	[135] = __NR_sysfs,
	[136] = __NR_personality,
	[137] = __NR_afs_syscall,
	[138] = __NR_setfsuid,
	[139] = __NR_setfsgid,
	[140] = -1, /* __NR__llseek, */
	[141] = __NR_getdents,
	[142] = -1, /* __NR__newselect, */
	[143] = __NR_flock,
	[144] = __NR_msync,
	[145] = __NR_readv,
	[146] = __NR_writev,
	[147] = __NR_getsid,
	[148] = __NR_fdatasync,
	[149] = __NR__sysctl,
	[150] = __NR_mlock,
	[151] = __NR_munlock,
	[152] = __NR_mlockall,
	[153] = __NR_munlockall,
	[154] = __NR_sched_setparam,
	[155] = __NR_sched_getparam,
	[156] = __NR_sched_setscheduler,
	[157] = __NR_sched_getscheduler,
	[158] = __NR_sched_yield,
	[159] = __NR_sched_get_priority_max,
	[160] = __NR_sched_get_priority_min,
	[161] = __NR_sched_rr_get_interval,
	[162] = __NR_nanosleep,
	[163] = __NR_mremap,
	[164] = __NR_setresuid,
	[165] = __NR_getresuid,
	[166] = -1, /* __NR_vm86, */
	[167] = __NR_query_module,
	[168] = __NR_poll,
	[169] = __NR_nfsservctl,
	[170] = __NR_setresgid,
	[171] = __NR_getresgid,
	[172] = __NR_prctl,
	[173] = __NR_rt_sigreturn,
	[174] = __NR_rt_sigaction,
	[175] = __NR_rt_sigprocmask,
	[176] = __NR_rt_sigpending,
	[177] = __NR_rt_sigtimedwait,
	[178] = __NR_rt_sigqueueinfo,
	[179] = __NR_rt_sigsuspend,
	[180] = __NR_pread64,
	[181] = __NR_pwrite64,
	[182] = __NR_chown,
	[183] = __NR_getcwd,
	[184] = __NR_capget,
	[185] = __NR_capset,
	[186] = __NR_sigaltstack,
	[187] = __NR_sendfile,
	[188] = __NR_getpmsg,
	[189] = __NR_putpmsg,
	[190] = __NR_vfork,
	[191] = -1, /* __NR_ugetrlimit, */
	[192] = -1, /* __NR_mmap2, */
	[193] = -1, /* __NR_truncate64, */
	[194] = -1, /* __NR_ftruncate64, */
	[195] = -1, /* __NR_stat64, */
	[196] = -1, /* __NR_lstat64, */
	[197] = -1, /* __NR_fstat64, */
	[198] = -1, /* __NR_lchown32, */
	[199] = -1, /* __NR_getuid32, */
	[200] = -1, /* __NR_getgid32, */
	[201] = -1, /* __NR_geteuid32, */
	[202] = -1, /* __NR_getegid32, */
	[203] = -1, /* __NR_setreuid32, */
	[204] = -1, /* __NR_setregid32, */
	[205] = -1, /* __NR_getgroups32, */
	[206] = -1, /* __NR_setgroups32, */
	[207] = -1, /* __NR_fchown32, */
	[208] = -1, /* __NR_setresuid32, */
	[209] = -1, /* __NR_getresuid32, */
	[210] = -1, /* __NR_setresgid32, */
	[211] = -1, /* __NR_getresgid32, */
	[212] = -1, /* __NR_chown32, */
	[213] = -1, /* __NR_setuid32, */
	[214] = -1, /* __NR_setgid32, */
	[215] = -1, /* __NR_setfsuid32, */
	[216] = -1, /* __NR_setfsgid32, */
	[217] = __NR_pivot_root,
	[218] = __NR_mincore,
	[219] = __NR_madvise,
	[219] = -1, /* __NR_madvise1, */
	[220] = __NR_getdents64,
	[221] = -1, /* __NR_fcntl64, */
	[224] = __NR_gettid,
	[225] = __NR_readahead,
	[226] = __NR_setxattr,
	[227] = __NR_lsetxattr,
	[228] = __NR_fsetxattr,
	[229] = __NR_getxattr,
	[230] = __NR_lgetxattr,
	[231] = __NR_fgetxattr,
	[232] = __NR_listxattr,
	[233] = __NR_llistxattr,
	[234] = __NR_flistxattr,
	[235] = __NR_removexattr,
	[236] = __NR_lremovexattr,
	[237] = __NR_fremovexattr,
	[238] = __NR_tkill,
	[239] = -1, /* __NR_sendfile64, */
	[240] = __NR_futex,
	[241] = __NR_sched_setaffinity,
	[242] = __NR_sched_getaffinity,
	[243] = __NR_set_thread_area,
	[244] = __NR_get_thread_area,
	[245] = __NR_io_setup,
	[246] = __NR_io_destroy,
	[247] = __NR_io_getevents,
	[248] = __NR_io_submit,
	[249] = __NR_io_cancel,
	[250] = __NR_fadvise64,
	[252] = __NR_exit_group,
	[253] = __NR_lookup_dcookie,
	[254] = __NR_epoll_create,
	[255] = __NR_epoll_ctl,
	[256] = __NR_epoll_wait,
	[257] = __NR_remap_file_pages,
	[258] = __NR_set_tid_address,
	[259] = __NR_timer_create,
	[268] = -1, /* __NR_statfs64, */
	[269] = -1, /* __NR_fstatfs64, */
	[270] = __NR_tgkill,
	[271] = __NR_utimes,
	[272] = -1, /* __NR_fadvise64_64, */
	[273] = __NR_vserver,
	[274] = __NR_mbind,
	[275] = __NR_get_mempolicy,
	[276] = __NR_set_mempolicy,
	[277] = __NR_mq_open,
	[283] = __NR_kexec_load,
	[284] = __NR_waitid,
	[286] = __NR_add_key,
	[287] = __NR_request_key,
	[288] = __NR_keyctl,
	[289] = __NR_ioprio_set,
	[290] = __NR_ioprio_get,
	[291] = __NR_inotify_init,
	[292] = __NR_inotify_add_watch,
	[293] = __NR_inotify_rm_watch,
	[294] = __NR_migrate_pages,
	[295] = __NR_openat,
	[296] = __NR_mkdirat,
	[297] = __NR_mknodat,
	[298] = __NR_fchownat,
	[299] = __NR_futimesat,
	[300] = -1, /* __NR_fstatat64, */
	[301] = __NR_unlinkat,
	[302] = __NR_renameat,
	[303] = __NR_linkat,
	[304] = __NR_symlinkat,
	[305] = __NR_readlinkat,
	[306] = __NR_fchmodat,
	[307] = __NR_faccessat,
	[308] = __NR_pselect6,
	[309] = __NR_ppoll,
	[310] = __NR_unshare,
	[311] = __NR_set_robust_list,
	[312] = __NR_get_robust_list,
	[313] = __NR_splice,
	[314] = __NR_sync_file_range,
	[315] = __NR_tee,
	[316] = __NR_vmsplice,
	[317] = __NR_move_pages,
	[318] = __NR_getcpu,
	[319] = __NR_epoll_pwait,
	[320] = __NR_utimensat,
	[321] = __NR_signalfd,
	[322] = __NR_timerfd_create,
	[323] = __NR_eventfd,
	[324] = __NR_fallocate,
	[325] = __NR_timerfd_settime,
	[326] = __NR_timerfd_gettime,
	[327] = __NR_signalfd4,
	[328] = __NR_eventfd2,
	[329] = __NR_epoll_create1,
	[330] = __NR_dup3,
	[331] = __NR_pipe2,
	[332] = __NR_inotify_init1,
	[333] = __NR_preadv,
	[334] = __NR_pwritev,
	[335] = __NR_rt_tgsigqueueinfo,
	[336] = __NR_perf_event_open,
	[337] = __NR_recvmmsg,
	[338] = __NR_fanotify_init,
	[339] = __NR_fanotify_mark,
	[340] = __NR_prlimit64,
	[341] = __NR_name_to_handle_at,
	[342] = __NR_open_by_handle_at,
	[343] = __NR_clock_adjtime,
	[344] = __NR_syncfs,
	[345] = __NR_sendmmsg,
	[346] = __NR_setns,
	[347] = __NR_process_vm_readv,
	[348] = __NR_process_vm_writev,
};

#endif
