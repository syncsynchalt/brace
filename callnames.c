#include <sys/syscall.h>
#include <stdio.h>

char *syscall_name(int callno, char *buf, int buflen)
{
#ifdef SYS_accept
	if (callno == SYS_accept) return "accept";
#endif
#ifdef SYS_accept4
	if (callno == SYS_accept4) return "accept4";
#endif
#ifdef SYS_access
	if (callno == SYS_access) return "access";
#endif
#ifdef SYS_acct
	if (callno == SYS_acct) return "acct";
#endif
#ifdef SYS_add_key
	if (callno == SYS_add_key) return "add_key";
#endif
#ifdef SYS_adjtimex
	if (callno == SYS_adjtimex) return "adjtimex";
#endif
#ifdef SYS_afs_syscall
	if (callno == SYS_afs_syscall) return "afs_syscall";
#endif
#ifdef SYS_alarm
	if (callno == SYS_alarm) return "alarm";
#endif
#ifdef SYS_arch_prctl
	if (callno == SYS_arch_prctl) return "arch_prctl";
#endif
#ifdef SYS_bind
	if (callno == SYS_bind) return "bind";
#endif
#ifdef SYS_brk
	if (callno == SYS_brk) return "brk";
#endif
#ifdef SYS_capget
	if (callno == SYS_capget) return "capget";
#endif
#ifdef SYS_capset
	if (callno == SYS_capset) return "capset";
#endif
#ifdef SYS_chdir
	if (callno == SYS_chdir) return "chdir";
#endif
#ifdef SYS_chmod
	if (callno == SYS_chmod) return "chmod";
#endif
#ifdef SYS_chown
	if (callno == SYS_chown) return "chown";
#endif
#ifdef SYS_chroot
	if (callno == SYS_chroot) return "chroot";
#endif
#ifdef SYS_clock_adjtime
	if (callno == SYS_clock_adjtime) return "clock_adjtime";
#endif
#ifdef SYS_clock_getres
	if (callno == SYS_clock_getres) return "clock_getres";
#endif
#ifdef SYS_clock_gettime
	if (callno == SYS_clock_gettime) return "clock_gettime";
#endif
#ifdef SYS_clock_nanosleep
	if (callno == SYS_clock_nanosleep) return "clock_nanosleep";
#endif
#ifdef SYS_clock_settime
	if (callno == SYS_clock_settime) return "clock_settime";
#endif
#ifdef SYS_clone
	if (callno == SYS_clone) return "clone";
#endif
#ifdef SYS_close
	if (callno == SYS_close) return "close";
#endif
#ifdef SYS_connect
	if (callno == SYS_connect) return "connect";
#endif
#ifdef SYS_creat
	if (callno == SYS_creat) return "creat";
#endif
#ifdef SYS_delete_module
	if (callno == SYS_delete_module) return "delete_module";
#endif
#ifdef SYS_dup
	if (callno == SYS_dup) return "dup";
#endif
#ifdef SYS_dup2
	if (callno == SYS_dup2) return "dup2";
#endif
#ifdef SYS_dup3
	if (callno == SYS_dup3) return "dup3";
#endif
#ifdef SYS_epoll_create
	if (callno == SYS_epoll_create) return "epoll_create";
#endif
#ifdef SYS_epoll_create1
	if (callno == SYS_epoll_create1) return "epoll_create1";
#endif
#ifdef SYS_epoll_ctl
	if (callno == SYS_epoll_ctl) return "epoll_ctl";
#endif
#ifdef SYS_epoll_pwait
	if (callno == SYS_epoll_pwait) return "epoll_pwait";
#endif
#ifdef SYS_epoll_wait
	if (callno == SYS_epoll_wait) return "epoll_wait";
#endif
#ifdef SYS_eventfd
	if (callno == SYS_eventfd) return "eventfd";
#endif
#ifdef SYS_eventfd2
	if (callno == SYS_eventfd2) return "eventfd2";
#endif
#ifdef SYS_execve
	if (callno == SYS_execve) return "execve";
#endif
#ifdef SYS_exit
	if (callno == SYS_exit) return "exit";
#endif
#ifdef SYS_exit_group
	if (callno == SYS_exit_group) return "exit_group";
#endif
#ifdef SYS_faccessat
	if (callno == SYS_faccessat) return "faccessat";
#endif
#ifdef SYS_fadvise64
	if (callno == SYS_fadvise64) return "fadvise64";
#endif
#ifdef SYS_fallocate
	if (callno == SYS_fallocate) return "fallocate";
#endif
#ifdef SYS_fanotify_init
	if (callno == SYS_fanotify_init) return "fanotify_init";
#endif
#ifdef SYS_fanotify_mark
	if (callno == SYS_fanotify_mark) return "fanotify_mark";
#endif
#ifdef SYS_fchdir
	if (callno == SYS_fchdir) return "fchdir";
#endif
#ifdef SYS_fchmod
	if (callno == SYS_fchmod) return "fchmod";
#endif
#ifdef SYS_fchmodat
	if (callno == SYS_fchmodat) return "fchmodat";
#endif
#ifdef SYS_fchown
	if (callno == SYS_fchown) return "fchown";
#endif
#ifdef SYS_fchownat
	if (callno == SYS_fchownat) return "fchownat";
#endif
#ifdef SYS_fcntl
	if (callno == SYS_fcntl) return "fcntl";
#endif
#ifdef SYS_fdatasync
	if (callno == SYS_fdatasync) return "fdatasync";
#endif
#ifdef SYS_fgetxattr
	if (callno == SYS_fgetxattr) return "fgetxattr";
#endif
#ifdef SYS_finit_module
	if (callno == SYS_finit_module) return "finit_module";
#endif
#ifdef SYS_flistxattr
	if (callno == SYS_flistxattr) return "flistxattr";
#endif
#ifdef SYS_flock
	if (callno == SYS_flock) return "flock";
#endif
#ifdef SYS_fork
	if (callno == SYS_fork) return "fork";
#endif
#ifdef SYS_fremovexattr
	if (callno == SYS_fremovexattr) return "fremovexattr";
#endif
#ifdef SYS_fsetxattr
	if (callno == SYS_fsetxattr) return "fsetxattr";
#endif
#ifdef SYS_fstat
	if (callno == SYS_fstat) return "fstat";
#endif
#ifdef SYS_fstatfs
	if (callno == SYS_fstatfs) return "fstatfs";
#endif
#ifdef SYS_fsync
	if (callno == SYS_fsync) return "fsync";
#endif
#ifdef SYS_ftruncate
	if (callno == SYS_ftruncate) return "ftruncate";
#endif
#ifdef SYS_futex
	if (callno == SYS_futex) return "futex";
#endif
#ifdef SYS_futimesat
	if (callno == SYS_futimesat) return "futimesat";
#endif
#ifdef SYS_get_mempolicy
	if (callno == SYS_get_mempolicy) return "get_mempolicy";
#endif
#ifdef SYS_get_robust_list
	if (callno == SYS_get_robust_list) return "get_robust_list";
#endif
#ifdef SYS_getcpu
	if (callno == SYS_getcpu) return "getcpu";
#endif
#ifdef SYS_getcwd
	if (callno == SYS_getcwd) return "getcwd";
#endif
#ifdef SYS_getdents
	if (callno == SYS_getdents) return "getdents";
#endif
#ifdef SYS_getdents64
	if (callno == SYS_getdents64) return "getdents64";
#endif
#ifdef SYS_getegid
	if (callno == SYS_getegid) return "getegid";
#endif
#ifdef SYS_geteuid
	if (callno == SYS_geteuid) return "geteuid";
#endif
#ifdef SYS_getgid
	if (callno == SYS_getgid) return "getgid";
#endif
#ifdef SYS_getgroups
	if (callno == SYS_getgroups) return "getgroups";
#endif
#ifdef SYS_getitimer
	if (callno == SYS_getitimer) return "getitimer";
#endif
#ifdef SYS_getpeername
	if (callno == SYS_getpeername) return "getpeername";
#endif
#ifdef SYS_getpgid
	if (callno == SYS_getpgid) return "getpgid";
#endif
#ifdef SYS_getpgrp
	if (callno == SYS_getpgrp) return "getpgrp";
#endif
#ifdef SYS_getpid
	if (callno == SYS_getpid) return "getpid";
#endif
#ifdef SYS_getpmsg
	if (callno == SYS_getpmsg) return "getpmsg";
#endif
#ifdef SYS_getppid
	if (callno == SYS_getppid) return "getppid";
#endif
#ifdef SYS_getpriority
	if (callno == SYS_getpriority) return "getpriority";
#endif
#ifdef SYS_getresgid
	if (callno == SYS_getresgid) return "getresgid";
#endif
#ifdef SYS_getresuid
	if (callno == SYS_getresuid) return "getresuid";
#endif
#ifdef SYS_getrlimit
	if (callno == SYS_getrlimit) return "getrlimit";
#endif
#ifdef SYS_getrusage
	if (callno == SYS_getrusage) return "getrusage";
#endif
#ifdef SYS_getsid
	if (callno == SYS_getsid) return "getsid";
#endif
#ifdef SYS_getsockname
	if (callno == SYS_getsockname) return "getsockname";
#endif
#ifdef SYS_getsockopt
	if (callno == SYS_getsockopt) return "getsockopt";
#endif
#ifdef SYS_gettid
	if (callno == SYS_gettid) return "gettid";
#endif
#ifdef SYS_gettimeofday
	if (callno == SYS_gettimeofday) return "gettimeofday";
#endif
#ifdef SYS_getuid
	if (callno == SYS_getuid) return "getuid";
#endif
#ifdef SYS_getxattr
	if (callno == SYS_getxattr) return "getxattr";
#endif
#ifdef SYS_init_module
	if (callno == SYS_init_module) return "init_module";
#endif
#ifdef SYS_inotify_add_watch
	if (callno == SYS_inotify_add_watch) return "inotify_add_watch";
#endif
#ifdef SYS_inotify_init
	if (callno == SYS_inotify_init) return "inotify_init";
#endif
#ifdef SYS_inotify_init1
	if (callno == SYS_inotify_init1) return "inotify_init1";
#endif
#ifdef SYS_inotify_rm_watch
	if (callno == SYS_inotify_rm_watch) return "inotify_rm_watch";
#endif
#ifdef SYS_io_cancel
	if (callno == SYS_io_cancel) return "io_cancel";
#endif
#ifdef SYS_io_destroy
	if (callno == SYS_io_destroy) return "io_destroy";
#endif
#ifdef SYS_io_getevents
	if (callno == SYS_io_getevents) return "io_getevents";
#endif
#ifdef SYS_io_setup
	if (callno == SYS_io_setup) return "io_setup";
#endif
#ifdef SYS_io_submit
	if (callno == SYS_io_submit) return "io_submit";
#endif
#ifdef SYS_ioctl
	if (callno == SYS_ioctl) return "ioctl";
#endif
#ifdef SYS_ioperm
	if (callno == SYS_ioperm) return "ioperm";
#endif
#ifdef SYS_iopl
	if (callno == SYS_iopl) return "iopl";
#endif
#ifdef SYS_ioprio_get
	if (callno == SYS_ioprio_get) return "ioprio_get";
#endif
#ifdef SYS_ioprio_set
	if (callno == SYS_ioprio_set) return "ioprio_set";
#endif
#ifdef SYS_kcmp
	if (callno == SYS_kcmp) return "kcmp";
#endif
#ifdef SYS_kexec_file_load
	if (callno == SYS_kexec_file_load) return "kexec_file_load";
#endif
#ifdef SYS_kexec_load
	if (callno == SYS_kexec_load) return "kexec_load";
#endif
#ifdef SYS_keyctl
	if (callno == SYS_keyctl) return "keyctl";
#endif
#ifdef SYS_kill
	if (callno == SYS_kill) return "kill";
#endif
#ifdef SYS_lchown
	if (callno == SYS_lchown) return "lchown";
#endif
#ifdef SYS_lgetxattr
	if (callno == SYS_lgetxattr) return "lgetxattr";
#endif
#ifdef SYS_link
	if (callno == SYS_link) return "link";
#endif
#ifdef SYS_linkat
	if (callno == SYS_linkat) return "linkat";
#endif
#ifdef SYS_listen
	if (callno == SYS_listen) return "listen";
#endif
#ifdef SYS_listxattr
	if (callno == SYS_listxattr) return "listxattr";
#endif
#ifdef SYS_llistxattr
	if (callno == SYS_llistxattr) return "llistxattr";
#endif
#ifdef SYS_lookup_dcookie
	if (callno == SYS_lookup_dcookie) return "lookup_dcookie";
#endif
#ifdef SYS_lremovexattr
	if (callno == SYS_lremovexattr) return "lremovexattr";
#endif
#ifdef SYS_lseek
	if (callno == SYS_lseek) return "lseek";
#endif
#ifdef SYS_lsetxattr
	if (callno == SYS_lsetxattr) return "lsetxattr";
#endif
#ifdef SYS_lstat
	if (callno == SYS_lstat) return "lstat";
#endif
#ifdef SYS_madvise
	if (callno == SYS_madvise) return "madvise";
#endif
#ifdef SYS_mbind
	if (callno == SYS_mbind) return "mbind";
#endif
#ifdef SYS_memfd_create
	if (callno == SYS_memfd_create) return "memfd_create";
#endif
#ifdef SYS_migrate_pages
	if (callno == SYS_migrate_pages) return "migrate_pages";
#endif
#ifdef SYS_mincore
	if (callno == SYS_mincore) return "mincore";
#endif
#ifdef SYS_mkdir
	if (callno == SYS_mkdir) return "mkdir";
#endif
#ifdef SYS_mkdirat
	if (callno == SYS_mkdirat) return "mkdirat";
#endif
#ifdef SYS_mknod
	if (callno == SYS_mknod) return "mknod";
#endif
#ifdef SYS_mknodat
	if (callno == SYS_mknodat) return "mknodat";
#endif
#ifdef SYS_mlock
	if (callno == SYS_mlock) return "mlock";
#endif
#ifdef SYS_mlockall
	if (callno == SYS_mlockall) return "mlockall";
#endif
#ifdef SYS_mmap
	if (callno == SYS_mmap) return "mmap";
#endif
#ifdef SYS_modify_ldt
	if (callno == SYS_modify_ldt) return "modify_ldt";
#endif
#ifdef SYS_mount
	if (callno == SYS_mount) return "mount";
#endif
#ifdef SYS_move_pages
	if (callno == SYS_move_pages) return "move_pages";
#endif
#ifdef SYS_mprotect
	if (callno == SYS_mprotect) return "mprotect";
#endif
#ifdef SYS_mq_getsetattr
	if (callno == SYS_mq_getsetattr) return "mq_getsetattr";
#endif
#ifdef SYS_mq_notify
	if (callno == SYS_mq_notify) return "mq_notify";
#endif
#ifdef SYS_mq_open
	if (callno == SYS_mq_open) return "mq_open";
#endif
#ifdef SYS_mq_timedreceive
	if (callno == SYS_mq_timedreceive) return "mq_timedreceive";
#endif
#ifdef SYS_mq_timedsend
	if (callno == SYS_mq_timedsend) return "mq_timedsend";
#endif
#ifdef SYS_mq_unlink
	if (callno == SYS_mq_unlink) return "mq_unlink";
#endif
#ifdef SYS_mremap
	if (callno == SYS_mremap) return "mremap";
#endif
#ifdef SYS_msgctl
	if (callno == SYS_msgctl) return "msgctl";
#endif
#ifdef SYS_msgget
	if (callno == SYS_msgget) return "msgget";
#endif
#ifdef SYS_msgrcv
	if (callno == SYS_msgrcv) return "msgrcv";
#endif
#ifdef SYS_msgsnd
	if (callno == SYS_msgsnd) return "msgsnd";
#endif
#ifdef SYS_msync
	if (callno == SYS_msync) return "msync";
#endif
#ifdef SYS_munlock
	if (callno == SYS_munlock) return "munlock";
#endif
#ifdef SYS_munlockall
	if (callno == SYS_munlockall) return "munlockall";
#endif
#ifdef SYS_munmap
	if (callno == SYS_munmap) return "munmap";
#endif
#ifdef SYS_name_to_handle_at
	if (callno == SYS_name_to_handle_at) return "name_to_handle_at";
#endif
#ifdef SYS_nanosleep
	if (callno == SYS_nanosleep) return "nanosleep";
#endif
#ifdef SYS_newfstatat
	if (callno == SYS_newfstatat) return "newfstatat";
#endif
#ifdef SYS_open
	if (callno == SYS_open) return "open";
#endif
#ifdef SYS_open_by_handle_at
	if (callno == SYS_open_by_handle_at) return "open_by_handle_at";
#endif
#ifdef SYS_openat
	if (callno == SYS_openat) return "openat";
#endif
#ifdef SYS_pause
	if (callno == SYS_pause) return "pause";
#endif
#ifdef SYS_perf_event_open
	if (callno == SYS_perf_event_open) return "perf_event_open";
#endif
#ifdef SYS_personality
	if (callno == SYS_personality) return "personality";
#endif
#ifdef SYS_pipe
	if (callno == SYS_pipe) return "pipe";
#endif
#ifdef SYS_pipe2
	if (callno == SYS_pipe2) return "pipe2";
#endif
#ifdef SYS_pivot_root
	if (callno == SYS_pivot_root) return "pivot_root";
#endif
#ifdef SYS_poll
	if (callno == SYS_poll) return "poll";
#endif
#ifdef SYS_ppoll
	if (callno == SYS_ppoll) return "ppoll";
#endif
#ifdef SYS_prctl
	if (callno == SYS_prctl) return "prctl";
#endif
#ifdef SYS_pread64
	if (callno == SYS_pread64) return "pread64";
#endif
#ifdef SYS_preadv
	if (callno == SYS_preadv) return "preadv";
#endif
#ifdef SYS_prlimit64
	if (callno == SYS_prlimit64) return "prlimit64";
#endif
#ifdef SYS_process_vm_readv
	if (callno == SYS_process_vm_readv) return "process_vm_readv";
#endif
#ifdef SYS_process_vm_writev
	if (callno == SYS_process_vm_writev) return "process_vm_writev";
#endif
#ifdef SYS_pselect6
	if (callno == SYS_pselect6) return "pselect6";
#endif
#ifdef SYS_ptrace
	if (callno == SYS_ptrace) return "ptrace";
#endif
#ifdef SYS_putpmsg
	if (callno == SYS_putpmsg) return "putpmsg";
#endif
#ifdef SYS_pwrite64
	if (callno == SYS_pwrite64) return "pwrite64";
#endif
#ifdef SYS_pwritev
	if (callno == SYS_pwritev) return "pwritev";
#endif
#ifdef SYS_quotactl
	if (callno == SYS_quotactl) return "quotactl";
#endif
#ifdef SYS_read
	if (callno == SYS_read) return "read";
#endif
#ifdef SYS_readahead
	if (callno == SYS_readahead) return "readahead";
#endif
#ifdef SYS_readlink
	if (callno == SYS_readlink) return "readlink";
#endif
#ifdef SYS_readlinkat
	if (callno == SYS_readlinkat) return "readlinkat";
#endif
#ifdef SYS_readv
	if (callno == SYS_readv) return "readv";
#endif
#ifdef SYS_reboot
	if (callno == SYS_reboot) return "reboot";
#endif
#ifdef SYS_recvfrom
	if (callno == SYS_recvfrom) return "recvfrom";
#endif
#ifdef SYS_recvmmsg
	if (callno == SYS_recvmmsg) return "recvmmsg";
#endif
#ifdef SYS_recvmsg
	if (callno == SYS_recvmsg) return "recvmsg";
#endif
#ifdef SYS_remap_file_pages
	if (callno == SYS_remap_file_pages) return "remap_file_pages";
#endif
#ifdef SYS_removexattr
	if (callno == SYS_removexattr) return "removexattr";
#endif
#ifdef SYS_rename
	if (callno == SYS_rename) return "rename";
#endif
#ifdef SYS_renameat
	if (callno == SYS_renameat) return "renameat";
#endif
#ifdef SYS_renameat2
	if (callno == SYS_renameat2) return "renameat2";
#endif
#ifdef SYS_request_key
	if (callno == SYS_request_key) return "request_key";
#endif
#ifdef SYS_restart_syscall
	if (callno == SYS_restart_syscall) return "restart_syscall";
#endif
#ifdef SYS_rmdir
	if (callno == SYS_rmdir) return "rmdir";
#endif
#ifdef SYS_rt_sigaction
	if (callno == SYS_rt_sigaction) return "rt_sigaction";
#endif
#ifdef SYS_rt_sigpending
	if (callno == SYS_rt_sigpending) return "rt_sigpending";
#endif
#ifdef SYS_rt_sigprocmask
	if (callno == SYS_rt_sigprocmask) return "rt_sigprocmask";
#endif
#ifdef SYS_rt_sigqueueinfo
	if (callno == SYS_rt_sigqueueinfo) return "rt_sigqueueinfo";
#endif
#ifdef SYS_rt_sigreturn
	if (callno == SYS_rt_sigreturn) return "rt_sigreturn";
#endif
#ifdef SYS_rt_sigsuspend
	if (callno == SYS_rt_sigsuspend) return "rt_sigsuspend";
#endif
#ifdef SYS_rt_sigtimedwait
	if (callno == SYS_rt_sigtimedwait) return "rt_sigtimedwait";
#endif
#ifdef SYS_rt_tgsigqueueinfo
	if (callno == SYS_rt_tgsigqueueinfo) return "rt_tgsigqueueinfo";
#endif
#ifdef SYS_sched_get_priority_max
	if (callno == SYS_sched_get_priority_max) return "sched_get_priority_max";
#endif
#ifdef SYS_sched_get_priority_min
	if (callno == SYS_sched_get_priority_min) return "sched_get_priority_min";
#endif
#ifdef SYS_sched_getaffinity
	if (callno == SYS_sched_getaffinity) return "sched_getaffinity";
#endif
#ifdef SYS_sched_getattr
	if (callno == SYS_sched_getattr) return "sched_getattr";
#endif
#ifdef SYS_sched_getparam
	if (callno == SYS_sched_getparam) return "sched_getparam";
#endif
#ifdef SYS_sched_getscheduler
	if (callno == SYS_sched_getscheduler) return "sched_getscheduler";
#endif
#ifdef SYS_sched_rr_get_interval
	if (callno == SYS_sched_rr_get_interval) return "sched_rr_get_interval";
#endif
#ifdef SYS_sched_setaffinity
	if (callno == SYS_sched_setaffinity) return "sched_setaffinity";
#endif
#ifdef SYS_sched_setattr
	if (callno == SYS_sched_setattr) return "sched_setattr";
#endif
#ifdef SYS_sched_setparam
	if (callno == SYS_sched_setparam) return "sched_setparam";
#endif
#ifdef SYS_sched_setscheduler
	if (callno == SYS_sched_setscheduler) return "sched_setscheduler";
#endif
#ifdef SYS_sched_yield
	if (callno == SYS_sched_yield) return "sched_yield";
#endif
#ifdef SYS_security
	if (callno == SYS_security) return "security";
#endif
#ifdef SYS_select
	if (callno == SYS_select) return "select";
#endif
#ifdef SYS_semctl
	if (callno == SYS_semctl) return "semctl";
#endif
#ifdef SYS_semget
	if (callno == SYS_semget) return "semget";
#endif
#ifdef SYS_semop
	if (callno == SYS_semop) return "semop";
#endif
#ifdef SYS_semtimedop
	if (callno == SYS_semtimedop) return "semtimedop";
#endif
#ifdef SYS_sendfile
	if (callno == SYS_sendfile) return "sendfile";
#endif
#ifdef SYS_sendmmsg
	if (callno == SYS_sendmmsg) return "sendmmsg";
#endif
#ifdef SYS_sendmsg
	if (callno == SYS_sendmsg) return "sendmsg";
#endif
#ifdef SYS_sendto
	if (callno == SYS_sendto) return "sendto";
#endif
#ifdef SYS_set_mempolicy
	if (callno == SYS_set_mempolicy) return "set_mempolicy";
#endif
#ifdef SYS_set_robust_list
	if (callno == SYS_set_robust_list) return "set_robust_list";
#endif
#ifdef SYS_set_tid_address
	if (callno == SYS_set_tid_address) return "set_tid_address";
#endif
#ifdef SYS_setdomainname
	if (callno == SYS_setdomainname) return "setdomainname";
#endif
#ifdef SYS_setfsgid
	if (callno == SYS_setfsgid) return "setfsgid";
#endif
#ifdef SYS_setfsuid
	if (callno == SYS_setfsuid) return "setfsuid";
#endif
#ifdef SYS_setgid
	if (callno == SYS_setgid) return "setgid";
#endif
#ifdef SYS_setgroups
	if (callno == SYS_setgroups) return "setgroups";
#endif
#ifdef SYS_sethostname
	if (callno == SYS_sethostname) return "sethostname";
#endif
#ifdef SYS_setitimer
	if (callno == SYS_setitimer) return "setitimer";
#endif
#ifdef SYS_setns
	if (callno == SYS_setns) return "setns";
#endif
#ifdef SYS_setpgid
	if (callno == SYS_setpgid) return "setpgid";
#endif
#ifdef SYS_setpriority
	if (callno == SYS_setpriority) return "setpriority";
#endif
#ifdef SYS_setregid
	if (callno == SYS_setregid) return "setregid";
#endif
#ifdef SYS_setresgid
	if (callno == SYS_setresgid) return "setresgid";
#endif
#ifdef SYS_setresuid
	if (callno == SYS_setresuid) return "setresuid";
#endif
#ifdef SYS_setreuid
	if (callno == SYS_setreuid) return "setreuid";
#endif
#ifdef SYS_setrlimit
	if (callno == SYS_setrlimit) return "setrlimit";
#endif
#ifdef SYS_setsid
	if (callno == SYS_setsid) return "setsid";
#endif
#ifdef SYS_setsockopt
	if (callno == SYS_setsockopt) return "setsockopt";
#endif
#ifdef SYS_settimeofday
	if (callno == SYS_settimeofday) return "settimeofday";
#endif
#ifdef SYS_setuid
	if (callno == SYS_setuid) return "setuid";
#endif
#ifdef SYS_setxattr
	if (callno == SYS_setxattr) return "setxattr";
#endif
#ifdef SYS_shmat
	if (callno == SYS_shmat) return "shmat";
#endif
#ifdef SYS_shmctl
	if (callno == SYS_shmctl) return "shmctl";
#endif
#ifdef SYS_shmdt
	if (callno == SYS_shmdt) return "shmdt";
#endif
#ifdef SYS_shmget
	if (callno == SYS_shmget) return "shmget";
#endif
#ifdef SYS_shutdown
	if (callno == SYS_shutdown) return "shutdown";
#endif
#ifdef SYS_sigaltstack
	if (callno == SYS_sigaltstack) return "sigaltstack";
#endif
#ifdef SYS_signalfd
	if (callno == SYS_signalfd) return "signalfd";
#endif
#ifdef SYS_signalfd4
	if (callno == SYS_signalfd4) return "signalfd4";
#endif
#ifdef SYS_socket
	if (callno == SYS_socket) return "socket";
#endif
#ifdef SYS_socketpair
	if (callno == SYS_socketpair) return "socketpair";
#endif
#ifdef SYS_splice
	if (callno == SYS_splice) return "splice";
#endif
#ifdef SYS_stat
	if (callno == SYS_stat) return "stat";
#endif
#ifdef SYS_statfs
	if (callno == SYS_statfs) return "statfs";
#endif
#ifdef SYS_swapoff
	if (callno == SYS_swapoff) return "swapoff";
#endif
#ifdef SYS_swapon
	if (callno == SYS_swapon) return "swapon";
#endif
#ifdef SYS_symlink
	if (callno == SYS_symlink) return "symlink";
#endif
#ifdef SYS_symlinkat
	if (callno == SYS_symlinkat) return "symlinkat";
#endif
#ifdef SYS_sync
	if (callno == SYS_sync) return "sync";
#endif
#ifdef SYS_sync_file_range
	if (callno == SYS_sync_file_range) return "sync_file_range";
#endif
#ifdef SYS_syncfs
	if (callno == SYS_syncfs) return "syncfs";
#endif
#ifdef SYS_sysfs
	if (callno == SYS_sysfs) return "sysfs";
#endif
#ifdef SYS_sysinfo
	if (callno == SYS_sysinfo) return "sysinfo";
#endif
#ifdef SYS_syslog
	if (callno == SYS_syslog) return "syslog";
#endif
#ifdef SYS_tee
	if (callno == SYS_tee) return "tee";
#endif
#ifdef SYS_tgkill
	if (callno == SYS_tgkill) return "tgkill";
#endif
#ifdef SYS_time
	if (callno == SYS_time) return "time";
#endif
#ifdef SYS_timer_create
	if (callno == SYS_timer_create) return "timer_create";
#endif
#ifdef SYS_timer_delete
	if (callno == SYS_timer_delete) return "timer_delete";
#endif
#ifdef SYS_timer_getoverrun
	if (callno == SYS_timer_getoverrun) return "timer_getoverrun";
#endif
#ifdef SYS_timer_gettime
	if (callno == SYS_timer_gettime) return "timer_gettime";
#endif
#ifdef SYS_timer_settime
	if (callno == SYS_timer_settime) return "timer_settime";
#endif
#ifdef SYS_timerfd_create
	if (callno == SYS_timerfd_create) return "timerfd_create";
#endif
#ifdef SYS_timerfd_gettime
	if (callno == SYS_timerfd_gettime) return "timerfd_gettime";
#endif
#ifdef SYS_timerfd_settime
	if (callno == SYS_timerfd_settime) return "timerfd_settime";
#endif
#ifdef SYS_times
	if (callno == SYS_times) return "times";
#endif
#ifdef SYS_tkill
	if (callno == SYS_tkill) return "tkill";
#endif
#ifdef SYS_truncate
	if (callno == SYS_truncate) return "truncate";
#endif
#ifdef SYS_tuxcall
	if (callno == SYS_tuxcall) return "tuxcall";
#endif
#ifdef SYS_umask
	if (callno == SYS_umask) return "umask";
#endif
#ifdef SYS_umount2
	if (callno == SYS_umount2) return "umount2";
#endif
#ifdef SYS_uname
	if (callno == SYS_uname) return "uname";
#endif
#ifdef SYS_unlink
	if (callno == SYS_unlink) return "unlink";
#endif
#ifdef SYS_unlinkat
	if (callno == SYS_unlinkat) return "unlinkat";
#endif
#ifdef SYS_unshare
	if (callno == SYS_unshare) return "unshare";
#endif
#ifdef SYS_userfaultfd
	if (callno == SYS_userfaultfd) return "userfaultfd";
#endif
#ifdef SYS_ustat
	if (callno == SYS_ustat) return "ustat";
#endif
#ifdef SYS_utime
	if (callno == SYS_utime) return "utime";
#endif
#ifdef SYS_utimensat
	if (callno == SYS_utimensat) return "utimensat";
#endif
#ifdef SYS_utimes
	if (callno == SYS_utimes) return "utimes";
#endif
#ifdef SYS_vfork
	if (callno == SYS_vfork) return "vfork";
#endif
#ifdef SYS_vhangup
	if (callno == SYS_vhangup) return "vhangup";
#endif
#ifdef SYS_vmsplice
	if (callno == SYS_vmsplice) return "vmsplice";
#endif
#ifdef SYS_wait4
	if (callno == SYS_wait4) return "wait4";
#endif
#ifdef SYS_waitid
	if (callno == SYS_waitid) return "waitid";
#endif
#ifdef SYS_write
	if (callno == SYS_write) return "write";
#endif
#ifdef SYS_writev
	if (callno == SYS_writev) return "writev";
#endif
	snprintf(buf, buflen, "syscall(%d)", callno);
	return buf;
}
