#!/usr/bin/env python3
"""Insert KernelSU manual-hook calls required by BakaSU/ReSukiSU on a 4.19 non-GKI tree.

Based on https://bakasu.org/guide/manual-integrate.html (stat/exec/open/read/reboot/input).
Every edit is anchored on an exact source snippet and applied once; anything that
cannot be anchored is reported so the build fails loudly instead of silently
producing a kernel without root support.
"""
import sys
import os

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()

STAT_HDR = """
#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
				int *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif
"""

EXEC_HDR = """
#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags, int *retval);
#endif
"""

# (relative path, anchor snippet, replacement snippet, label)
EDITS = [
    # ---- fs/stat.c ----
    ("fs/stat.c",
     "SYSCALL_DEFINE2(newlstat, const char __user *, filename,",
     None, "stat.c: prototypes before newlstat"),

    ("fs/stat.c",
     """SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;
""",
     """SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;

#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif
""", "stat.c: newfstatat hook"),

    ("fs/stat.c",
     """SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
		struct stat64 __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;
""",
     """SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
		struct stat64 __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;

#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif
""", "stat.c: fstatat64 hook"),

    ("fs/stat.c",
     """SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat(&stat, statbuf);
""",
     """SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat(&stat, statbuf);

#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_newfstat_ret(&fd, &statbuf);
#endif
""", "stat.c: newfstat ret hook"),

    ("fs/stat.c",
     """SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat64(&stat, statbuf);
""",
     """SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat64(&stat, statbuf);

#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_fstat64_ret(&fd, &statbuf);
#endif
""", "stat.c: fstat64 ret hook"),

    # ---- fs/exec.c ----
    ("fs/exec.c",
     """int do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}""",
     """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags, int *retval);
#endif

int do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
#ifdef CONFIG_KSU_MANUAL_HOOK
	int retval;

	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	retval = do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
	ksu_handle_post_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0, &retval);
	return retval;
#else
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
#endif
}""", "exec.c: do_execve hook"),

    ("fs/exec.c",
     """int do_execveat(int fd, struct filename *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp,
		int flags)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };

	return do_execveat_common(fd, filename, argv, envp, flags);
}""",
     """int do_execveat(int fd, struct filename *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp,
		int flags)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
#ifdef CONFIG_KSU_MANUAL_HOOK
	int retval;

	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	retval = do_execveat_common(fd, filename, argv, envp, flags);
	ksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);
	return retval;
#else

	return do_execveat_common(fd, filename, argv, envp, flags);
#endif
}""", "exec.c: do_execveat hook"),

    # ---- fs/open.c ----
    ("fs/open.c",
     """SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
	return do_faccessat(dfd, filename, mode);
}""",
     """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif

SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
	return do_faccessat(dfd, filename, mode);
}""", "open.c: faccessat hook"),

    # ---- fs/read_write.c ----
    ("fs/read_write.c",
     """SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}""",
     """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
				size_t *count_ptr);
#endif

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_sys_read(fd, &buf, &count);
#endif
	return ksys_read(fd, buf, count);
}""", "read_write.c: read hook"),

    # ---- kernel/reboot.c ----
    ("kernel/reboot.c",
     """SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;
""",
     """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
				void __user **arg);
#endif

SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;

#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif
""", "reboot.c: reboot hook"),

    # ---- drivers/input/input.c ----
    ("drivers/input/input.c",
     """static void input_handle_event(struct input_dev *dev,
			       unsigned int type, unsigned int code, int value)
{""",
     """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				int *value);
#endif

static void input_handle_event(struct input_dev *dev,
			       unsigned int type, unsigned int code, int value)
{""", "input.c: input event hook prototype"),

    # -Wdeclaration-after-statement is -Werror here, so the hook call must go
    # AFTER the leading declarations of input_handle_event: split the
    # "int disposition = input_get_disposition(...)" declaration.
    ("drivers/input/input.c",
     "	int disposition = input_get_disposition(dev, type, code, &value);",
     """	int disposition;
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_input_handle_event(&type, &code, &value);
#endif
	disposition = input_get_disposition(dev, type, code, &value);""",
     "input.c: disposition split for -Wdeclaration-after-statement"),
]


def apply():
    cache = {}
    failed = []
    for rel, anchor, repl, label in EDITS:
        path = os.path.join(ROOT, rel)
        if rel not in cache:
            with open(path, encoding="utf-8", errors="surrogateescape") as fh:
                cache[rel] = fh.read()
        src = cache[rel]
        if anchor not in src:
            failed.append(label)
            continue
        if repl is None:
            # append prototypes right before the anchor
            src = src.replace(anchor, STAT_HDR + "\n" + anchor, 1)
        else:
            if repl not in src:
                src = src.replace(anchor, repl, 1)
        cache[rel] = src

    for rel, text in cache.items():
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(text)

    if failed:
        print("[!] KSU manual hook: could not anchor: " + ", ".join(failed))
        return 1
    print("[+] KSU manual hook: all %d hooks applied" % len(EDITS))
    return 0


sys.exit(apply())
