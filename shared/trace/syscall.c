/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

/*
 * Syscall hooks
 *
 * Features:
 * 1. getdents64: hide sensitive files from directory listings
 * 2. readlinkat: hide sensitive symlink targets
 * 3. fgetxattr: spoof SELinux contexts
 */

#include <compiler.h>
#include <kpmodule.h>
#include <syscall.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>
#include "symbols.h"
#include "syscall.h"

/* ARM64 syscall numbers */
#define __NR_openat      56
#define __NR_readlinkat  78
#define __NR_getdents64  61
#define __NR_truncate    45
#define __NR_fgetxattr   10
#define __NR_getsockopt  209

/* Socket option constants - used for getsockopt SELinux detection */
#define SOL_SOCKET       1
#define SO_PEERSEC       31

/* File names to hide */
static const char *hide_files[] = {
    "libhhh.so",
    "libhhh.config.so",
    NULL
};

/* Hook state */
static int readlink_hooked = 0;
static int getdents_hooked = 0;
static int truncate_hooked = 0;
static int fgetxattr_hooked = 0;
static int getsockopt_hooked = 0;

/* Feature switches (soft switches) */
static int syscall_enabled = 1;
static int readlink_enabled = 1;
/*
 * getdents64 is still unstable on some devices (can crash userspace).
 * Disabled by default; enable manually when needed: getdents=1
 */
static int getdents_enabled = 0;
static int truncate_enabled = 1;
/*
 * These are "write-back to user buffer" syscall hooks:
 * - getsockopt(SO_PEERSEC)
 * - fgetxattr(security.selinux)
 *
 * Confirmed working on current test devices; enabled by default.
 * Disable manually if any anomalies occur.
 */
static int fgetxattr_enabled = 1;
static int getsockopt_enabled = 1;

static inline int should_filter(void)
{
    return current_uid() > 10000;
}

void set_syscall_enabled(int enabled)
{
    syscall_enabled = enabled ? 1 : 0;
    pr_info("[trace] syscall feature %s\n", syscall_enabled ? "enabled" : "disabled");
}

int get_syscall_enabled(void)
{
    return syscall_enabled;
}

void set_readlink_enabled(int enabled)
{
    readlink_enabled = enabled ? 1 : 0;
    pr_info("[trace] readlink feature %s\n", readlink_enabled ? "enabled" : "disabled");
}

int get_readlink_enabled(void)
{
    return readlink_enabled;
}

void set_getdents_enabled(int enabled)
{
    getdents_enabled = enabled ? 1 : 0;
    pr_info("[trace] getdents feature %s\n", getdents_enabled ? "enabled" : "disabled");
}

int get_getdents_enabled(void)
{
    return getdents_enabled;
}

void set_truncate_enabled(int enabled)
{
    truncate_enabled = enabled ? 1 : 0;
    pr_info("[trace] truncate feature %s\n", truncate_enabled ? "enabled" : "disabled");
}

int get_truncate_enabled(void)
{
    return truncate_enabled;
}

void set_fgetxattr_enabled(int enabled)
{
    fgetxattr_enabled = enabled ? 1 : 0;
    pr_info("[trace] fgetxattr feature %s\n", fgetxattr_enabled ? "enabled" : "disabled");
}

int get_fgetxattr_enabled(void)
{
    return fgetxattr_enabled;
}

void set_getsockopt_enabled(int enabled)
{
    getsockopt_enabled = enabled ? 1 : 0;
    pr_info("[trace] getsockopt feature %s\n", getsockopt_enabled ? "enabled" : "disabled");
}

int get_getsockopt_enabled(void)
{
    return getsockopt_enabled;
}

/*
 * readlinkat after hook
 * readlinkat(dirfd, pathname, buf, bufsiz)
 *   - args[0] = dirfd
 *   - args[1] = pathname (which symlink to read)
 *   - args[2] = buf (output buffer - symlink target)
 *   - args[3] = bufsiz
 *
 * Important: only filter /proc/xxx/fd/xxx symlink queries.
 * Never filter paths that affect linker library loading!
 */
static void readlink_after_hook(hook_fargs4_t *args, void *udata)
{
    char path_buf[256];
    char kbuf[1024];
    char __user *user_path;
    char __user *user_buf;
    long ret;
    size_t n;
    size_t bufsiz;

    if (!should_filter()) {
        return;
    }

    if (!syscall_enabled || !readlink_enabled) {
        return;
    }

    /* Only process successful syscalls */
    ret = (long)args->ret;
    if (ret <= 0) {
        return;
    }

    /* Check if pathname (args[1]) is a /proc/ related path */
    user_path = (char __user *)syscall_argn(args, 1);
    if (!user_path) {
        return;
    }

    if (compat_strncpy_from_user(path_buf, user_path, sizeof(path_buf)) <= 0) {
        return;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /*
     * Critical safety check: only process /proc/ symlinks.
     * Avoid interfering with linker library path resolution.
     */
    if (!kf_strstr || !kf_strstr(path_buf, "/proc/")) {
        return;
    }

    /* Get readlink result (args[2] = buf) */
    user_buf = (char __user *)syscall_argn(args, 2);
    if (!user_buf) {
        return;
    }

    /* readlink result is not NUL-terminated: copy exactly ret bytes to avoid overread */
    if (!kf_raw_copy_from_user) {
        return;
    }
    n = (size_t)ret;
    if (n >= sizeof(kbuf)) {
        n = sizeof(kbuf) - 1;
    }
    if (kf_raw_copy_from_user(kbuf, user_buf, n)) {
        return;
    }
    kbuf[n] = '\0';

    /*
     * Detection logic (only for /proc/xxx/fd/xxx):
     * 1. ends_with "libhhh.so"
     * 2. ends_with "libhhh.config.so"
     *
     * Note: zygisk_gadget/zygisk_lsposed detection is handled in maps filtering
     */
    if ((kf_strstr && kf_strstr(kbuf, "libhhh.so")) ||
        (kf_strstr && kf_strstr(kbuf, "libhhh.config.so"))) {

        /* Replace with /dev/null (truncate to bufsiz to avoid overwrite) */
        bufsiz = (size_t)syscall_argn(args, 3);
        if (bufsiz > 0) {
            size_t len = sizeof("/dev/null") - 1; /* readlink does not require NUL */
            if (len > bufsiz) {
                len = bufsiz;
            }
            compat_copy_to_user(user_buf, "/dev/null", len);
            args->ret = (long)len;
        }
        pr_info("[trace] hide readlink target in /proc\n");
    }
}

/*
 * getdents64 after hook
 * Filter sensitive file names from directory entries
 *
 * linux_dirent64 structure:
 *   d_ino     (8 bytes)
 *   d_off     (8 bytes)
 *   d_reclen  (2 bytes)
 *   d_type    (1 byte)
 *   d_name[]  (variable)
 */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

/*
 * getdents64(fd, buf, count)
 *   - args[0] = fd
 *   - args[1] = buf (directory entry buffer)
 *   - args[2] = count
 *   - ret = actual bytes read
 */
static void getdents_after_hook(hook_fargs3_t *args, void *udata)
{
    char __user *user_buf;
    long ret;
    size_t ret_len;
    char *kbuf;
    char *filtered_buf;
    size_t filtered_len;
    size_t offset;

    if (!should_filter()) {
        return;
    }

    if (!syscall_enabled || !getdents_enabled) {
        return;
    }

    ret = (long)args->ret;
    if (ret <= 0) {
        return;
    }
    ret_len = (size_t)ret;

    /* Use syscall_argn to get args[1] = buf */
    user_buf = (char __user *)syscall_argn(args, 1);
    if (!user_buf) {
        return;
    }

    /*
     * Guard: avoid abnormally large return values causing vmalloc pressure.
     * getdents64 typically returns < 64KB; skip filtering if larger.
     */
    if (ret_len > (64 * 1024)) {
        return;
    }

    /* Allocate kernel buffers */
    kbuf = kf_vmalloc(ret_len);
    if (!kbuf) {
        pr_err("[trace] getdents: failed to alloc kbuf\n");
        return;
    }

    filtered_buf = kf_vmalloc(ret_len);
    if (!filtered_buf) {
        kf_vfree(kbuf);
        pr_err("[trace] getdents: failed to alloc filtered_buf\n");
        return;
    }

    /*
     * Copy user data.
     * Note: KernelPatch does not provide compat_copy_from_user,
     * so we use raw_copy_from_user resolved via kallsyms.
     */
    if (kf_raw_copy_from_user) {
        if (kf_raw_copy_from_user(kbuf, user_buf, ret_len)) {
            kf_vfree(kbuf);
            kf_vfree(filtered_buf);
            return;
        }
    } else {
        /* Fallback: cannot copy, skip filtering */
        kf_vfree(kbuf);
        kf_vfree(filtered_buf);
        return;
    }

    /* Iterate and filter directory entries */
    offset = 0;
    filtered_len = 0;

    while (offset < ret_len) {
        struct linux_dirent64 *d;
        size_t reclen;
        size_t name_off;
        size_t name_max;
        int should_hide = 0;
        const char **keyword;

        if (ret_len - offset < sizeof(struct linux_dirent64)) {
            break;
        }

        d = (struct linux_dirent64 *)(kbuf + offset);
        reclen = (size_t)d->d_reclen;
        if (reclen == 0) {
            break;
        }
        if (reclen < sizeof(struct linux_dirent64)) {
            break;
        }
        if (offset + reclen > ret_len) {
            break;
        }
        if (filtered_len + reclen > ret_len) {
            break;
        }

        /* Maximum accessible length of d_name within the record */
        name_off = (size_t)((char *)d->d_name - (char *)d);
        if (reclen <= name_off) {
            break;
        }
        name_max = reclen - name_off;

        /* Check if this entry should be hidden */
        for (keyword = hide_files; *keyword; keyword++) {
            const char *k = *keyword;
            size_t i = 0;

            if (!k) {
                continue;
            }

            /* Safe comparison: only compare within record boundary, require exact match */
            while (i < name_max) {
                char c = d->d_name[i];
                char t = k[i];
                if (c != t) {
                    break;
                }
                if (t == '\0') {
                    should_hide = 1;
                    break;
                }
                i++;
            }

            if (should_hide) {
                should_hide = 1;
                break;
            }
        }

        if (!should_hide) {
            /* Copy to filtered buffer */
            if (kf_memcpy) {
                kf_memcpy(filtered_buf + filtered_len, d, reclen);
            } else {
                /* Edge case: memcpy symbol resolution failed, skip filtering */
                break;
            }
            filtered_len += reclen;
        }

        offset += reclen;
    }

    /* Copy back to user space */
    if (filtered_len < ret_len) {
        /*
         * Use _copy_to_user (paired with _copy_from_user) which returns 0
         * on complete success. compat_copy_to_user has unstable behavior
         * across devices, which can cause userspace parsing failures.
         */
        if (kf_raw_copy_to_user) {
            if (kf_raw_copy_to_user(user_buf, filtered_buf, filtered_len) == 0) {
                args->ret = (long)filtered_len;
            }
        }
    }

    kf_vfree(kbuf);
    kf_vfree(filtered_buf);
}

/*
 * truncate before hook
 * Prevent truncation of certain hidden marker files.
 * Detects specific patterns in the path.
 */
static void truncate_before_hook(hook_fargs2_t *args, void *udata)
{
    char path_buf[1024];
    char __user *user_path;

    if (!should_filter()) {
        return;
    }

    if (!syscall_enabled || !truncate_enabled) {
        return;
    }

    /* Get path argument */
    user_path = (char __user *)syscall_argn(args, 0);
    if (!user_path) {
        return;
    }

    if (compat_strncpy_from_user(path_buf, user_path, sizeof(path_buf)) <= 0) {
        return;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /*
     * Detect marker file patterns:
     * 1. "0123456789abcdef"
     * 2. 30 consecutive 'a' characters
     * These may be hidden marker files that should not be truncated.
     */
    if ((kf_strstr && kf_strstr(path_buf, "0123456789abcdef")) ||
        (kf_strstr && kf_strstr(path_buf, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))) {
        /* Set skip_origin to block truncate execution */
        args->skip_origin = 1;
        args->ret = 0;  /* Return success but do not execute */
        pr_info("[trace] block truncate: %s\n", path_buf);
    }
}

/*
 * getsockopt after hook
 * SELinux context spoofing via socket SO_PEERSEC
 *
 * getsockopt(fd, level, optname, optval, optlen)
 *   - args[0] = fd
 *   - args[1] = level  (must be SOL_SOCKET = 1)
 *   - args[2] = optname (must be SO_PEERSEC = 31)
 *   - args[3] = optval (SELinux context)
 *   - args[4] = optlen
 *
 * Critical: must check level and optname to avoid affecting other socket operations!
 */
static void getsockopt_after_hook(hook_fargs5_t *args, void *udata)
{
    char context_buf[64];
    char __user *user_optval;
    int __user *user_optlen;
    int level, optname;
    long ret;
    int optlen;
    size_t n;

    if (!should_filter()) {
        return;
    }

    if (!syscall_enabled || !getsockopt_enabled) {
        return;
    }

    /* Only process successful syscalls (getsockopt: 0=success, <0=failure) */
    ret = (long)args->ret;
    if (ret != 0) {
        return;
    }

    /*
     * Critical check: only process SO_PEERSEC option
     * level = SOL_SOCKET (1), optname = SO_PEERSEC (31)
     */
    level = (int)syscall_argn(args, 1);
    optname = (int)syscall_argn(args, 2);

    if (level != SOL_SOCKET || optname != SO_PEERSEC) {
        return;  /* Not a SELinux query, skip */
    }

    /* getsockopt(fd, level, optname, optval, optlen) - index 3 is optval */
    user_optval = (char __user *)syscall_argn(args, 3);
    if (!user_optval) {
        return;
    }

    user_optlen = (int __user *)syscall_argn(args, 4);
    if (!user_optlen) {
        return;
    }

    /* Read user-provided buffer length to avoid write overflows that crash the app */
    if (!kf_raw_copy_from_user) {
        return;
    }
    optlen = 0;
    if (kf_raw_copy_from_user(&optlen, user_optlen, sizeof(optlen))) {
        return;
    }
    if (optlen <= 0) {
        return;
    }

    /* SO_PEERSEC return may not be strncpy-friendly: copy exactly optlen bytes with NUL */
    n = (size_t)optlen;
    if (n > sizeof(context_buf) - 1) {
        n = sizeof(context_buf) - 1;
    }
    if (kf_raw_copy_from_user(context_buf, user_optval, n)) {
        return;
    }
    context_buf[n] = '\0';

    /* Spoof magisk/su context */
    if ((kf_strcmp && kf_strcmp(context_buf, "u:r:magisk:s0") == 0) ||
        (kf_strcmp && kf_strcmp(context_buf, "u:r:su:s0") == 0)) {

        /* Must truncate to optlen + ensure NUL termination, no overflow writes */
        const char fake_context[] = "u:r:surfaceflinger:s0";
        char out[64];
        size_t cap = (size_t)optlen;
        size_t max = cap;
        size_t i;
        int new_len;

        if (max > sizeof(out)) {
            max = sizeof(out);
        }
        if (max == 0) {
            return;
        }
        for (i = 0; i + 1 < max && fake_context[i] != '\0'; i++) {
            out[i] = fake_context[i];
        }
        out[i] = '\0';

        compat_copy_to_user(user_optval, out, i + 1);
        new_len = (int)(i + 1);
        compat_copy_to_user(user_optlen, &new_len, sizeof(new_len));
        pr_info("[trace] getsockopt fake selinux: %s\n", context_buf);
    }
}

/*
 * fgetxattr after hook
 * fgetxattr(fd, name, value, size)
 *   - args[0] = fd
 *   - args[1] = name (xattr name)
 *   - args[2] = value (xattr value)
 *   - args[3] = size
 *
 * Spoof magisk/su SELinux context to surfaceflinger.
 * Note: must use syscall_argn to correctly handle has_syscall_wrapper
 */
static void fgetxattr_after_hook(hook_fargs4_t *args, void *udata)
{
    char xattr_name[64];
    char xattr_value[512];
    char __user *user_name;
    char __user *user_value;
    long ret;
    size_t size_cap;
    size_t n;

    if (!should_filter()) {
        return;
    }

    if (!syscall_enabled || !fgetxattr_enabled) {
        return;
    }

    /* Only process successful syscalls (fgetxattr: >0=length, <0=failure) */
    ret = (long)args->ret;
    if (ret <= 0) {
        return;
    }

    /* Use syscall_argn to get parameters correctly */
    user_name = (char __user *)syscall_argn(args, 1);
    user_value = (char __user *)syscall_argn(args, 2);

    if (!user_name || !user_value) {
        return;
    }

    /* Check if this is the security.selinux attribute */
    if (compat_strncpy_from_user(xattr_name, user_name, sizeof(xattr_name)) <= 0) {
        return;
    }
    xattr_name[sizeof(xattr_name) - 1] = '\0';

    if (!kf_strcmp || kf_strcmp(xattr_name, "security.selinux") != 0) {
        return;
    }

    /* Check attribute value */
    size_cap = (size_t)syscall_argn(args, 3);
    if (size_cap == 0) {
        return;
    }
    if (!kf_raw_copy_from_user) {
        return;
    }
    n = (size_t)ret;
    if (n > size_cap) {
        n = size_cap;
    }
    if (n > sizeof(xattr_value) - 1) {
        n = sizeof(xattr_value) - 1;
    }
    if (kf_raw_copy_from_user(xattr_value, user_value, n)) {
        return;
    }
    xattr_value[n] = '\0';

    /* Spoof magisk/su context */
    if (kf_strcmp(xattr_value, "u:r:magisk:s0") == 0 ||
        kf_strcmp(xattr_value, "u:r:su:s0") == 0) {

        /* Truncate to size_cap + ensure NUL termination, no overflow writes */
        const char fake_context[] = "u:r:surfaceflinger:s0";
        size_t cap = size_cap;
        size_t max = cap;
        size_t i;
        char out[64];

        if (max > sizeof(out)) {
            max = sizeof(out);
        }
        if (max == 0) {
            return;
        }
        for (i = 0; i + 1 < max && fake_context[i] != '\0'; i++) {
            out[i] = fake_context[i];
        }
        out[i] = '\0';

        compat_copy_to_user(user_value, out, i + 1);
        args->ret = (long)(i + 1);
        pr_info("[trace] fake selinux context\n");
    }
}

int install_syscall_hooks(void)
{
    int ret;

    /* Hook readlinkat - after */
    ret = fp_wrap_syscalln(__NR_readlinkat, 4, NULL, NULL,
                          (void *)readlink_after_hook, NULL);
    if (ret == 0) {
        readlink_hooked = 1;
        pr_info("[trace] readlinkat hook installed\n");
    }

    /* Hook getdents64 - after */
    ret = fp_wrap_syscalln(__NR_getdents64, 3, NULL, NULL,
                          (void *)getdents_after_hook, NULL);
    if (ret == 0) {
        getdents_hooked = 1;
        pr_info("[trace] getdents64 hook installed\n");
    }

    /* Hook truncate - before */
    ret = fp_wrap_syscalln(__NR_truncate, 2, NULL,
                          (void *)truncate_before_hook, NULL, NULL);
    if (ret == 0) {
        truncate_hooked = 1;
        pr_info("[trace] truncate hook installed\n");
    }

    /* Hook fgetxattr - after */
    ret = fp_wrap_syscalln(__NR_fgetxattr, 4, NULL, NULL,
                          (void *)fgetxattr_after_hook, NULL);
    if (ret == 0) {
        fgetxattr_hooked = 1;
        pr_info("[trace] fgetxattr hook installed\n");
    }

    /* Hook getsockopt - after */
    ret = fp_wrap_syscalln(__NR_getsockopt, 5, NULL, NULL,
                          (void *)getsockopt_after_hook, NULL);
    if (ret == 0) {
        getsockopt_hooked = 1;
        pr_info("[trace] getsockopt hook installed\n");
    }

    return SUCCESS;
}

void uninstall_syscall_hooks(void)
{
    /* KPM does not provide a syscall unhook API; removed on reboot */
    pr_info("[trace] syscall hooks will be removed on reboot\n");
}
