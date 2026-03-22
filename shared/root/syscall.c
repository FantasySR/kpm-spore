/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */
/*
 * Syscall interception
 *
 * Architecture:
 * 1. Uses KernelPatch fp_wrap_syscalln API for syscall hooking
 * 2. Before/after hooks detect sensitive paths and modify return values
 * 3. Supports native (64-bit) and compat (32-bit) modes
 *
 * Target syscalls:
 *   - faccessat (48): hide sensitive file existence
 *   - readlinkat (78): hide sensitive symlink targets
 *   - execve (221): monitor suspicious executions
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <kconfig.h>
#include <syscall.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>
#include <sucompat.h>
#include "symbols.h"
#include "syscall.h"

#ifndef pr_debug
#define pr_debug(fmt, ...) do { } while (0)
#endif

/*
 * ============================================================
 * Constants
 * ============================================================
 */

/* ARM64 syscall numbers */
#ifndef __NR_faccessat
#define __NR_faccessat      48
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat     78
#endif
#ifndef __NR_execve
#define __NR_execve         221
#endif
#ifndef __NR_openat
#define __NR_openat         56
#endif

/*
 * ============================================================
 * Global variables
 * ============================================================
 */

/* Interception mode */
/* -1 = compat mode, 0 = initializing, 1 = native mode */
static int interception_mode = 0;

/* Hook state */
static int faccessat_hooked = 0;
static int readlinkat_hooked = 0;
static int execve_hooked = 0;
static int syscall_enabled = 1;

/*
 * ============================================================
 * Exclude list check
 * ============================================================
 *
 * Gating logic:
 *   current_uid();
 *   if (get_ap_mod_exclude(uid) == 0) return;  // skip
 *
 * Only continue interception when get_ap_mod_exclude(uid) != 0.
 */

static inline int rg_pass_exclude_gate_uid(uid_t uid)
{
    return get_ap_mod_exclude(uid) != 0;
}

/*
 * Match only the path component "/su" (avoid false positives like "/support")
 */
static int path_has_su_component(const char *path)
{
    const char *p;

    if (!path || !kf_strstr) return 0;

    p = path;
    while ((p = kf_strstr(p, "/su")) != NULL) {
        char next = p[3]; /* character after "/su" */
        if (next == '\0' || next == '/') {
            return 1;
        }
        /* Continue searching to avoid infinite loop */
        p += 3;
    }

    return 0;
}

/*
 * APatch artifact path matching (avoid false positives on app private data dirs)
 *
 * Intercepting /data/user/0/<pkg> paths can cause apps to crash
 * because they do faccessat/stat checks on their own data directories.
 */
static int path_has_apatch_artifact(const char *path)
{
    if (!path || !kf_strstr) return 0;
    if (!kf_strstr(path, "apatch")) return 0;

    /* Avoid intercepting app private directories (reduce false positives) */
    if (kf_strstr(path, "/data/user/") || kf_strstr(path, "/data/data/")) {
        return 0;
    }

    return 1;
}

/*
 * ============================================================
 * faccessat Hook
 * Hide su/magisk/busybox related files
 * ============================================================
 */

static void faccessat_before_hook(hook_fargs4_t *args, void *udata)
{
    char path_buf[256];
    char __user *pathname;
    uid_t uid;

    if (!syscall_enabled) {
        return;
    }

    uid = current_uid();
    if (!rg_pass_exclude_gate_uid(uid)) {
        return;
    }

    /* Get argument via syscall_argn */
    pathname = (char __user *)syscall_argn(args, 1);
    if (!pathname) {
        return;
    }

    if (compat_strncpy_from_user(path_buf, pathname, sizeof(path_buf)) <= 0) {
        return;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    if (kf_strstr) {
        /* Check for sensitive paths */
        if (path_has_su_component(path_buf) ||
            kf_strstr(path_buf, "magisk") ||
            kf_strstr(path_buf, "busybox") ||
            kf_strstr(path_buf, "supersu") ||
            kf_strstr(path_buf, "kernelsu") ||
            path_has_apatch_artifact(path_buf)) {
            /* Return -ENOENT */
            args->skip_origin = 1;
            args->ret = -2;  /* ENOENT */
            pr_info("[root] faccessat blocked: %s\n", path_buf);
        }
    }
}

/*
 * ============================================================
 * readlinkat Hook
 * Hide symlink targets pointing to sensitive locations
 * ============================================================
 */

static void readlinkat_after_hook(hook_fargs4_t *args, void *udata)
{
    char kbuf[256];
    char __user *pathname;
    char __user *buf;
    long ret;
    size_t n;
    size_t bufsiz;
    char path_buf[256];
    uid_t uid;

    if (!syscall_enabled) {
        return;
    }

    uid = current_uid();
    if (!rg_pass_exclude_gate_uid(uid)) {
        return;
    }

    ret = (long)args->ret;
    if (ret <= 0) {
        return;
    }

    /* Get arguments via syscall_argn */
    pathname = (char __user *)syscall_argn(args, 1);
    buf = (char __user *)syscall_argn(args, 2);
    bufsiz = (size_t)syscall_argn(args, 3);

    if (!buf) {
        return;
    }

    /* Only process /proc/ related paths */
    if (pathname) {
        if (compat_strncpy_from_user(path_buf, pathname, sizeof(path_buf)) > 0) {
            path_buf[sizeof(path_buf) - 1] = '\0';
            if (!kf_strstr || !kf_strstr(path_buf, "/proc/")) {
                return;
            }
        }
    }

    /* Check result */
    if (!kf_raw_copy_from_user) {
        return;
    }

    n = (size_t)ret;
    if (n >= sizeof(kbuf)) {
        n = sizeof(kbuf) - 1;
    }

    if (kf_raw_copy_from_user(kbuf, buf, n) != 0) {
        return;
    }
    kbuf[n] = '\0';

    if (kf_strstr) {
        if (kf_strstr(kbuf, "magisk") ||
            kf_strstr(kbuf, "zygisk") ||
            kf_strstr(kbuf, "lsposed") ||
            kf_strstr(kbuf, "riru")) {
            /* Replace with /dev/null */
            const char *fake = "/dev/null";
            size_t fake_len = 9;
            if (bufsiz > fake_len) {
                compat_copy_to_user(buf, fake, fake_len);
                args->ret = fake_len;
                pr_info("[root] readlinkat replaced: %s -> %s\n", kbuf, fake);
            }
        }
    }
}

/*
 * ============================================================
 * execve Hook
 * Monitor suspicious executions (no blocking, logging only)
 * ============================================================
 */

static void execve_before_hook(hook_fargs3_t *args, void *udata)
{
    char path_buf[256];
    char __user *filename;
    uid_t uid;

    if (!syscall_enabled) {
        return;
    }

    uid = current_uid();
    if (!rg_pass_exclude_gate_uid(uid)) {
        return;
    }

    filename = (char __user *)syscall_argn(args, 0);
    if (!filename) {
        return;
    }

    if (compat_strncpy_from_user(path_buf, filename, sizeof(path_buf)) <= 0) {
        return;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    if (kf_strstr) {
        if (kf_strstr(path_buf, "su") ||
            kf_strstr(path_buf, "magisk")) {
            pr_debug("[root] execve detected: %s\n", path_buf);
        }
    }
}

/*
 * ============================================================
 * Install hooks
 * ============================================================
 */

int install_syscall_hooks(void)
{
    int ret;

    pr_info("[root] installing syscall hooks...\n");

    /* Hook faccessat - before */
    ret = fp_wrap_syscalln(__NR_faccessat, 4, 0,
                          (void *)faccessat_before_hook, NULL, NULL);
    if (ret == 0) {
        faccessat_hooked = 1;
        pr_info("[root] faccessat hook installed\n");
    } else {
        pr_warn("[root] faccessat hook failed: %d\n", ret);
    }

    /* Hook readlinkat - after */
    ret = fp_wrap_syscalln(__NR_readlinkat, 4, 0,
                          NULL, (void *)readlinkat_after_hook, NULL);
    if (ret == 0) {
        readlinkat_hooked = 1;
        pr_info("[root] readlinkat hook installed\n");
    } else {
        pr_warn("[root] readlinkat hook failed: %d\n", ret);
    }

    /* Hook execve - before (monitoring only) */
    ret = fp_wrap_syscalln(__NR_execve, 3, 0,
                          (void *)execve_before_hook, NULL, NULL);
    if (ret == 0) {
        execve_hooked = 1;
        pr_info("[root] execve hook installed\n");
    } else {
        pr_warn("[root] execve hook failed: %d\n", ret);
    }

    /* Set interception mode: current implementation only installs native syscall hooks */
    interception_mode = 1;   /* native mode */
    pr_info("[root] interception mode: native (1)\n");

    pr_info("[root] syscall hooks active\n");
    return SUCCESS;
}

/*
 * Uninstall hooks
 */
void uninstall_syscall_hooks(void)
{
    /* KPM does not provide syscall unhook API, removed on reboot */
    pr_info("[root] syscall hooks will be removed on reboot\n");

    faccessat_hooked = 0;
    readlinkat_hooked = 0;
    execve_hooked = 0;
    interception_mode = 0;
}

/*
 * Feature toggle
 */
void set_syscall_enabled(int enabled)
{
    syscall_enabled = enabled ? 1 : 0;
    pr_info("[root] syscall interception %s\n",
            syscall_enabled ? "enabled" : "disabled");
}

int get_syscall_enabled(void)
{
    return syscall_enabled;
}

/*
 * Get/set interception mode
 */
int get_interception_mode(void)
{
    return interception_mode;
}

void set_interception_mode(int mode)
{
    interception_mode = mode;
    pr_info("[root] interception mode set to %d\n", mode);
}
