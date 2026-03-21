/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>

#include "symbols.h"
#include "syscall.h"

KPM_NAME("kpm-trace-syscall");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Syscall interception for hiding sensitive paths and SELinux context");

static long trace_syscall_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    pr_info("[trace] trace_syscall module loading...\n");

    ret = init_kernel_offsets();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init kernel offsets\n");
    }

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init symbols\n");
        return ret;
    }

    ret = install_syscall_hooks();
    if (ret == SUCCESS) {
        pr_info("[trace] syscall hooks: enabled\n");
    } else {
        pr_err("[trace] syscall hooks: failed\n");
    }

    pr_info("[trace] trace_syscall loaded\n");
    return 0;
}

static long trace_syscall_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *response = "trace_syscall: syscall=0|1, readlink/getdents/truncate/fgetxattr/getsockopt=0|1";

    if (!args) args = "";

    if (strncmp(args, "syscall=1", 9) == 0) {
        set_syscall_enabled(1);
        response = "syscall: enabled";
    } else if (strncmp(args, "syscall=0", 9) == 0) {
        set_syscall_enabled(0);
        response = "syscall: disabled";
    } else if (strncmp(args, "readlink=1", 10) == 0) {
        set_readlink_enabled(1);
        response = "readlink: enabled";
    } else if (strncmp(args, "readlink=0", 10) == 0) {
        set_readlink_enabled(0);
        response = "readlink: disabled";
    } else if (strncmp(args, "getdents=1", 10) == 0) {
        set_getdents_enabled(1);
        response = "getdents: enabled";
    } else if (strncmp(args, "getdents=0", 10) == 0) {
        set_getdents_enabled(0);
        response = "getdents: disabled";
    } else if (strncmp(args, "truncate=1", 10) == 0) {
        set_truncate_enabled(1);
        response = "truncate: enabled";
    } else if (strncmp(args, "truncate=0", 10) == 0) {
        set_truncate_enabled(0);
        response = "truncate: disabled";
    } else if (strncmp(args, "fgetxattr=1", 11) == 0) {
        set_fgetxattr_enabled(1);
        response = "fgetxattr: enabled";
    } else if (strncmp(args, "fgetxattr=0", 11) == 0) {
        set_fgetxattr_enabled(0);
        response = "fgetxattr: disabled";
    } else if (strncmp(args, "getsockopt=1", 12) == 0) {
        set_getsockopt_enabled(1);
        response = "getsockopt: enabled";
    } else if (strncmp(args, "getsockopt=0", 12) == 0) {
        set_getsockopt_enabled(0);
        response = "getsockopt: disabled";
    }

    if (out_msg && outlen > 0) {
        int len = strlen(response) + 1;
        int copy_len = (len < outlen) ? len : outlen;
        compat_copy_to_user(out_msg, response, copy_len);
    }

    return 0;
}

static long trace_syscall_exit(void *__user reserved)
{
    uninstall_syscall_hooks();
    pr_info("[trace] trace_syscall unloaded\n");
    return 0;
}

KPM_INIT(trace_syscall_init);
KPM_CTL0(trace_syscall_control0);
KPM_EXIT(trace_syscall_exit);
