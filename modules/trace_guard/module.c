/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>

#include "symbols.h"
#include "maps.h"
#include "mount.h"
#include "syscall.h"
#include "debug.h"

KPM_NAME("kpm-trace-guard");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Hide injection traces, mount points, and debug info");

static void append_text(char *buf, int *pos, int max, const char *text)
{
    while (text && *text && *pos < max - 1) {
        buf[(*pos)++] = *text++;
    }
}

static void append_flag(char *buf, int *pos, int max, const char *key, int enabled)
{
    append_text(buf, pos, max, key);
    if (*pos < max - 1) {
        buf[(*pos)++] = enabled ? '1' : '0';
    }
    if (*pos < max - 1) {
        buf[(*pos)++] = ' ';
    }
}

static const char *build_status_str(void)
{
    static char resp[256];
    int pos = 0;

    resp[0] = '\0';
    append_flag(resp, &pos, (int)sizeof(resp), "merge_so=", get_merge_so_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "maps=", get_maps_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "mount=", get_mount_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "syscall=", get_syscall_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "debug=", get_debug_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "readlink=", get_readlink_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "getdents=", get_getdents_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "truncate=", get_truncate_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "fgetxattr=", get_fgetxattr_enabled());
    append_flag(resp, &pos, (int)sizeof(resp), "getsockopt=", get_getsockopt_enabled());

    if (pos > 0 && pos <= (int)sizeof(resp)) {
        resp[pos - 1] = '\0';
    } else {
        resp[(int)sizeof(resp) - 1] = '\0';
    }
    return resp;
}

static long trace_guard_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    pr_info("[trace] ========================================\n");
    pr_info("[trace] trace_guard module loading...\n");
    pr_info("[trace] kernel version: 0x%x\n", kver);
    pr_info("[trace] ========================================\n");

    ret = init_kernel_offsets();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init kernel offsets\n");
    }

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init symbols, some features disabled\n");
    }

    ret = install_maps_hook();
    if (ret == SUCCESS) {
        pr_info("[trace] maps hide: enabled\n");
    } else {
        pr_err("[trace] maps hide: failed\n");
    }

    ret = install_mount_hooks();
    if (ret == SUCCESS) {
        pr_info("[trace] mount hide: enabled\n");
    } else {
        pr_err("[trace] mount hide: failed\n");
    }

    ret = install_syscall_hooks();
    if (ret == SUCCESS) {
        pr_info("[trace] syscall hide: enabled\n");
    } else {
        pr_err("[trace] syscall hide: failed\n");
    }

    ret = install_debug_hooks();
    if (ret == SUCCESS) {
        pr_info("[trace] debug hide: enabled\n");
    } else {
        pr_err("[trace] debug hide: failed\n");
    }

    pr_info("[trace] module loaded successfully\n");
    return 0;
}

static long trace_guard_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *response;

    pr_info("[trace] control0 called, args: %s\n", args ? args : "(null)");

    if (!args) {
        args = "";
    }

    if (strncmp(args, "safe=1", 6) == 0) {
        set_merge_so_enabled(0);
        set_maps_enabled(0);
        set_mount_enabled(0);
        set_syscall_enabled(0);
        set_debug_enabled(0);
        set_readlink_enabled(0);
        set_getdents_enabled(0);
        set_truncate_enabled(0);
        set_fgetxattr_enabled(0);
        set_getsockopt_enabled(0);
        response = "safe: enabled (all hooks disabled)";
    } else if (strncmp(args, "safe=0", 6) == 0) {
        set_maps_enabled(1);
        set_mount_enabled(1);
        set_syscall_enabled(1);
        set_debug_enabled(1);
        set_readlink_enabled(1);
        set_getdents_enabled(0);
        set_truncate_enabled(1);
        set_fgetxattr_enabled(1);
        set_getsockopt_enabled(1);
        response = "safe: disabled (hooks enabled, merge_so/getdents default off)";
    } else if (strncmp(args, "merge_so=1", 10) == 0) {
        set_merge_so_enabled(1);
        response = "merge_so: enabled";
    } else if (strncmp(args, "merge_so=0", 10) == 0) {
        set_merge_so_enabled(0);
        response = "merge_so: disabled";
    } else if (strncmp(args, "maps=1", 6) == 0) {
        set_maps_enabled(1);
        response = "maps: enabled";
    } else if (strncmp(args, "maps=0", 6) == 0) {
        set_maps_enabled(0);
        response = "maps: disabled";
    } else if (strncmp(args, "mount=1", 7) == 0) {
        set_mount_enabled(1);
        response = "mount: enabled";
    } else if (strncmp(args, "mount=0", 7) == 0) {
        set_mount_enabled(0);
        response = "mount: disabled";
    } else if (strncmp(args, "syscall=1", 9) == 0) {
        set_syscall_enabled(1);
        response = "syscall: enabled";
    } else if (strncmp(args, "syscall=0", 9) == 0) {
        set_syscall_enabled(0);
        response = "syscall: disabled";
    } else if (strncmp(args, "debug=1", 7) == 0) {
        set_debug_enabled(1);
        response = "debug: enabled";
    } else if (strncmp(args, "debug=0", 7) == 0) {
        set_debug_enabled(0);
        response = "debug: disabled";
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
    } else if (strncmp(args, "status", 6) == 0) {
        response = build_status_str();
    } else {
        response = "trace_guard: safe=0|1, maps=0|1, mount=0|1, syscall=0|1, debug=0|1, readlink/getdents/truncate/fgetxattr/getsockopt=0|1, merge_so=0|1, status";
    }

    if (out_msg && outlen > 0) {
        int len = strlen(response) + 1;
        int copy_len = (len < outlen) ? len : outlen;
        compat_copy_to_user(out_msg, response, copy_len);
    }

    return 0;
}

static long trace_guard_control1(void *a1, void *a2, void *a3)
{
    pr_info("[trace] control1 called: a1=%llx, a2=%llx, a3=%llx\n",
            (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
    return 0;
}

static long trace_guard_exit(void *__user reserved)
{
    pr_info("[trace] module unloading...\n");

    uninstall_maps_hook();
    uninstall_mount_hooks();
    uninstall_syscall_hooks();
    uninstall_debug_hooks();

    pr_info("[trace] module unloaded\n");
    return 0;
}

KPM_INIT(trace_guard_init);
KPM_CTL0(trace_guard_control0);
KPM_CTL1(trace_guard_control1);
KPM_EXIT(trace_guard_exit);
