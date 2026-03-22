/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>

#include "symbols.h"
#include "mount.h"

KPM_NAME("kpm-trace-mount");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Hide sensitive mount points from /proc/mountinfo");

static long trace_mount_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    pr_info("[trace] trace_mount module loading...\n");

    ret = init_kernel_offsets();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init kernel offsets\n");
    }

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init symbols\n");
        return ret;
    }

    ret = install_mount_hooks();
    if (ret == SUCCESS) {
        pr_info("[trace] mount hide: enabled\n");
    } else {
        pr_err("[trace] mount hide: failed\n");
    }

    pr_info("[trace] trace_mount loaded\n");
    return 0;
}

static long trace_mount_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *response = "trace_mount: mount=0|1";

    if (!args) args = "";

    if (strncmp(args, "mount=1", 7) == 0) {
        set_mount_enabled(1);
        response = "mount: enabled";
    } else if (strncmp(args, "mount=0", 7) == 0) {
        set_mount_enabled(0);
        response = "mount: disabled";
    }

    if (out_msg && outlen > 0) {
        int len = strlen(response) + 1;
        int copy_len = (len < outlen) ? len : outlen;
        compat_copy_to_user(out_msg, response, copy_len);
    }

    return 0;
}

static long trace_mount_exit(void *__user reserved)
{
    uninstall_mount_hooks();
    pr_info("[trace] trace_mount unloaded\n");
    return 0;
}

KPM_INIT(trace_mount_init);
KPM_CTL0(trace_mount_control0);
KPM_EXIT(trace_mount_exit);
