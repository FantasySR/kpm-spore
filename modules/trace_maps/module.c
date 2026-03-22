/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>

#include "symbols.h"
#include "maps.h"

KPM_NAME("kpm-trace-maps");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Hide /proc/[pid]/maps injection traces");

static long trace_maps_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    pr_info("[trace] trace_maps module loading...\n");

    ret = init_kernel_offsets();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init kernel offsets\n");
    }

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[trace] failed to init symbols\n");
        return ret;
    }

    ret = install_maps_hook();
    if (ret == SUCCESS) {
        pr_info("[trace] maps hide: enabled\n");
    } else {
        pr_err("[trace] maps hide: failed\n");
    }

    pr_info("[trace] trace_maps loaded\n");
    return 0;
}

static long trace_maps_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *response = "trace_maps: maps=0|1, merge_so=0|1, status";

    if (!args) args = "";

    if (strncmp(args, "maps=1", 6) == 0) {
        set_maps_enabled(1);
        response = "maps: enabled";
    } else if (strncmp(args, "maps=0", 6) == 0) {
        set_maps_enabled(0);
        response = "maps: disabled";
    } else if (strncmp(args, "merge_so=1", 10) == 0) {
        set_merge_so_enabled(1);
        response = "merge_so: enabled";
    } else if (strncmp(args, "merge_so=0", 10) == 0) {
        set_merge_so_enabled(0);
        response = "merge_so: disabled";
    }

    if (out_msg && outlen > 0) {
        int len = strlen(response) + 1;
        int copy_len = (len < outlen) ? len : outlen;
        compat_copy_to_user(out_msg, response, copy_len);
    }

    return 0;
}

static long trace_maps_exit(void *__user reserved)
{
    uninstall_maps_hook();
    pr_info("[trace] trace_maps unloaded\n");
    return 0;
}

KPM_INIT(trace_maps_init);
KPM_CTL0(trace_maps_control0);
KPM_EXIT(trace_maps_exit);
