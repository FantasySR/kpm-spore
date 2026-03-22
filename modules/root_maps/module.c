/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include "symbols.h"
#include "maps.h"

KPM_NAME("kpm-root-maps");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Hide sensitive VMA entries from /proc/pid/maps");

static long root_maps_init(const char *args, const char *event, void *reserved)
{
    int ret;

    pr_info("[root] root_maps module loading...\n");

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[root] symbol resolution failed\n");
    }

    ret = install_maps_hook();
    if (ret == SUCCESS) {
        pr_info("[root] maps hiding installed\n");
    } else {
        pr_err("[root] maps hiding failed\n");
    }

    pr_info("[root] root_maps loaded\n");
    return SUCCESS;
}

static long root_maps_exit(void *reserved)
{
    uninstall_maps_hook();
    pr_info("[root] root_maps unloaded\n");
    return SUCCESS;
}

static long root_maps_control0(const char *args, char *out_msg, int out_len)
{
    const char *response = "root_maps: maps=0|1";

    if (args && kf_strstr) {
        if (kf_strstr(args, "enable")) {
            set_maps_hide_enabled(1);
            response = "maps: enabled";
        } else if (kf_strstr(args, "disable")) {
            set_maps_hide_enabled(0);
            response = "maps: disabled";
        }
    }

    if (out_msg && out_len > 0) {
        int len = 0;
        while (response[len] && len < out_len - 1) len++;
        compat_copy_to_user(out_msg, response, len + 1);
    }

    return SUCCESS;
}

KPM_INIT(root_maps_init);
KPM_EXIT(root_maps_exit);
KPM_CTL0(root_maps_control0);
