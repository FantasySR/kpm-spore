/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "symbols.h"
#include "setuid.h"
#include "maps.h"

KPM_NAME("kpm-root-setuid");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Zygote/setuid hook for root detection bypass");

static long root_setuid_init(const char *args, const char *event, void *reserved)
{
    int ret;

    pr_info("[root] root_setuid module loading...\n");

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[root] symbol resolution failed\n");
    }

    ret = init_kernel_offsets();
    if (ret != SUCCESS) {
        pr_warn("[root] offset discovery incomplete\n");
    }

    /* maps hook needed for should_hide_vma */
    ret = install_maps_hook();
    if (ret == SUCCESS) {
        pr_info("[root] maps hiding installed\n");
    }

    ret = install_setuid_hook();
    if (ret == SUCCESS) {
        pr_info("[root] setuid hook installed\n");
    } else {
        pr_err("[root] setuid hook failed\n");
    }

    pr_info("[root] root_setuid loaded\n");
    return SUCCESS;
}

static long root_setuid_exit(void *reserved)
{
    uninstall_setuid_hook();
    uninstall_maps_hook();
    pr_info("[root] root_setuid unloaded\n");
    return SUCCESS;
}

static long root_setuid_control0(const char *args, char *out_msg, int out_len)
{
    const char *response = "root_setuid: enable/disable";

    if (args && kf_strstr) {
        if (kf_strstr(args, "enable")) {
            set_setuid_hook_enabled(1);
            response = "setuid: enabled";
        } else if (kf_strstr(args, "disable")) {
            set_setuid_hook_enabled(0);
            response = "setuid: disabled";
        }
    }

    if (out_msg && out_len > 0) {
        int i = 0;
        while (i < out_len - 1 && response[i]) {
            out_msg[i] = response[i];
            i++;
        }
        out_msg[i] = '\0';
    }

    return SUCCESS;
}

KPM_INIT(root_setuid_init);
KPM_EXIT(root_setuid_exit);
KPM_CTL0(root_setuid_control0);
