/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "symbols.h"
#include "syscall.h"
#include "probes.h"

KPM_NAME("kpm-root-syscall");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Syscall interception for root detection bypass");

static long root_syscall_init(const char *args, const char *event, void *reserved)
{
    int ret;

    pr_info("[root] root_syscall module loading...\n");

    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[root] symbol resolution failed\n");
    }

    ret = install_discovery_probes();
    if (ret == SUCCESS) {
        pr_info("[root] discovery probes installed\n");
    }

    ret = install_syscall_hooks();
    if (ret == SUCCESS) {
        pr_info("[root] syscall hooks installed\n");
    } else {
        pr_err("[root] syscall hooks failed\n");
    }

    pr_info("[root] root_syscall loaded\n");
    return SUCCESS;
}

static long root_syscall_exit(void *reserved)
{
    uninstall_discovery_probes();
    uninstall_syscall_hooks();
    pr_info("[root] root_syscall unloaded\n");
    return SUCCESS;
}

static long root_syscall_control0(const char *args, char *out_msg, int out_len)
{
    const char *response = "root_syscall: enable/disable";

    if (args && kf_strstr) {
        if (kf_strstr(args, "enable")) {
            set_syscall_enabled(1);
            response = "syscall: enabled";
        } else if (kf_strstr(args, "disable")) {
            set_syscall_enabled(0);
            response = "syscall: disabled";
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

KPM_INIT(root_syscall_init);
KPM_EXIT(root_syscall_exit);
KPM_CTL0(root_syscall_control0);
