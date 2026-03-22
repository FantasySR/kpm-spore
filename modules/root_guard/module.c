/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include "symbols.h"
#include "syscall.h"
#include "setuid.h"
#include "maps.h"
#include "probes.h"

KPM_NAME("kpm-root-guard");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("kpm-spore");
KPM_DESCRIPTION("[UNVERIFIED] Root detection bypass via syscall and VMA hooks");

static void rg_set_out_msg(char *__user out_msg, int out_len, const char *msg)
{
    if (!out_msg || out_len <= 0 || !msg) return;
    int len = 0;
    while (msg[len] && len < out_len - 1) len++;
    compat_copy_to_user(out_msg, msg, len + 1);
}

static int module_initialized = 0;
static int hooks_installed = 0;

static int feature_syscall_intercept = 1;
static int feature_maps_hide = 1;
static int feature_setuid_hook = 1;
static int feature_probes = 1;
static int feature_offset_discovery = 1;

static int install_all_hooks(void)
{
    int ret;
    int success_count = 0;
    int fail_count = 0;

    pr_info("[root] installing all hooks...\n");

    if (feature_probes) {
        ret = install_discovery_probes();
        if (ret == SUCCESS) {
            pr_info("[root] discovery probes installed\n");
        } else {
            pr_warn("[root] discovery probes failed\n");
        }
    }

    if (feature_syscall_intercept) {
        ret = install_syscall_hooks();
        if (ret == SUCCESS) {
            success_count++;
            pr_info("[root] syscall interception installed\n");
        } else {
            fail_count++;
            pr_warn("[root] syscall interception failed\n");
        }
    }

    if (feature_setuid_hook) {
        ret = install_setuid_hook();
        if (ret == SUCCESS) {
            success_count++;
            pr_info("[root] setuid hook installed\n");
        } else {
            fail_count++;
            pr_warn("[root] setuid hook failed\n");
        }
    }

    if (feature_maps_hide) {
        ret = install_maps_hook();
        if (ret == SUCCESS) {
            success_count++;
            pr_info("[root] maps hiding installed\n");
        } else {
            fail_count++;
            pr_warn("[root] maps hiding failed\n");
        }
    }

    hooks_installed = (success_count > 0);

    pr_info("[root] hooks installation: %d success, %d failed\n",
            success_count, fail_count);

    return (success_count > 0) ? SUCCESS : FAILED;
}

static void uninstall_all_hooks(void)
{
    pr_info("[root] uninstalling all hooks...\n");

    uninstall_discovery_probes();
    uninstall_syscall_hooks();
    uninstall_setuid_hook();
    uninstall_maps_hook();

    hooks_installed = 0;
    pr_info("[root] all hooks uninstalled\n");
}

static long root_guard_init(const char *args, const char *event, void *reserved)
{
    int ret;

    pr_info("[root] ============================================\n");
    pr_info("[root]   root_guard module loading\n");
    pr_info("[root] ============================================\n");

    pr_info("[root] initializing (kver=0x%x)...\n", kver);

    if (args && *args) {
        pr_info("[root] args: %s\n", args);

        if (kf_strstr) {
            if (kf_strstr(args, "full")) {
                feature_maps_hide = 1;
                feature_setuid_hook = 1;
                feature_probes = 1;
                pr_info("[root] full mode enabled by args\n");
            }
            if (kf_strstr(args, "maps")) {
                feature_maps_hide = 1;
            }
            if (kf_strstr(args, "setuid")) {
                feature_setuid_hook = 1;
            }
            if (kf_strstr(args, "probes")) {
                feature_probes = 1;
            }
            if (kf_strstr(args, "offsets")) {
                feature_offset_discovery = 1;
            }
            if (kf_strstr(args, "safe")) {
                feature_maps_hide = 0;
                feature_setuid_hook = 0;
                feature_probes = 0;
                feature_offset_discovery = 0;
                pr_info("[root] safe mode enabled by args\n");
            }
            if (kf_strstr(args, "nosyscall")) {
                feature_syscall_intercept = 0;
            }
            if (kf_strstr(args, "nomaps")) {
                feature_maps_hide = 0;
            }
            if (kf_strstr(args, "nosetuid")) {
                feature_setuid_hook = 0;
            }
            if (kf_strstr(args, "noprobes")) {
                feature_probes = 0;
            }
            if (kf_strstr(args, "nooffsets")) {
                feature_offset_discovery = 0;
            }
        }
    }

    pr_info("[root] step 1: resolving symbols...\n");
    ret = init_symbols();
    if (ret != SUCCESS) {
        pr_err("[root] symbol resolution failed\n");
    }

    if (feature_offset_discovery) {
        pr_info("[root] step 2: discovering kernel offsets...\n");
        ret = init_kernel_offsets();
        if (ret != SUCCESS) {
            pr_warn("[root] offset discovery incomplete, using fallbacks\n");
        }
    } else {
        pr_info("[root] step 2: kernel offset discovery skipped\n");
    }

    pr_info("[root] step 3: installing hooks...\n");
    ret = install_all_hooks();
    if (ret != SUCCESS) {
        pr_err("[root] hook installation failed\n");
        return ret;
    }

    module_initialized = 1;

    pr_info("[root] ============================================\n");
    pr_info("[root]   Initialization Complete!\n");
    pr_info("[root] ============================================\n");

    return SUCCESS;
}

static long root_guard_exit(void *reserved)
{
    pr_info("[root] exiting...\n");

    if (hooks_installed) {
        uninstall_all_hooks();
    }

    module_initialized = 0;

    pr_info("[root] module unloaded\n");
    return SUCCESS;
}

static long root_guard_control0(const char *args, char *out_msg, int out_len)
{
    if (!args || !*args) {
        goto return_status;
    }

    if (kf_strstr) {
        if (kf_strstr(args, "status")) {
            goto return_status;
        }

        if (kf_strstr(args, "enable")) {
            set_syscall_enabled(1);
            set_maps_hide_enabled(1);
            set_setuid_hook_enabled(1);
            if (out_msg && out_len > 0) {
                rg_set_out_msg(out_msg, out_len, "all features enabled");
            }
            return SUCCESS;
        }

        if (kf_strstr(args, "disable")) {
            set_syscall_enabled(0);
            set_maps_hide_enabled(0);
            set_setuid_hook_enabled(0);
            if (out_msg && out_len > 0) {
                rg_set_out_msg(out_msg, out_len, "all features disabled");
            }
            return SUCCESS;
        }

        if (kf_strstr(args, "stats")) {
            if (out_msg && out_len > 0) {
                rg_set_out_msg(out_msg, out_len, "stats: ok (see dmesg)");
            }
            return SUCCESS;
        }

        if (kf_strstr(args, "probes")) {
            if (out_msg && out_len > 0) {
                rg_set_out_msg(out_msg, out_len, "probes: ok (see dmesg)");
            }
            return SUCCESS;
        }
    }

return_status:
    if (out_msg && out_len > 0) {
        rg_set_out_msg(out_msg, out_len, "root_guard: ok (see dmesg)");
    }
    return SUCCESS;
}

static long root_guard_control1(void *a1, void *a2, void *a3)
{
    if (!a1) {
        return FAILED;
    }

    unsigned long cmd = (unsigned long)a1;

    switch (cmd) {
        case 1:
            if (hooks_installed) {
                uninstall_all_hooks();
            }
            return install_all_hooks();

        case 2:
            pr_info("[root] debug: initialized=%d, hooks=%d\n",
                    module_initialized, hooks_installed);
            pr_info("[root] offsets: task_mm=0x%x, mmap_lock=0x%x\n",
                    koffsets.task_mm_offset, koffsets.mm_mmap_lock_offset);
            return SUCCESS;

        default:
            return FAILED;
    }
}

KPM_INIT(root_guard_init);
KPM_EXIT(root_guard_exit);
KPM_CTL0(root_guard_control0);
KPM_CTL1(root_guard_control1);
