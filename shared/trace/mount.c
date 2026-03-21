/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

/*
 * Mount point hiding feature
 *
 * Hooks show_vfsmnt/show_mountinfo/show_vfsstat to hide
 * sensitive mount points (APatch, Magisk modules, etc.)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>
#include "symbols.h"
#include "mount.h"

/* Simplified seq_file structure */
struct seq_file_simple {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
};

/* Mount point keywords to hide */
static const char *mount_hide_keywords[] = {
    "APatch",
    "apatch",
    "magisk",
    "Magisk",
    "revanced",
    "zygisk",
    "dex2oat",
    "/data/adb/modules",
    "/data/adb/ap",
    "/data/adb/ksu",
    NULL
};

static int vfsmnt_hook_installed = 0;
static int mountinfo_hook_installed = 0;
static int vfsstat_hook_installed = 0;

/* Mount feature master switch: 0=off, 1=on */
static int mount_enabled = 1;

static inline int should_filter(void)
{
    return current_uid() > 10000;
}

/*
 * Check if a mount point path should be hidden
 */
static int should_hide_mount(const char *path, size_t len)
{
    const char **keyword;

    for (keyword = mount_hide_keywords; *keyword; keyword++) {
        if (strnstr(path, *keyword, len)) {
            return 1;
        }
    }
    return 0;
}

/* show_vfsmnt hook */
static void vfsmnt_before_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m = (struct seq_file_simple *)args->arg0;
    args->local.data0 = m->count;
}

static void vfsmnt_after_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m;
    size_t old_count, new_count;
    char *content;
    size_t len;

    if (!should_filter()) {
        return;
    }

    if (!mount_enabled) {
        return;
    }

    m = (struct seq_file_simple *)args->arg0;
    old_count = (size_t)args->local.data0;
    new_count = m->count;

    if (new_count <= old_count || !m->buf) {
        return;
    }

    content = m->buf + old_count;
    len = new_count - old_count;

    if (should_hide_mount(content, len)) {
        m->count = old_count;
        pr_info("[trace] hide mount entry\n");
    }
}

/* show_mountinfo hook - uses same logic */
static void mountinfo_before_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m = (struct seq_file_simple *)args->arg0;
    args->local.data0 = m->count;
}

static void mountinfo_after_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m;
    size_t old_count, new_count;
    char *content;
    size_t len;

    if (!should_filter()) {
        return;
    }

    if (!mount_enabled) {
        return;
    }

    m = (struct seq_file_simple *)args->arg0;
    old_count = (size_t)args->local.data0;
    new_count = m->count;

    if (new_count <= old_count || !m->buf) {
        return;
    }

    content = m->buf + old_count;
    len = new_count - old_count;

    if (should_hide_mount(content, len)) {
        m->count = old_count;
    }
}

/* show_vfsstat hook */
static void vfsstat_before_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m = (struct seq_file_simple *)args->arg0;
    args->local.data0 = m->count;
}

static void vfsstat_after_hook(hook_fargs3_t *args, void *udata)
{
    struct seq_file_simple *m;
    size_t old_count, new_count;
    char *content;
    size_t len;

    if (!should_filter()) {
        return;
    }

    if (!mount_enabled) {
        return;
    }

    m = (struct seq_file_simple *)args->arg0;
    old_count = (size_t)args->local.data0;
    new_count = m->count;

    if (new_count <= old_count || !m->buf) {
        return;
    }

    content = m->buf + old_count;
    len = new_count - old_count;

    if (should_hide_mount(content, len)) {
        m->count = old_count;
    }
}

int install_mount_hooks(void)
{
    int ret;

    /* Hook show_vfsmnt */
    if (kf_show_vfsmnt && !vfsmnt_hook_installed) {
        ret = hook_wrap((void *)kf_show_vfsmnt, 3,
                        (void *)vfsmnt_before_hook,
                        (void *)vfsmnt_after_hook,
                        NULL);
        if (ret == 0) {
            vfsmnt_hook_installed = 1;
            pr_info("[trace] show_vfsmnt hook installed\n");
        } else {
            pr_err("[trace] failed to hook show_vfsmnt: %d\n", ret);
        }
    }

    /* Hook show_mountinfo */
    if (kf_show_mountinfo && !mountinfo_hook_installed) {
        ret = hook_wrap((void *)kf_show_mountinfo, 3,
                        (void *)mountinfo_before_hook,
                        (void *)mountinfo_after_hook,
                        NULL);
        if (ret == 0) {
            mountinfo_hook_installed = 1;
            pr_info("[trace] show_mountinfo hook installed\n");
        } else {
            pr_err("[trace] failed to hook show_mountinfo: %d\n", ret);
        }
    }

    /* Hook show_vfsstat */
    if (kf_show_vfsstat && !vfsstat_hook_installed) {
        ret = hook_wrap((void *)kf_show_vfsstat, 3,
                        (void *)vfsstat_before_hook,
                        (void *)vfsstat_after_hook,
                        NULL);
        if (ret == 0) {
            vfsstat_hook_installed = 1;
            pr_info("[trace] show_vfsstat hook installed\n");
        } else {
            pr_err("[trace] failed to hook show_vfsstat: %d\n", ret);
        }
    }

    return SUCCESS;
}

void uninstall_mount_hooks(void)
{
    if (vfsmnt_hook_installed && kf_show_vfsmnt) {
        unhook((void *)kf_show_vfsmnt);
        vfsmnt_hook_installed = 0;
    }

    if (mountinfo_hook_installed && kf_show_mountinfo) {
        unhook((void *)kf_show_mountinfo);
        mountinfo_hook_installed = 0;
    }

    if (vfsstat_hook_installed && kf_show_vfsstat) {
        unhook((void *)kf_show_vfsstat);
        vfsstat_hook_installed = 0;
    }

    pr_info("[trace] mount hooks uninstalled\n");
}

void set_mount_enabled(int enabled)
{
    mount_enabled = enabled ? 1 : 0;
    pr_info("[trace] mount feature %s\n", mount_enabled ? "enabled" : "disabled");
}

int get_mount_enabled(void)
{
    return mount_enabled;
}
