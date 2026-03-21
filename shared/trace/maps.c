/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

/*
 * Maps hiding feature
 *
 * Hooks show_map_vma and rolls back seq_file count pointer
 * in the after callback if the output contains sensitive keywords.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>
#include "symbols.h"
#include "maps.h"

/* Simplified seq_file structure - only need access to buf and count */
struct seq_file_simple {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
    /* remaining fields omitted */
};

/*
 * ============================================================
 * merge_so_list feature - disabled by default
 *
 * Merges multiple memory mapping regions of the same shared library.
 * When an executable segment of a specific library is detected,
 * its end address is merged into the previous same-name mapping,
 * then the current line is hidden.
 * ============================================================
 */

/* Maps feature master switch: 0=off, 1=on */
static int maps_enabled = 1;

/* Feature switch: 0=off, 1=on */
static int merge_so_enabled = 0;

/* List of shared libraries to merge */
static const char *merge_so_libs[] = {
    "libmtguard.so",
    "libc.so",
    "libandroid_runtime.so",
    "libselinux.so",
    "libart.so",
    NULL
};

/* List of application package names that need this feature */
static const char *merge_so_apps[] = {
    "com.Qunar",
    "com.zhenxi.hunter",
    "com.marriott.mrt",
    "com.tongcheng.android",
    "com.autonavi.minimap",
    "com.cahx.gw1",
    "com.android.envtest",
    "com.vnpay.Agribank3g",
    "com.dianping.v1",
    "icu.nullptr.nativetest",
    "com.sankuai.meituan",
    "com.xjy.myapplication",
    "com.wizzair.WizzAirApp",
    "ph.com.gotyme",
    "th.co.truemoney.wallet",
    "com.lucky.luckyclient",
    "com.org.dobby_qbdi",
    "com.sbi.lotusintouch",
    "com.vietinbank.ipay",
    "com.kasikorn.retail.mbanking.wap",
    "id.bmri.livin",
    "com.scb.phone",
    "com.csair.mbp",
    "com.TMBTOUCH.PRODUCTION",
    "com.kasikornbank.kbiz",
    "com.rytong.ceair",
    "com.bca.mybca.omni.android",
    "com.mobikwik_new",
    "io.liankong.riskdetector",
    NULL
};

/*
 * ============================================================
 * Basic hiding feature
 * ============================================================
 */

/* Hide keyword list */
static const char *hide_keywords[] = {
    /* Frida related - obfuscated string: fxoda = frida */
    "fxoda-bgent-64.so",

    /* Custom injection cache */
    "/memfd:jit-cache",

    /* Custom injection library */
    "libhhh.so",

    /* Zygisk related - only detect full memfd paths */
    "/memfd:jit-cache-zygisk_gadget",
    "/memfd:jit-cache-zygisk_lsposed",

    /* DEX anonymous mappings */
    "anon:dalvik-DEX",

    NULL
};

/*
 * Anonymous mapping detection: check for "xp 00000000 00:00 0"
 * but exclude [vdso] and [anon: prefixed legitimate mappings
 */
static const char *anon_pattern = "xp 00000000 00:00 0";
static const char *anon_excludes[] = {
    "[vdso]",
    "[anon:",
    NULL
};

static int hook_installed = 0;

/*
 * Check if the current process should be filtered.
 * Only applies to regular app processes with UID > 10000.
 */
static inline int should_filter(void)
{
    return current_uid() > 10000;
}

/*
 * Check if buffer content contains sensitive keywords
 */
static int contains_sensitive(const char *buf, size_t len)
{
    const char **keyword;
    const char **exclude;
    int is_anon_exec = 0;

    /* 1. Check explicit sensitive keywords */
    for (keyword = hide_keywords; *keyword; keyword++) {
        if (strnstr(buf, *keyword, len)) {
            return 1;
        }
    }

    /* 2. Check suspicious anonymous executable mappings */
    if (strnstr(buf, anon_pattern, len)) {
        is_anon_exec = 1;
        /* Exclude legitimate anonymous mappings */
        for (exclude = anon_excludes; *exclude; exclude++) {
            if (strnstr(buf, *exclude, len)) {
                is_anon_exec = 0;
                break;
            }
        }
        if (is_anon_exec) {
            return 1;
        }
    }

    return 0;
}

/*
 * ============================================================
 * merge_so_list implementation
 * ============================================================
 */

/*
 * Check if the current line contains a library that needs merging.
 * Returns: pointer to the matched library name, or NULL
 */
static const char *find_merge_so(const char *line, size_t len)
{
    const char **so;

    if (!merge_so_enabled) {
        return NULL;
    }

    for (so = merge_so_libs; *so; so++) {
        if (strnstr(line, *so, len)) {
            return *so;
        }
    }

    /* Also check application package names */
    for (so = merge_so_apps; *so; so++) {
        if (strnstr(line, *so, len)) {
            return *so;
        }
    }

    return NULL;
}

/*
 * Check if the line is an executable mapping (r-xp or rwxp)
 */
static int is_executable_mapping(const char *line, size_t len)
{
    return (strnstr(line, "r-xp", len) != NULL ||
            strnstr(line, "rwxp", len) != NULL);
}

/*
 * Find the start of the previous line in buf.
 * Returns pointer to the previous line start, or NULL if none.
 */
static char *find_prev_line_start(char *buf, char *current_line_start)
{
    char *p;

    if (current_line_start <= buf) {
        return NULL;
    }

    /* Skip newline before the current line */
    p = current_line_start - 1;
    if (p <= buf) {
        return NULL;
    }

    /* Search backwards for the previous newline */
    while (p > buf && *(p - 1) != '\n') {
        p--;
    }

    return p;
}

/*
 * Merge memory mapping addresses
 *
 * maps format: start-end perms offset dev inode pathname
 * e.g.: 7f8b1000-7f8b2000 r-xp 00000000 08:01 12345 /path/to/lib.so
 *
 * Operation: copy the end address from the current line to the previous line
 */
static void merge_mapping_address(struct seq_file_simple *m,
                                  char *current_line,
                                  size_t current_len,
                                  size_t old_count)
{
    char *prev_line;
    char *curr_dash;       /* '-' position in current line */
    char *prev_dash;       /* '-' position in previous line */
    char *curr_end_addr;   /* start of end address in current line */
    char *curr_end_space;  /* space after end address in current line */
    char *prev_end_space;  /* space after end address in previous line */
    size_t addr_len;

    /* Find the previous line */
    prev_line = find_prev_line_start(m->buf, current_line);
    if (!prev_line) {
        return;
    }

    /* Find '-' in current line */
    curr_dash = NULL;
    for (char *p = current_line; p < current_line + current_len && *p != '\n'; p++) {
        if (*p == '-') {
            curr_dash = p;
            break;
        }
    }
    if (!curr_dash) {
        return;
    }

    /* End address starts after '-' */
    curr_end_addr = curr_dash + 1;

    /* Find space after end address in current line */
    curr_end_space = NULL;
    for (char *p = curr_end_addr; p < current_line + current_len && *p != '\n'; p++) {
        if (*p == ' ') {
            curr_end_space = p;
            break;
        }
    }
    if (!curr_end_space) {
        return;
    }

    /* Find '-' in previous line */
    prev_dash = NULL;
    for (char *p = prev_line; p < current_line && *p != '\n'; p++) {
        if (*p == '-') {
            prev_dash = p;
            break;
        }
    }
    if (!prev_dash) {
        return;
    }

    /* Find space after end address in previous line */
    prev_end_space = NULL;
    for (char *p = prev_dash + 1; p < current_line && *p != '\n'; p++) {
        if (*p == ' ') {
            prev_end_space = p;
            break;
        }
    }
    if (!prev_end_space) {
        return;
    }

    /* Calculate address length and copy */
    addr_len = curr_end_space - curr_end_addr;
    if (addr_len > 0 && addr_len <= 16) {  /* max 16 chars for address */
        /* Ensure previous line has enough space */
        size_t prev_addr_len = prev_end_space - (prev_dash + 1);
        if (prev_addr_len == addr_len) {
            /* Overwrite directly */
            kf_memcpy(prev_dash + 1, curr_end_addr, addr_len);
            pr_info("[trace] merge so mapping\n");
        }
    }

    /* Roll back count to hide current line */
    m->count = old_count;
}

/*
 * show_map_vma before hook
 * Record the current count position
 */
static void maps_before_hook(hook_fargs2_t *args, void *udata)
{
    struct seq_file_simple *m = (struct seq_file_simple *)args->arg0;

    /* Save current count to local variable */
    args->local.data0 = m->count;
}

/*
 * show_map_vma after hook
 * Check new content and roll back if it contains sensitive keywords
 */
static void maps_after_hook(hook_fargs2_t *args, void *udata)
{
    struct seq_file_simple *m;
    size_t old_count, new_count;
    char *new_content;
    size_t content_len;
    const char *merge_target;

    if (!should_filter()) {
        return;
    }

    if (!maps_enabled) {
        return;
    }

    m = (struct seq_file_simple *)args->arg0;
    old_count = (size_t)args->local.data0;
    new_count = m->count;

    if (new_count <= old_count || !m->buf) {
        return;
    }

    new_content = m->buf + old_count;
    content_len = new_count - old_count;

    /* 1. Check merge_so_list feature (if enabled) */
    if (merge_so_enabled) {
        merge_target = find_merge_so(new_content, content_len);
        if (merge_target && is_executable_mapping(new_content, content_len)) {
            merge_mapping_address(m, new_content, content_len, old_count);
            return;  /* Already handled, no further checking needed */
        }
    }

    /* 2. Check sensitive keywords */
    if (contains_sensitive(new_content, content_len)) {
        /* Roll back count to hide this line */
        m->count = old_count;
        pr_info("[trace] hide maps entry\n");
    }
}

/*
 * Enable/disable merge_so feature
 * Can be called via module control interface
 */
void set_merge_so_enabled(int enabled)
{
    merge_so_enabled = enabled ? 1 : 0;
    pr_info("[trace] merge_so feature %s\n",
            merge_so_enabled ? "enabled" : "disabled");
}

int get_merge_so_enabled(void)
{
    return merge_so_enabled;
}

void set_maps_enabled(int enabled)
{
    maps_enabled = enabled ? 1 : 0;
    pr_info("[trace] maps feature %s\n", maps_enabled ? "enabled" : "disabled");
}

int get_maps_enabled(void)
{
    return maps_enabled;
}

int install_maps_hook(void)
{
    int ret;

    if (hook_installed) {
        pr_info("[trace] maps hook already installed\n");
        return SUCCESS;
    }

    if (!kf_show_map_vma) {
        pr_err("[trace] show_map_vma symbol not found\n");
        return FAILED;
    }

    ret = hook_wrap((void *)kf_show_map_vma, 2,
                    (void *)maps_before_hook,
                    (void *)maps_after_hook,
                    NULL);

    if (ret != 0) {
        pr_err("[trace] failed to hook show_map_vma: %d\n", ret);
        return FAILED;
    }

    hook_installed = 1;
    pr_info("[trace] maps hook installed at %p\n", kf_show_map_vma);
    pr_info("[trace] merge_so feature: %s\n",
            merge_so_enabled ? "enabled" : "disabled");
    return SUCCESS;
}

void uninstall_maps_hook(void)
{
    if (!hook_installed) {
        return;
    }

    if (kf_show_map_vma) {
        unhook((void *)kf_show_map_vma);
    }

    hook_installed = 0;
    pr_info("[trace] maps hook uninstalled\n");
}
