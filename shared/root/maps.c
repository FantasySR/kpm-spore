/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */
/*
 * Maps hiding module
 *
 * How it works:
 * 1. Hook show_map_vma before/after
 * 2. Before hook records current seq_file->count
 * 3. After hook checks new output content
 * 4. If output contains sensitive paths, roll back count to hide the line
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include "symbols.h"
#include "maps.h"

#ifndef pr_debug
#define pr_debug(fmt, ...) do { } while (0)
#endif

/*
 * ============================================================
 * Sensitive path detection
 * ============================================================
 */

/* Keywords for paths that should be hidden */
static const char *hide_keywords[] = {
    "magisk",
    "zygisk",
    "lsposed",
    "riru",
    "xposed",
    "supersu",
    "kingroot",
    "/su",
    "kernelsu",
    "apatch",
    ".magisk",
    NULL
};

static size_t rg_strlen(const char *s)
{
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int rg_memcmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if ((unsigned char)a[i] != (unsigned char)b[i]) {
            return (int)((unsigned char)a[i] - (unsigned char)b[i]);
        }
    }
    return 0;
}

static int rg_memmem(const char *haystack, size_t haystack_len, const char *needle)
{
    size_t nlen;
    size_t i;

    if (!haystack || !needle) return 0;
    nlen = rg_strlen(needle);
    if (nlen == 0 || nlen > haystack_len) return 0;

    for (i = 0; i + nlen <= haystack_len; i++) {
        if (haystack[i] == needle[0] &&
            rg_memcmp(haystack + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Check if a path should be hidden
 */
static int should_hide_path(const char *path, size_t path_len)
{
    const char **kw;

    if (!path || path_len == 0) {
        return 0;
    }

    /* Bounded search: avoid out-of-bounds reads on non-NUL-terminated buffers */
    for (kw = hide_keywords; *kw; kw++) {
        if (rg_memmem(path, path_len, *kw)) {
            return 1;
        }
    }

    return 0;
}

/*
 * ============================================================
 * seq_file structure offsets (simplified, assumes standard layout)
 * ============================================================
 */

/* Key offsets in seq_file structure */
#define SEQ_FILE_BUF_OFFSET     0x00   /* char *buf */
#define SEQ_FILE_SIZE_OFFSET    0x08   /* size_t size */
#define SEQ_FILE_COUNT_OFFSET   0x18   /* size_t count */

/*
 * Get seq_file count field
 */
static inline size_t get_seq_file_count(struct seq_file *sf)
{
    return *(size_t *)((char *)sf + SEQ_FILE_COUNT_OFFSET);
}

/*
 * Set seq_file count field
 */
static inline void set_seq_file_count(struct seq_file *sf, size_t count)
{
    *(size_t *)((char *)sf + SEQ_FILE_COUNT_OFFSET) = count;
}

/*
 * Get seq_file buf field
 */
static inline char *get_seq_file_buf(struct seq_file *sf)
{
    return *(char **)((char *)sf + SEQ_FILE_BUF_OFFSET);
}

static inline size_t get_seq_file_size(struct seq_file *sf)
{
    return *(size_t *)((char *)sf + SEQ_FILE_SIZE_OFFSET);
}

/*
 * ============================================================
 * Hook state and controls
 * ============================================================
 */

static void *show_map_vma_addr = NULL;
static int maps_hook_installed = 0;
static int maps_hide_enabled = 1;

/*
 * ============================================================
 * show_map_vma before hook
 * Record seq_file->count before the call
 * ============================================================
 */

static void show_map_vma_before_hook(hook_fargs2_t *args, void *udata)
{
    struct seq_file *sf;
    uid_t uid;
    char *buf;
    size_t size;
    size_t count;

    /* Initialize local data */
    args->local.data0 = 0; /* old_count */
    args->local.data1 = 0; /* size */
    args->local.data2 = 0; /* active */

    if (!maps_hide_enabled) {
        return;
    }

    /* Only enable for app processes (uid >= 10000) */
    uid = current_uid();
    if (uid < 10000) {
        return;
    }

    sf = (struct seq_file *)args->arg0;
    if (!sf) {
        return;
    }

    buf = get_seq_file_buf(sf);
    size = get_seq_file_size(sf);
    count = get_seq_file_count(sf);

    /* Basic validity check to avoid out-of-bounds/null pointer */
    if (!buf || size == 0 || count > size) {
        return;
    }

    /* Save current state to fargs->local (shared between before/after in same call) */
    args->local.data0 = (uint64_t)count;
    args->local.data1 = (uint64_t)size;
    args->local.data2 = 1;
}

/*
 * ============================================================
 * show_map_vma after hook
 * Check output and decide whether to roll back
 * ============================================================
 */

static void show_map_vma_after_hook(hook_fargs2_t *args, void *udata)
{
    struct seq_file *sf;
    size_t old_count, new_count;
    char *buf;
    char *line_start;
    size_t line_len;
    size_t size;

    if (!maps_hide_enabled) {
        return;
    }

    if (args->local.data2 == 0) {
        return;
    }

    sf = (struct seq_file *)args->arg0;
    if (!sf) {
        return;
    }

    old_count = (size_t)args->local.data0;
    size = (size_t)args->local.data1;
    new_count = get_seq_file_count(sf);
    buf = get_seq_file_buf(sf);

    /* Clear active flag */
    args->local.data2 = 0;

    if (!buf || size == 0) {
        return;
    }

    /* Size may have changed, prefer current value for validation */
    {
        size_t cur_size = get_seq_file_size(sf);
        if (cur_size != 0) size = cur_size;
    }

    if (new_count > size || old_count > new_count) {
        return;
    }

    /* No new output, nothing to process */
    if (new_count <= old_count) {
        return;
    }

    /* Check new output content */
    line_start = buf + old_count;
    line_len = new_count - old_count;

    /* Limit search length */
    if (line_len > 512) {
        line_len = 512;
    }

    /* Search for sensitive paths in output */
    if (should_hide_path(line_start, line_len)) {
        /* Sensitive path found, roll back count to hide this line */
        set_seq_file_count(sf, old_count);

        pr_debug("[root] maps hiding: rolled back %zu bytes\n",
                 new_count - old_count);
    }
}

/*
 * ============================================================
 * Install/uninstall hooks
 * ============================================================
 */

int install_maps_hook(void)
{
    int ret;

    pr_info("[root] installing maps hiding hook...\n");

    /* Find show_map_vma */
    if (kf_show_map_vma) {
        show_map_vma_addr = (void *)kf_show_map_vma;
    } else {
        show_map_vma_addr = (void *)kallsyms_lookup_name("show_map_vma");
    }

    if (!show_map_vma_addr) {
        pr_err("[root] show_map_vma not found\n");
        return FAILED;
    }

    pr_info("[root] found show_map_vma at %px\n", show_map_vma_addr);

    /* Install hook */
    ret = hook_wrap2(show_map_vma_addr,
                     (void *)show_map_vma_before_hook,
                     (void *)show_map_vma_after_hook,
                     NULL);

    if (ret != 0) {
        pr_err("[root] failed to hook show_map_vma: %d\n", ret);
        return FAILED;
    }

    maps_hook_installed = 1;
    pr_info("[root] maps hiding hook installed\n");

    return SUCCESS;
}

void uninstall_maps_hook(void)
{
    if (maps_hook_installed && show_map_vma_addr) {
        unhook(show_map_vma_addr);
        maps_hook_installed = 0;
        pr_info("[root] maps hiding hook uninstalled\n");
    }
}

/*
 * ============================================================
 * Feature toggle
 * ============================================================
 */

void set_maps_hide_enabled(int enabled)
{
    maps_hide_enabled = enabled ? 1 : 0;
    pr_info("[root] maps hiding %s\n",
            maps_hide_enabled ? "enabled" : "disabled");
}

int get_maps_hide_enabled(void)
{
    return maps_hide_enabled;
}

/*
 * ============================================================
 * VMA hiding check (direct VMA structure access)
 * ============================================================
 */

int should_hide_vma(struct vm_area_struct *vma)
{
    if (!vma || !maps_hide_enabled) {
        return 0;
    }

    /* Actual detection happens in after hook via output content */
    return 0;
}
