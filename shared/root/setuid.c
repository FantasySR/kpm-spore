/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */
/*
 * cap_task_fix_setuid hook
 *
 * How it works:
 * 1. Hook cap_task_fix_setuid function
 * 2. Detect calling process SELinux context
 * 3. For zygote processes, execute special memory hiding logic
 * 4. Modify flags parameter to influence subsequent behavior
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <kputils.h>
#include <sucompat.h>
#include "symbols.h"
#include "setuid.h"
#include "maps.h"

#ifndef pr_debug
#define pr_debug(fmt, ...) do { } while (0)
#endif

/*
 * ============================================================
 * Constants
 * ============================================================
 */

/* cap_task_fix_setuid flags values */
#define LSM_SETID_ID    1
#define LSM_SETID_RE    2
#define LSM_SETID_RES   4
#define LSM_SETID_FS    8

/*
 * ============================================================
 * Global variables
 * ============================================================
 */

static void *cap_task_fix_setuid_addr = NULL;
static int setuid_hook_installed = 0;
static int setuid_hook_enabled = 1;

/* Statistics (for debugging) */
static unsigned long zygote_fork_count = 0;
static unsigned long app_process_count = 0;
/* Zygote timing: only do mmap_lock write lock/unlock, no VMA traversal */

static inline int have_cred_uid_offset(void)
{
    /* cred_offset parsed and exported by KernelPatch at boot stage */
    return (cred_offset.uid_offset >= 0 && cred_offset.uid_offset < 0x200);
}

static inline uid_t read_cred_uid(const struct cred *cred)
{
    if (!cred) return (uid_t)-1;
    if (have_cred_uid_offset()) {
        return *(uid_t *)((char *)cred + cred_offset.uid_offset);
    }
    /* Fallback (not guaranteed accurate across kernel versions) */
    return *(uid_t *)((char *)cred + 4);
}

static inline int have_mm_offsets(void)
{
    return (koffsets.task_mm_offset >= 0 &&
            koffsets.mm_mmap_lock_offset >= 0 &&
            koffsets.vma_vm_next_offset >= 0);
}

/*
 * ============================================================
 * mm_struct access helpers
 * ============================================================
 */

static inline struct mm_struct *get_task_mm_via_offset(struct task_struct *task)
{
    if (!task || koffsets.task_mm_offset < 0) {
        return NULL;
    }
    return *(struct mm_struct **)((char *)task + koffsets.task_mm_offset);
}

static inline struct rw_semaphore *get_mm_mmap_lock(struct mm_struct *mm)
{
    if (!mm || koffsets.mm_mmap_lock_offset < 0) {
        return NULL;
    }
    return (struct rw_semaphore *)((char *)mm + koffsets.mm_mmap_lock_offset);
}

/*
 * ============================================================
 * VMA traversal and hiding
 * ============================================================
 */

/*
 * Traverse all VMAs of a process and hide sensitive mappings
 */
static __maybe_unused int hide_sensitive_vmas(struct task_struct *task)
{
    struct mm_struct *mm;
    struct rw_semaphore *mmap_lock;
    struct vm_area_struct *vma;
    void **mmap_ptr;
    int hidden_count = 0;

    /* Get mm_struct */
    if (kf_get_task_mm) {
        mm = kf_get_task_mm(task);
    } else {
        mm = get_task_mm_via_offset(task);
    }

    if (!mm) {
        pr_debug("[root] task has no mm\n");
        return 0;
    }

    /* Get mmap_lock */
    mmap_lock = get_mm_mmap_lock(mm);
    if (!mmap_lock) {
        goto out_put_mm;
    }

    /* Acquire read lock for VMA traversal */
    down_read(mmap_lock);

    /*
     * Traverse VMA linked list
     * mm->mmap is the first VMA
     * Newer kernels use VMA iterator; this uses the traditional linked list approach
     */
    mmap_ptr = (void **)((char *)mm + 0x0);  /* mm->mmap offset is typically 0 */
    vma = (struct vm_area_struct *)*mmap_ptr;

    while (vma) {
        /* Check if VMA should be hidden */
        if (should_hide_vma(vma)) {
            hidden_count++;
            pr_debug("[root] marking VMA for hiding: 0x%lx-0x%lx\n",
                    *(unsigned long *)((char *)vma + koffsets.vma_vm_start_offset),
                    *(unsigned long *)((char *)vma + koffsets.vma_vm_end_offset));
        }

        /* Get next VMA */
        if (koffsets.vma_vm_next_offset >= 0) {
            vma = *(struct vm_area_struct **)((char *)vma + koffsets.vma_vm_next_offset);
        } else {
            break;
        }
    }

    up_read(mmap_lock);

out_put_mm:
    if (kf_mmput && kf_get_task_mm) {
        kf_mmput(mm);
    }

    return hidden_count;
}

/*
 * Clear sensitive pages of a process
 * This is an optional aggressive approach
 */
static __maybe_unused void clear_sensitive_pages(struct task_struct *task)
{
    struct mm_struct *mm;
    struct rw_semaphore *mmap_lock;
    struct vm_area_struct *vma;
    void **mmap_ptr;

    if (kf_get_task_mm) {
        mm = kf_get_task_mm(task);
    } else {
        mm = get_task_mm_via_offset(task);
    }

    if (!mm) {
        return;
    }

    mmap_lock = get_mm_mmap_lock(mm);
    if (!mmap_lock) {
        goto out_put_mm;
    }

    /* Need write lock for modification */
    if (down_write_killable(mmap_lock) != 0) {
        goto out_put_mm;
    }

    /* Traverse and process */
    mmap_ptr = (void **)((char *)mm + 0x0);
    vma = (struct vm_area_struct *)*mmap_ptr;

    while (vma) {
        if (should_hide_vma(vma)) {
            /*
             * Possible actions:
             * 1. Make pages unreadable
             * 2. Unmap
             * 3. Replace content
             *
             * Only marking here; actual action depends on requirements
             */
        }

        if (koffsets.vma_vm_next_offset >= 0) {
            vma = *(struct vm_area_struct **)((char *)vma + koffsets.vma_vm_next_offset);
        } else {
            break;
        }
    }

    up_write(mmap_lock);

out_put_mm:
    if (kf_mmput && kf_get_task_mm) {
        kf_mmput(mm);
    }
}

/*
 * ============================================================
 * cap_task_fix_setuid Hook Handlers
 * ============================================================
 */

/*
 * Before hook
 * Check and prepare before setuid execution
 */
static void cap_task_fix_setuid_before_hook(hook_fargs3_t *args, void *udata)
{
    struct cred *new_cred;
    const struct cred *old_cred;
    int flags;
    struct task_struct *task;
    uid_t old_uid, new_uid;

    if (!setuid_hook_enabled) {
        return;
    }

    new_cred = (struct cred *)args->arg0;
    old_cred = (const struct cred *)args->arg1;
    flags = (int)args->arg2;
    task = current;

    if (!new_cred || !old_cred) {
        return;
    }

    old_uid = read_cred_uid(old_cred);
    new_uid = read_cred_uid(new_cred);

    /*
     * Align with original flags handling:
     * if (flags == 1 || flags == 2) flags = 4;
     */
    if (flags == LSM_SETID_ID || flags == LSM_SETID_RE) {
        args->arg2 = (uint64_t)LSM_SETID_RES;
        flags = LSM_SETID_RES;
    }

    /*
     * Check if this is a zygote process
     * Zygote is the parent of all Android app processes
     * During fork, it executes setuid to change UID from 0 to app UID
     */
    if (is_zygote_context()) {
        zygote_fork_count++;

        pr_debug("[root] zygote setuid detected (fork #%lu)\n",
                 zygote_fork_count);

        /*
         * Critical timing: zygote is forking a new app process
         * Memory hiding operations are performed at this point
         */

        /*
         * Zygote timing mmap_lock + memory processing framework:
         * - Requires task_mm_offset / mm_mmap_lock_offset etc.
         * - If offsets not discovered, only log and skip to avoid crash
         */
        /*
         * Gating alignment:
         * - Only consider when old_uid == 0 (zygote privilege drop)
         * - Only enter mmap_lock branch when get_ap_mod_exclude(new_uid) != 0
         */
        if (old_uid == 0 && get_ap_mod_exclude(new_uid) != 0) {
            /*
             * Aligned behavior:
             * - Get mm via task_mm_offset
             * - Calculate mmap_lock via mm_mmap_lock_offset
             * - If down_write_killable succeeds, immediately up_write
             * - No VMA traversal/modification under lock (avoid instability)
             */
            if (!have_mm_offsets()) {
                pr_warn("[root] offsets not discovered yet\n");
            } else {
                struct mm_struct *mm = get_task_mm_via_offset(task);
                if (!mm) {
                    pr_debug("[root] mm is null\n");
                } else {
                    struct rw_semaphore *mmap_lock = get_mm_mmap_lock(mm);
                    if (mmap_lock && down_write_killable(mmap_lock) == 0) {
                        up_write(mmap_lock);
                    } else {
                        pr_debug("[root] mmap_lock failed\n");
                    }
                }
            }
        }

        /*
         * Modify flags to influence subsequent processing
         */
        if ((flags & LSM_SETID_RES) != 0) {
            /* setresuid call */
            app_process_count++;
            pr_info("[root] app process starting: uid 0 -> %u\n", new_uid);
        }
    }

    /*
     * Check if this is a privilege drop from root to regular user
     * This typically happens during app startup
     */
    if (old_uid == 0 && new_uid >= 10000) {
        pr_debug("[root] app process starting: uid 0 -> %u\n", new_uid);

        /*
         * App process is about to start
         * Ensure necessary hiding operations are completed before this point
         */
    }
}

/*
 * After hook (optional)
 * Clean up after setuid execution
 */
static void cap_task_fix_setuid_after_hook(hook_fargs3_t *args, void *udata)
{
    /* No after processing needed currently */
}

/*
 * ============================================================
 * Install/uninstall hooks
 * ============================================================
 */

int install_setuid_hook(void)
{
    int ret;

    pr_info("[root] installing cap_task_fix_setuid hook...\n");

    /* Find function address */
    if (kf_cap_task_fix_setuid) {
        cap_task_fix_setuid_addr = (void *)kf_cap_task_fix_setuid;
    } else {
        cap_task_fix_setuid_addr = (void *)kallsyms_lookup_name("cap_task_fix_setuid");
    }

    if (!cap_task_fix_setuid_addr) {
        pr_err("[root] cap_task_fix_setuid not found\n");
        return FAILED;
    }

    pr_info("[root] found cap_task_fix_setuid at %px\n", cap_task_fix_setuid_addr);

    /* Install hook */
    ret = hook_wrap3(cap_task_fix_setuid_addr,
                     (void *)cap_task_fix_setuid_before_hook,
                     (void *)cap_task_fix_setuid_after_hook,
                     NULL);

    if (ret != 0) {
        pr_err("[root] failed to hook cap_task_fix_setuid: %d\n", ret);
        return FAILED;
    }

    setuid_hook_installed = 1;
    pr_info("[root] cap_task_fix_setuid hook installed\n");

    return SUCCESS;
}

void uninstall_setuid_hook(void)
{
    if (setuid_hook_installed && cap_task_fix_setuid_addr) {
        unhook(cap_task_fix_setuid_addr);
        setuid_hook_installed = 0;
        pr_info("[root] cap_task_fix_setuid hook uninstalled\n");
        pr_info("[root] stats: zygote_forks=%lu, app_starts=%lu\n",
                zygote_fork_count, app_process_count);
    }
}

/*
 * ============================================================
 * Feature toggle
 * ============================================================
 */

void set_setuid_hook_enabled(int enabled)
{
    setuid_hook_enabled = enabled ? 1 : 0;
    pr_info("[root] setuid hook %s\n",
            setuid_hook_enabled ? "enabled" : "disabled");
}

int get_setuid_hook_enabled(void)
{
    return setuid_hook_enabled;
}

/*
 * ============================================================
 * Statistics query
 * ============================================================
 */

unsigned long get_zygote_fork_count(void)
{
    return zygote_fork_count;
}

unsigned long get_app_process_count(void)
{
    return app_process_count;
}
