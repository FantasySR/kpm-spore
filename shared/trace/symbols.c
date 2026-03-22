/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include "symbols.h"

struct kernel_offsets koffsets = {0};

/* Kernel function pointer definitions */
void (*kf_show_map_vma)(struct seq_file *, struct vm_area_struct *);
int (*kf_show_vfsmnt)(struct seq_file *, struct vfsmount *, struct path *);
int (*kf_show_mountinfo)(struct seq_file *, struct vfsmount *, struct path *);
int (*kf_show_vfsstat)(struct seq_file *, struct vfsmount *, struct path *);

void *(*kf_vmalloc)(unsigned long size);
void (*kf_vfree)(const void *addr);
char *(*kf_strstr)(const char *, const char *);
int (*kf_strcmp)(const char *, const char *);
size_t (*kf_strlen)(const char *);
void *(*kf_memcpy)(void *, const void *, size_t);
char *(*kf_strchr)(const char *, int);
unsigned long (*kf_raw_copy_from_user)(void *to, const void __user *from, unsigned long n);
unsigned long (*kf_raw_copy_to_user)(void __user *to, const void *from, unsigned long n);

struct symbol_entry {
    const char *name;
    void **addr;
    int required;  /* 1 = required, 0 = optional */
};

int init_symbols(void)
{
    static struct symbol_entry symbols[] = {
        /* Core hook targets */
        {"show_map_vma",   (void **)&kf_show_map_vma,   1},
        {"show_vfsmnt",    (void **)&kf_show_vfsmnt,    0},
        {"show_mountinfo", (void **)&kf_show_mountinfo, 0},
        {"show_vfsstat",   (void **)&kf_show_vfsstat,   0},

        /* Helper functions */
        {"vmalloc",        (void **)&kf_vmalloc,        1},
        {"vfree",          (void **)&kf_vfree,          1},
        {"strstr",         (void **)&kf_strstr,         1},
        {"strcmp",         (void **)&kf_strcmp,         1},
        {"strlen",         (void **)&kf_strlen,         1},
        {"memcpy",         (void **)&kf_memcpy,         1},
        {"strchr",         (void **)&kf_strchr,         1},

        /* User space data access (optional, used by getdents) */
        {"_copy_from_user", (void **)&kf_raw_copy_from_user, 0},
        {"_copy_to_user",   (void **)&kf_raw_copy_to_user,   0},

        {NULL, NULL, 0}
    };

    struct symbol_entry *entry;
    int failed = 0;

    for (entry = symbols; entry->name; entry++) {
        *entry->addr = (void *)kallsyms_lookup_name(entry->name);
        if (!*entry->addr) {
            if (entry->required) {
                pr_err("[trace] required symbol '%s' not found\n", entry->name);
                failed = 1;
            } else {
                pr_info("[trace] optional symbol '%s' not found\n", entry->name);
            }
        }
    }

    return failed ? FAILED : SUCCESS;
}

/*
 * Initialize structure offsets based on kernel version
 * kver format: 0xMMmmPP (Major.minor.Patch)
 */
int init_kernel_offsets(void)
{
    uint32_t ver = kver;

    if (ver >= 0x50a00 && ver <= 0x50eff) {
        /* 5.10.x */
        pr_info("[trace] kernel 5.10 detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x4c8;
        koffsets.task_pid_offset = 0x5c8;
        koffsets.group_leader_offset = 0x608;
        koffsets.mmap_lock_offset = 0x70;
        koffsets.vm_mm_offset = 0x40;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x50;
        koffsets.vm_file_offset = 0xa0;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x140;
        koffsets.usage_offset = 0x40;
        koffsets.pgd_offset = 0x48;
        koffsets.socket_ops_offset = 0x20;
    } else if (ver >= 0x50f00 && ver <= 0x60100) {
        /* 5.15.x - 6.1.0 early */
        pr_info("[trace] kernel 5.15 detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x4d0;
        koffsets.task_pid_offset = 0x5d8;
        koffsets.group_leader_offset = 0x618;
        koffsets.mmap_lock_offset = 0x68;
        koffsets.vm_mm_offset = 0x40;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x50;
        koffsets.vm_file_offset = 0xa0;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x140;
        koffsets.usage_offset = 0x38;
        koffsets.pgd_offset = 0x40;
        koffsets.socket_ops_offset = 0x20;
    } else if (ver > 0x60100) {
        /* 6.1.x+ (significant structure changes) */
        pr_info("[trace] kernel 6.1+ detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x550;
        koffsets.task_pid_offset = 0x630;
        koffsets.group_leader_offset = 0x670;
        koffsets.mmap_lock_offset = 0x60;
        koffsets.vm_mm_offset = 0x10;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x20;
        koffsets.vm_file_offset = 0x88;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x138;
        koffsets.usage_offset = 0x40;
        koffsets.pgd_offset = 0x38;
        koffsets.socket_ops_offset = 0x20;
    } else if (ver >= 0x50400 && ver < 0x50a00) {
        /* 5.4.x */
        pr_info("[trace] kernel 5.4 detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x550;
        koffsets.task_pid_offset = 0x650;
        koffsets.group_leader_offset = 0x690;
        koffsets.mmap_lock_offset = 0x70;
        koffsets.vm_mm_offset = 0x40;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x50;
        koffsets.vm_file_offset = 0xa0;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x130;
        koffsets.usage_offset = 0x38;
        koffsets.pgd_offset = 0x48;
        koffsets.socket_ops_offset = 0x20;
    } else if (ver >= 0x41300 && ver < 0x50400) {
        /* 4.19.x */
        pr_info("[trace] kernel 4.19 detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x538;
        koffsets.task_pid_offset = 0x638;
        koffsets.group_leader_offset = 0x678;
        koffsets.mmap_lock_offset = 0x68;
        koffsets.vm_mm_offset = 0x40;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x50;
        koffsets.vm_file_offset = 0xa0;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x128;
        koffsets.usage_offset = 0x68;
        koffsets.pgd_offset = 0x48;
        koffsets.socket_ops_offset = 0x28;
    } else if (ver >= 0x40e00 && ver < 0x41300) {
        /* 4.14.x */
        pr_info("[trace] kernel 4.14 detected (0x%x)\n", ver);
        koffsets.tasks_offset = 0x530;
        koffsets.task_pid_offset = 0x630;
        koffsets.group_leader_offset = 0x670;
        koffsets.mmap_lock_offset = 0x68;
        koffsets.vm_mm_offset = 0x40;
        koffsets.vm_next_offset = 0x10;
        koffsets.vm_end_offset = 0x8;
        koffsets.vm_flags_offset = 0x50;
        koffsets.vm_file_offset = 0xa0;
        koffsets.f_path_offset = 0x10;
        koffsets.start_stack_offset = 0x128;
        koffsets.usage_offset = 0x68;
        koffsets.pgd_offset = 0x48;
        koffsets.socket_ops_offset = 0x28;
    } else {
        pr_err("[trace] unsupported kernel version: 0x%x\n", ver);
        return FAILED;
    }

    return SUCCESS;
}
