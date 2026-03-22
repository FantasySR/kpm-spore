/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _TRACE_GUARD_SYMBOLS_H
#define _TRACE_GUARD_SYMBOLS_H

#include <ktypes.h>
#include <kpmodule.h>

#define SUCCESS 0
#define FAILED  (-1)

/* Kernel structure offsets - dynamically set per kernel version */
struct kernel_offsets {
    /* task_struct offsets */
    int tasks_offset;
    int task_pid_offset;
    int group_leader_offset;

    /* mm_struct offsets */
    int mmap_lock_offset;
    int start_stack_offset;
    int pgd_offset;

    /* vm_area_struct offsets */
    int vm_mm_offset;
    int vm_next_offset;
    int vm_end_offset;
    int vm_flags_offset;
    int vm_file_offset;

    /* file offsets */
    int f_path_offset;

    /* other */
    int usage_offset;
    int socket_ops_offset;
};

extern struct kernel_offsets koffsets;

/* Forward declarations */
struct seq_file;
struct vm_area_struct;
struct file;
struct task_struct;
struct mm_struct;
struct vfsmount;
struct path;
struct mount;

/* Kernel function pointers */
extern void (*kf_show_map_vma)(struct seq_file *, struct vm_area_struct *);
extern int (*kf_show_vfsmnt)(struct seq_file *, struct vfsmount *, struct path *);
extern int (*kf_show_mountinfo)(struct seq_file *, struct vfsmount *, struct path *);
extern int (*kf_show_vfsstat)(struct seq_file *, struct vfsmount *, struct path *);

extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern char *(*kf_strstr)(const char *, const char *);
extern int (*kf_strcmp)(const char *, const char *);
extern size_t (*kf_strlen)(const char *);
extern void *(*kf_memcpy)(void *, const void *, size_t);
extern char *(*kf_strchr)(const char *, int);

/* User space data copy - resolved via kallsyms */
extern unsigned long (*kf_raw_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern unsigned long (*kf_raw_copy_to_user)(void __user *to, const void *from, unsigned long n);

/* Initialization functions */
int init_symbols(void);
int init_kernel_offsets(void);

#endif /* _TRACE_GUARD_SYMBOLS_H */
