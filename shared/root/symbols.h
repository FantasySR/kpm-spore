/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _ROOT_GUARD_SYMBOLS_H
#define _ROOT_GUARD_SYMBOLS_H

#include <ktypes.h>
#include <kpmodule.h>
#include <asm/current.h>
#include <linux/security.h>

#define SUCCESS 0
#define FAILED  -1

/* Forward declarations */
struct seq_file;
struct vm_area_struct;
struct task_struct;
struct mm_struct;
struct cred;
struct rw_semaphore;
struct rb_node;
struct rb_root;
struct module;

/* Kernel structure offsets - dynamically discovered */
struct kernel_offsets {
    /* task_struct offsets */
    int task_mm_offset;
    int task_cred_offset;
    int task_real_cred_offset;

    /* mm_struct offsets */
    int mm_mmap_lock_offset;

    /* vm_area_struct offsets */
    int vma_vm_start_offset;
    int vma_vm_end_offset;
    int vma_vm_next_offset;
    int vma_vm_flags_offset;
    int vma_vm_file_offset;
    int vma_vm_mm_offset;

    /* inode offsets */
    int inode_i_ino_offset;
    int inode_i_mode_offset;
    int inode_i_uid_offset;
    int inode_i_gid_offset;

    /* Thread info */
    int thread_info_in_task;
    int sp_el0_is_current;
    int task_in_thread_info_offset;
};

extern struct kernel_offsets koffsets;

/* Built-in implementations */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base);
long simple_strtol(const char *cp, char **endp, unsigned int base);

/* rwsem operations (resolved via kallsyms internally) */
void down_read(struct rw_semaphore *sem);
void up_read(struct rw_semaphore *sem);
void down_write(struct rw_semaphore *sem);
int down_write_killable(struct rw_semaphore *sem);
void up_write(struct rw_semaphore *sem);

/* Kernel function pointers */

/* String operations */
extern int (*kf_strcmp)(const char *, const char *);
extern int (*kf_strncmp)(const char *, const char *, unsigned long);
extern unsigned long (*kf_strlen)(const char *);
extern char *(*kf_strstr)(const char *, const char *);
extern char *(*kf_strchr)(const char *, int);
extern void *(*kf_memcpy)(void *, const void *, unsigned long);

/* Credential operations */
extern const struct cred *(*kf_override_creds)(const struct cred *);
extern void (*kf_revert_creds)(const struct cred *);
extern struct cred *(*kf_prepare_kernel_cred)(struct task_struct *);

/* SELinux */
extern void (*kf_security_task_getsecid)(struct task_struct *, unsigned int *);
extern int (*kf_security_secid_to_secctx)(unsigned int, char **, unsigned int *);
extern void (*kf_security_release_secctx)(char *, unsigned int);

/* Memory management */
extern struct mm_struct *(*kf_get_task_mm)(struct task_struct *);
extern void (*kf_mmput)(struct mm_struct *);

/* VMA operations */
extern int (*kf_populate_vma_page_range)(struct vm_area_struct *,
                                         unsigned long, unsigned long, int *);
extern int (*kf_copy_page_range)(struct vm_area_struct *, struct vm_area_struct *);
extern void (*kf_show_pte)(unsigned long);
extern struct vm_area_struct *(*kf_vm_area_dup)(struct vm_area_struct *);
extern void (*kf_vm_area_free)(struct vm_area_struct *);

/* Debug */
extern int (*kf_sprint_symbol)(char *, unsigned long);
extern void (*kf_dump_stack)(void);
extern void (*kf_rb_erase_color)(struct rb_node *, struct rb_root *);

/* Memory allocation */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);

/* Hook targets */
extern void (*kf_show_map_vma)(struct seq_file *, struct vm_area_struct *);
extern int (*kf_cap_task_fix_setuid)(struct cred *, const struct cred *, int);

/* User space data access */
extern unsigned long (*kf_raw_copy_from_user)(void *, const void *, unsigned long);
extern unsigned long (*kf_raw_copy_to_user)(void *, const void *, unsigned long);

/* Initialization */
int init_symbols(void);
int init_kernel_offsets(void);
int install_vfs_mm_hooks(void);

/* SELinux context helpers */
int get_current_selinux_context(char *buf, unsigned long buflen);
int is_zygote_context(void);
int is_magisk_context(void);
int is_system_core_context(void);

#endif /* _ROOT_GUARD_SYMBOLS_H */
