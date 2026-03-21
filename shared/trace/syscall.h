/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _TRACE_GUARD_SYSCALL_H
#define _TRACE_GUARD_SYSCALL_H

int install_syscall_hooks(void);
void uninstall_syscall_hooks(void);

/* Syscall feature toggle / per-hook toggles (soft switches) */
void set_syscall_enabled(int enabled);
int get_syscall_enabled(void);

void set_readlink_enabled(int enabled);
int get_readlink_enabled(void);

void set_getdents_enabled(int enabled);
int get_getdents_enabled(void);

void set_truncate_enabled(int enabled);
int get_truncate_enabled(void);

void set_fgetxattr_enabled(int enabled);
int get_fgetxattr_enabled(void);

void set_getsockopt_enabled(int enabled);
int get_getsockopt_enabled(void);

#endif /* _TRACE_GUARD_SYSCALL_H */
