/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _ROOT_GUARD_SYSCALL_H
#define _ROOT_GUARD_SYSCALL_H

int install_syscall_hooks(void);
void uninstall_syscall_hooks(void);

void set_syscall_enabled(int enabled);
int get_syscall_enabled(void);

int get_interception_mode(void);
void set_interception_mode(int mode);

#endif /* _ROOT_GUARD_SYSCALL_H */
