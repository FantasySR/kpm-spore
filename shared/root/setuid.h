/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _ROOT_GUARD_SETUID_H
#define _ROOT_GUARD_SETUID_H

int install_setuid_hook(void);
void uninstall_setuid_hook(void);

void set_setuid_hook_enabled(int enabled);
int get_setuid_hook_enabled(void);

unsigned long get_zygote_fork_count(void);
unsigned long get_app_process_count(void);

#endif /* _ROOT_GUARD_SETUID_H */
