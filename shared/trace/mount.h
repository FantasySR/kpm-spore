/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _TRACE_GUARD_MOUNT_H
#define _TRACE_GUARD_MOUNT_H

int install_mount_hooks(void);
void uninstall_mount_hooks(void);

/* Mount hiding feature toggle (soft switch) */
void set_mount_enabled(int enabled);
int get_mount_enabled(void);

#endif /* _TRACE_GUARD_MOUNT_H */
