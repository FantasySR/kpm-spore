/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _TRACE_GUARD_DEBUG_H
#define _TRACE_GUARD_DEBUG_H

int install_debug_hooks(void);
void uninstall_debug_hooks(void);

/* Debug hiding feature toggle (soft switch) */
void set_debug_enabled(int enabled);
int get_debug_enabled(void);

#endif /* _TRACE_GUARD_DEBUG_H */
