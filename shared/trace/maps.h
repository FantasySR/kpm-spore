/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _TRACE_GUARD_MAPS_H
#define _TRACE_GUARD_MAPS_H

/* Basic hook install/uninstall */
int install_maps_hook(void);
void uninstall_maps_hook(void);

/*
 * Maps feature toggle (soft switch)
 *
 * Note: Some hooks cannot be hot-unloaded, so this provides a soft toggle.
 * When disabled, hook callbacks return immediately, effectively disabling the feature.
 */
void set_maps_enabled(int enabled);
int get_maps_enabled(void);

/*
 * merge_so feature control
 *
 * Merges multiple memory mapping regions of the same shared library.
 * Default: disabled
 */
void set_merge_so_enabled(int enabled);
int get_merge_so_enabled(void);

#endif /* _TRACE_GUARD_MAPS_H */
