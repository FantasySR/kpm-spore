/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _ROOT_GUARD_MAPS_H
#define _ROOT_GUARD_MAPS_H

struct vm_area_struct;

/* Install show_map_vma hook to hide sensitive memory mappings */
int install_maps_hook(void);
void uninstall_maps_hook(void);

/* Toggle controls */
void set_maps_hide_enabled(int enabled);
int get_maps_hide_enabled(void);

/* Check if VMA should be hidden */
int should_hide_vma(struct vm_area_struct *vma);

#endif /* _ROOT_GUARD_MAPS_H */
