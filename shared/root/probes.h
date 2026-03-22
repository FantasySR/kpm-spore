/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

#ifndef _ROOT_GUARD_PROBES_H
#define _ROOT_GUARD_PROBES_H

int install_discovery_probes(void);
void uninstall_discovery_probes(void);

int get_probes_completed(void);
int get_probes_total(void);
int are_all_probes_completed(void);

void *get_discovered_supercall_handler(void);
void *get_discovered_faccessat_handler(void);
void *get_discovered_readlinkat_handler(void);
void *get_discovered_execve_handler(void);
void *get_discovered_compat_execve_handler(void);
void *get_discovered_compat_openat2_handler(void);
void *get_discovered_compat_statx_handler(void);

int discover_handlers_via_api(void);

#endif /* _ROOT_GUARD_PROBES_H */
