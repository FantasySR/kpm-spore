/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */
/*
 * Probe system
 *
 * How it works:
 * 1. Probes are temporary syscall hooks
 * 2. They self-uninstall after being called once
 * 3. From the hook context, extract the actual syscall handler address
 * 4. Store discovered addresses in global variables for later use
 *
 * pt_regs context structure:
 * - +0x00: x0-x7 registers
 * - +0x10: possible handler address location 1
 * - +0x18: possible handler address location 2
 * - +0xe8: flags
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <kconfig.h>
#include <syscall.h>
#include <hook.h>
#include <linux/printk.h>
#include "symbols.h"
#include "probes.h"

/*
 * ============================================================
 * Discovered handler address storage
 * ============================================================
 */

/* Native syscall handlers */
static void *discovered_supercall_handler = NULL;
static void *discovered_faccessat_handler = NULL;
static void *discovered_readlinkat_handler = NULL;
static void *discovered_execve_handler = NULL;

/* Compat syscall handlers */
static void *discovered_compat_execve_handler = NULL;
static void *discovered_compat_openat2_handler = NULL;
static void *discovered_compat_statx_handler = NULL;

/* Probe state */
static int probe_supercall_active = 0;
static int probe_faccessat_active = 0;
static int probe_readlinkat_active = 0;
static int probe_execve_active = 0;
static int probe_compat_execve_active = 0;
static int probe_compat_openat2_active = 0;
static int probe_compat_statx_active = 0;

/* Probe counters */
static int probes_completed = 0;
static int probes_total = 0;

/*
 * ============================================================
 * Extract handler address from hook context
 * ============================================================
 */

/*
 * Extract syscall handler address from hook context
 *
 * For fp_hook_wrap (function pointer hooks like sys_call_table), hook_fargs->chain
 * points to fp_hook_chain_t, where hook.origin_fp is the original function pointer
 * before hooking.
 *
 * This is more reliable than inferring from pt_regs and avoids mistaking
 * user-space arguments for kernel addresses.
 */
static void *extract_handler_from_context(void *hook_fargs)
{
    void *chain;
    fp_hook_chain_t *fpchain;
    void *origin;

    if (!hook_fargs) return NULL;

    chain = ((hook_fargs0_t *)hook_fargs)->chain;
    if (!chain) return NULL;

    fpchain = (fp_hook_chain_t *)chain;
    origin = (void *)(uintptr_t)fpchain->hook.origin_fp;

    /* Filter obviously invalid addresses (e.g., small integers like 0x8) */
    if (is_bad_address(origin)) {
        return NULL;
    }

    return origin;
}

/*
 * Compatibility note:
 * Some Apatch/KernelPatch versions do not export syscalln_addr,
 * referencing it would cause module load failure.
 * Only use probes to extract handler addresses from hook context.
 */

/*
 * ============================================================
 * Probe hook functions
 * ============================================================
 */

/*
 * probe_supercall_syscall - probe supercall (0x2d/45) handler
 */
static void probe_supercall_before(hook_fargs6_t *args, void *udata)
{
    void *handler;

    if (!probe_supercall_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_supercall_handler = handler;

    /* Uninstall probe */
    fp_unhook_syscalln(0x2d, (void *)probe_supercall_before, NULL);
    probe_supercall_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: supercall handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: supercall handler not found\n");
    }
}

/*
 * probe_faccessat_syscall - probe faccessat (0x4f/79) handler
 */
static void probe_faccessat_before(hook_fargs4_t *args, void *udata)
{
    void *handler;

    if (!probe_faccessat_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_faccessat_handler = handler;

    /* Uninstall probe */
    fp_unhook_syscalln(0x4f, (void *)probe_faccessat_before, NULL);
    probe_faccessat_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: faccessat handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: faccessat handler not found\n");
    }
}

/*
 * probe_readlinkat_syscall - probe readlinkat (0x30/48) handler
 */
static void probe_readlinkat_before(hook_fargs4_t *args, void *udata)
{
    void *handler;

    if (!probe_readlinkat_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_readlinkat_handler = handler;

    /* Uninstall probe */
    fp_unhook_syscalln(0x30, (void *)probe_readlinkat_before, NULL);
    probe_readlinkat_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: readlinkat handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: readlinkat handler not found\n");
    }
}

/*
 * probe_execve_syscall - probe execve (0xdd/221) handler
 */
static void probe_execve_before(hook_fargs3_t *args, void *udata)
{
    void *handler;

    if (!probe_execve_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_execve_handler = handler;

    /* Uninstall probe */
    fp_unhook_syscalln(0xdd, (void *)probe_execve_before, NULL);
    probe_execve_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: execve handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: execve handler not found\n");
    }

    /* Do not skip execve, let it execute normally */
}

/*
 * probe_compat_execve_syscall - probe compat execve (0xb/11) handler
 */
static void probe_compat_execve_before(hook_fargs3_t *args, void *udata)
{
    void *handler;

    if (!probe_compat_execve_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_compat_execve_handler = handler;

    /* Uninstall probe */
    fp_unhook_compat_syscalln(0xb, (void *)probe_compat_execve_before, NULL);
    probe_compat_execve_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: compat_execve handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: compat_execve handler not found\n");
    }
}

/*
 * probe_compat_openat2_syscall - probe compat openat2 (0x147/327) handler
 */
static void probe_compat_openat2_before(hook_fargs4_t *args, void *udata)
{
    void *handler;

    if (!probe_compat_openat2_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_compat_openat2_handler = handler;

    /* Uninstall probe */
    fp_unhook_compat_syscalln(0x147, (void *)probe_compat_openat2_before, NULL);
    probe_compat_openat2_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: compat_openat2 handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: compat_openat2 handler not found\n");
    }
}

/*
 * probe_compat_statx_syscall - probe compat statx (0x14e/334) handler
 */
static void probe_compat_statx_before(hook_fargs5_t *args, void *udata)
{
    void *handler;

    if (!probe_compat_statx_active) {
        return;
    }

    /* Extract handler address */
    handler = extract_handler_from_context(args);

    discovered_compat_statx_handler = handler;

    /* Uninstall probe */
    fp_unhook_compat_syscalln(0x14e, (void *)probe_compat_statx_before, NULL);
    probe_compat_statx_active = 0;
    probes_completed++;

    if (handler) {
        pr_info("[root] probe: compat_statx handler discovered at %px\n", handler);
    } else {
        pr_warn("[root] probe: compat_statx handler not found\n");
    }
}

/*
 * ============================================================
 * Install probes
 * ============================================================
 */

int install_discovery_probes(void)
{
    int ret;

    pr_info("[root] installing discovery probes...\n");

    probes_total = 0;
    probes_completed = 0;

    /* Native syscall probes */

    /* supercall (0x2d) - for special functionality */
    ret = fp_hook_syscalln(0x2d, 6, (void *)probe_supercall_before, NULL, NULL);
    if (ret == 0) {
        probe_supercall_active = 1;
        probes_total++;
        pr_info("[root] probe: supercall installed\n");
    }

    /* faccessat (0x4f) */
    ret = fp_hook_syscalln(0x4f, 4, (void *)probe_faccessat_before, NULL, NULL);
    if (ret == 0) {
        probe_faccessat_active = 1;
        probes_total++;
        pr_info("[root] probe: faccessat installed\n");
    }

    /* readlinkat (0x30) */
    ret = fp_hook_syscalln(0x30, 4, (void *)probe_readlinkat_before, NULL, NULL);
    if (ret == 0) {
        probe_readlinkat_active = 1;
        probes_total++;
        pr_info("[root] probe: readlinkat installed\n");
    }

    /* execve (0xdd) */
    ret = fp_hook_syscalln(0xdd, 3, (void *)probe_execve_before, NULL, NULL);
    if (ret == 0) {
        probe_execve_active = 1;
        probes_total++;
        pr_info("[root] probe: execve installed\n");
    }

    /*
     * Compat syscall probes are not enabled by default:
     * Different Apatch/KernelPatch versions have varying compat support,
     * enabling them may cause crashes/reboots.
     * Enable on a per-device basis after confirming stability.
     */

    pr_info("[root] installed %d discovery probes\n", probes_total);

    return probes_total > 0 ? SUCCESS : FAILED;
}

/*
 * Uninstall all active probes
 */
void uninstall_discovery_probes(void)
{
    pr_info("[root] uninstalling discovery probes...\n");

    if (probe_supercall_active) {
        fp_unhook_syscalln(0x2d, (void *)probe_supercall_before, NULL);
        probe_supercall_active = 0;
    }

    if (probe_faccessat_active) {
        fp_unhook_syscalln(0x4f, (void *)probe_faccessat_before, NULL);
        probe_faccessat_active = 0;
    }

    if (probe_readlinkat_active) {
        fp_unhook_syscalln(0x30, (void *)probe_readlinkat_before, NULL);
        probe_readlinkat_active = 0;
    }

    if (probe_execve_active) {
        fp_unhook_syscalln(0xdd, (void *)probe_execve_before, NULL);
        probe_execve_active = 0;
    }

    if (probe_compat_execve_active) {
        fp_unhook_compat_syscalln(0xb, (void *)probe_compat_execve_before, NULL);
        probe_compat_execve_active = 0;
    }

    if (probe_compat_openat2_active) {
        fp_unhook_compat_syscalln(0x147, (void *)probe_compat_openat2_before, NULL);
        probe_compat_openat2_active = 0;
    }

    if (probe_compat_statx_active) {
        fp_unhook_compat_syscalln(0x14e, (void *)probe_compat_statx_before, NULL);
        probe_compat_statx_active = 0;
    }

    pr_info("[root] probes uninstalled\n");
}

/*
 * ============================================================
 * Status query
 * ============================================================
 */

int get_probes_completed(void)
{
    return probes_completed;
}

int get_probes_total(void)
{
    return probes_total;
}

int are_all_probes_completed(void)
{
    return (probes_total > 0 && probes_completed >= probes_total);
}

/*
 * ============================================================
 * Handler address retrieval
 * ============================================================
 */

void *get_discovered_supercall_handler(void)
{
    return discovered_supercall_handler;
}

void *get_discovered_faccessat_handler(void)
{
    return discovered_faccessat_handler;
}

void *get_discovered_readlinkat_handler(void)
{
    return discovered_readlinkat_handler;
}

void *get_discovered_execve_handler(void)
{
    return discovered_execve_handler;
}

void *get_discovered_compat_execve_handler(void)
{
    return discovered_compat_execve_handler;
}

void *get_discovered_compat_openat2_handler(void)
{
    return discovered_compat_openat2_handler;
}

void *get_discovered_compat_statx_handler(void)
{
    return discovered_compat_statx_handler;
}

/*
 * Handler discovery via API is disabled for compatibility.
 * Some Apatch/KernelPatch versions do not export syscalln_addr,
 * which would cause module load failure.
 */
int discover_handlers_via_api(void)
{
    pr_info("[root] handler discovery via API is disabled (compat mode)\n");
    return FAILED;
}
