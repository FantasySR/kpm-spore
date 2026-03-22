/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */

/*
 * Debug hiding feature
 *
 * Features:
 * 1. seq_put_decimal_ull: modify Seccomp_filters value
 * 2. seq_puts: replace "t (tracing stop)" with "S (sleeping)"
 * 3. proc_pid_wchan: replace "ptrace_stop" with "0"
 * 4. do_task_stat: replace "t" state with "S" in /proc/pid/stat
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>
#include "symbols.h"
#include "debug.h"

/* Simplified seq_file structure */
struct seq_file_dbg {
    char *buf;        /* 0x00 */
    size_t size;      /* 0x08 */
    size_t from;      /* 0x10 */
    size_t count;     /* 0x18 */
};

/* Kernel function pointers */
static void (*kf_seq_put_decimal_ull)(void *m, const char *delimiter,
                                       unsigned long long num);
static void (*kf_seq_puts)(void *m, const char *s);
static int (*kf_proc_pid_wchan)(void *m, void *ns, void *pid, void *task);
static int (*kf_do_task_stat)(void *m, void *ns, void *pid, void *task, int whole);

static int seq_put_decimal_hooked = 0;
static int seq_puts_hooked = 0;
static int wchan_hooked = 0;
static int stat_hooked = 0;

/* Debug feature master switch: 0=off, 1=on */
static int debug_enabled = 1;

static inline int should_filter(void)
{
    return current_uid() > 10000;
}

/*
 * seq_put_decimal_ull before hook
 * seq_put_decimal_ull(m, delimiter, num)
 *
 * Detects delimiter containing "\nSeccomp_filters:\t"
 * and sets num to 1 if matched.
 */
static void seq_put_decimal_before_hook(hook_fargs3_t *args, void *udata)
{
    const char *delimiter;

    if (!should_filter()) {
        return;
    }

    if (!debug_enabled) {
        return;
    }

    delimiter = (const char *)args->arg1;
    if (!delimiter) {
        return;
    }

    /* Detect Seccomp_filters */
    if (strnstr(delimiter, "\nSeccomp_filters:\t", 32)) {
        args->arg2 = 1;
        pr_info("[trace] hide Seccomp_filters\n");
    }
}

/*
 * seq_puts before hook
 * seq_puts(m, s)
 *
 * Detects s == "t (tracing stop)" and replaces with "S (sleeping)"
 */
static void seq_puts_before_hook(hook_fargs2_t *args, void *udata)
{
    const char *s;

    if (!should_filter()) {
        return;
    }

    if (!debug_enabled) {
        return;
    }

    s = (const char *)args->arg1;
    if (!s) {
        return;
    }

    /* Detect process state */
    if (kf_strcmp && kf_strcmp(s, "t (tracing stop)") == 0) {
        args->arg1 = (uint64_t)"S (sleeping)";
        pr_info("[trace] hide tracing stop state\n");
    }
}

/*
 * proc_pid_wchan after hook
 *
 * Detects if seq_file->buf is "ptrace_stop" and replaces with "0\0",
 * setting count = 1.
 */
static void wchan_after_hook(hook_fargs4_t *args, void *udata)
{
    struct seq_file_dbg *m;

    if (!should_filter()) {
        return;
    }

    if (!debug_enabled) {
        return;
    }

    m = (struct seq_file_dbg *)args->arg0;
    if (!m || !m->buf) {
        return;
    }

    /* Detect and replace ptrace_stop */
    if (kf_strcmp && kf_strcmp(m->buf, "ptrace_stop") == 0) {
        m->buf[0] = '0';
        m->buf[1] = '\0';
        m->count = 1;
        pr_info("[trace] hide wchan ptrace_stop\n");
    }
}

/*
 * do_task_stat after hook
 *
 * Searches for ") t" pattern in /proc/[pid]/stat output
 * and replaces 't' (tracing stop) with 'S' (sleeping).
 */
static void stat_after_hook(hook_fargs5_t *args, void *udata)
{
    struct seq_file_dbg *m;
    char *buf;
    size_t i;

    if (!should_filter()) {
        return;
    }

    if (!debug_enabled) {
        return;
    }

    m = (struct seq_file_dbg *)args->arg0;
    if (!m || !m->buf || m->count <= 2) {
        return;
    }

    buf = m->buf;

    /* Search for ") t" pattern (0x29 0x20 0x74) */
    for (i = 2; i < m->count; i++) {
        if (buf[i-2] == ')' && buf[i-1] == ' ' && buf[i] == 't') {
            /* Replace 't' with 'S' */
            buf[i] = 'S';
            pr_info("[trace] hide stat tracing state\n");
            break;
        }
    }
}

int install_debug_hooks(void)
{
    int ret;

    /* Look up symbols */
    kf_seq_put_decimal_ull = (void *)kallsyms_lookup_name("seq_put_decimal_ull");
    kf_seq_puts = (void *)kallsyms_lookup_name("seq_puts");
    kf_proc_pid_wchan = (void *)kallsyms_lookup_name("proc_pid_wchan");
    kf_do_task_stat = (void *)kallsyms_lookup_name("do_task_stat");

    /* Hook seq_put_decimal_ull */
    if (kf_seq_put_decimal_ull && !seq_put_decimal_hooked) {
        ret = hook_wrap((void *)kf_seq_put_decimal_ull, 3,
                        (void *)seq_put_decimal_before_hook, NULL, NULL);
        if (ret == 0) {
            seq_put_decimal_hooked = 1;
            pr_info("[trace] seq_put_decimal_ull hook installed\n");
        } else {
            pr_err("[trace] failed to hook seq_put_decimal_ull: %d\n", ret);
        }
    } else if (!kf_seq_put_decimal_ull) {
        pr_info("[trace] seq_put_decimal_ull not found\n");
    }

    /* Hook seq_puts */
    if (kf_seq_puts && !seq_puts_hooked) {
        ret = hook_wrap((void *)kf_seq_puts, 2,
                        (void *)seq_puts_before_hook, NULL, NULL);
        if (ret == 0) {
            seq_puts_hooked = 1;
            pr_info("[trace] seq_puts hook installed\n");
        } else {
            pr_err("[trace] failed to hook seq_puts: %d\n", ret);
        }
    } else if (!kf_seq_puts) {
        pr_info("[trace] seq_puts not found\n");
    }

    /* Hook proc_pid_wchan */
    if (kf_proc_pid_wchan && !wchan_hooked) {
        ret = hook_wrap((void *)kf_proc_pid_wchan, 4,
                        NULL, (void *)wchan_after_hook, NULL);
        if (ret == 0) {
            wchan_hooked = 1;
            pr_info("[trace] proc_pid_wchan hook installed\n");
        } else {
            pr_err("[trace] failed to hook proc_pid_wchan: %d\n", ret);
        }
    } else if (!kf_proc_pid_wchan) {
        pr_info("[trace] proc_pid_wchan not found\n");
    }

    /* Hook do_task_stat */
    if (kf_do_task_stat && !stat_hooked) {
        ret = hook_wrap((void *)kf_do_task_stat, 5,
                        NULL, (void *)stat_after_hook, NULL);
        if (ret == 0) {
            stat_hooked = 1;
            pr_info("[trace] do_task_stat hook installed\n");
        } else {
            pr_err("[trace] failed to hook do_task_stat: %d\n", ret);
        }
    } else if (!kf_do_task_stat) {
        pr_info("[trace] do_task_stat not found\n");
    }

    return SUCCESS;
}

void uninstall_debug_hooks(void)
{
    if (seq_put_decimal_hooked && kf_seq_put_decimal_ull) {
        unhook((void *)kf_seq_put_decimal_ull);
        seq_put_decimal_hooked = 0;
    }

    if (seq_puts_hooked && kf_seq_puts) {
        unhook((void *)kf_seq_puts);
        seq_puts_hooked = 0;
    }

    if (wchan_hooked && kf_proc_pid_wchan) {
        unhook((void *)kf_proc_pid_wchan);
        wchan_hooked = 0;
    }

    if (stat_hooked && kf_do_task_stat) {
        unhook((void *)kf_do_task_stat);
        stat_hooked = 0;
    }

    pr_info("[trace] debug hooks uninstalled\n");
}

void set_debug_enabled(int enabled)
{
    debug_enabled = enabled ? 1 : 0;
    pr_info("[trace] debug feature %s\n", debug_enabled ? "enabled" : "disabled");
}

int get_debug_enabled(void)
{
    return debug_enabled;
}
