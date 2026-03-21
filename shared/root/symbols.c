/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WARNING: This module has not been verified on real devices */
/*
 * Symbol initialization and dynamic offset discovery
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
/* Avoid kfunc dependency from <linux/security.h> wrappers */
#include <asm/current.h>
#include <common.h>
#include "symbols.h"

/* Debug logging - enable as needed */
#ifndef pr_debug
#define pr_debug(fmt, ...) do { } while (0)
#endif

/*
 * ============================================================
 * Built-in implementations (no kernel symbol dependency)
 * ============================================================
 */

static int _rg_is_space(char c)
{
    return (c == ' ') || (c == '\t') || (c == '\n') ||
           (c == '\r') || (c == '\f') || (c == '\v');
}

static int _rg_digit_val(char c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return 10 + (int)(c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (int)(c - 'A');
    return -1;
}

static unsigned long _rg_parse_ul(const char *cp, char **endp, unsigned int base)
{
    const char *s = cp;
    const char *orig = cp;
    unsigned long result = 0;
    int any = 0;

    if (!s) {
        if (endp) *endp = (char *)orig;
        return 0;
    }

    while (*s && _rg_is_space(*s)) s++;

    if (base == 0) {
        if (s[0] == '0') {
            if (s[1] == 'x' || s[1] == 'X') {
                base = 16;
                s += 2;
            } else {
                base = 8;
                s += 1;
            }
        } else {
            base = 10;
        }
    } else if (base == 16) {
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            s += 2;
        }
    }

    if (base < 2 || base > 16) {
        if (endp) *endp = (char *)orig;
        return 0;
    }

    while (*s) {
        int v = _rg_digit_val(*s);
        if (v < 0 || (unsigned int)v >= base) break;
        any = 1;
        result = result * base + (unsigned long)v;
        s++;
    }

    if (endp) {
        *endp = (char *)(any ? s : orig);
    }

    return result;
}

unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{
    const char *s = cp;
    int neg = 0;
    unsigned long v;

    if (!s) {
        if (endp) *endp = (char *)cp;
        return 0;
    }

    while (*s && _rg_is_space(*s)) s++;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    v = _rg_parse_ul(s, endp, base);
    if (neg) {
        return (unsigned long)(-(long)v);
    }
    return v;
}

long simple_strtol(const char *cp, char **endp, unsigned int base)
{
    const char *s = cp;
    int neg = 0;
    unsigned long v;

    if (!s) {
        if (endp) *endp = (char *)cp;
        return 0;
    }

    while (*s && _rg_is_space(*s)) s++;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }

    v = _rg_parse_ul(s, endp, base);
    return neg ? -(long)v : (long)v;
}

/*
 * ============================================================
 * CFI-aware symbol lookup
 * ============================================================
 */

static void *lookup_kallsyms_name_cfi(const char *name)
{
    char buf[128];
    const char suffix[] = ".cfi_jt";
    unsigned long i = 0;
    unsigned long j = 0;

    if (!name || !*name || !kallsyms_lookup_name) {
        return 0;
    }

    while (name[i] && i + 1 < sizeof(buf)) {
        buf[i] = name[i];
        i++;
    }
    buf[i] = '\0';

    /* Try name.cfi_jt first */
    if (!name[i] && i + sizeof(suffix) < sizeof(buf)) {
        for (j = 0; suffix[j] && i + j + 1 < sizeof(buf); j++) {
            buf[i + j] = suffix[j];
        }
        buf[i + j] = '\0';

        void *addr = (void *)kallsyms_lookup_name(buf);
        if (addr) {
            return addr;
        }
    }

    return (void *)kallsyms_lookup_name(name);
}

static void *lookup_kallsyms_name_or_alt(const char *name, const char *alt_name)
{
    void *addr = lookup_kallsyms_name_cfi(name);
    if (!addr && alt_name) {
        addr = lookup_kallsyms_name_cfi(alt_name);
    }
    return addr;
}

/*
 * ============================================================
 * rwsem operation wrappers
 * ============================================================
 */

typedef void (*_rg_rwsem_void_t)(struct rw_semaphore *sem);
typedef int (*_rg_rwsem_int_t)(struct rw_semaphore *sem);

static _rg_rwsem_void_t _rg_down_read_fn;
static _rg_rwsem_void_t _rg_up_read_fn;
static _rg_rwsem_void_t _rg_down_write_fn;
static _rg_rwsem_int_t _rg_down_write_killable_fn;
static _rg_rwsem_void_t _rg_up_write_fn;

void down_read(struct rw_semaphore *sem)
{
    if (!sem) return;
    if (!_rg_down_read_fn) {
        _rg_down_read_fn = (_rg_rwsem_void_t)lookup_kallsyms_name_cfi("down_read");
    }
    if (_rg_down_read_fn) {
        _rg_down_read_fn(sem);
    }
}

void up_read(struct rw_semaphore *sem)
{
    if (!sem) return;
    if (!_rg_up_read_fn) {
        _rg_up_read_fn = (_rg_rwsem_void_t)lookup_kallsyms_name_cfi("up_read");
    }
    if (_rg_up_read_fn) {
        _rg_up_read_fn(sem);
    }
}

void down_write(struct rw_semaphore *sem)
{
    if (!sem) return;
    if (!_rg_down_write_fn) {
        _rg_down_write_fn = (_rg_rwsem_void_t)lookup_kallsyms_name_cfi("down_write");
    }
    if (_rg_down_write_fn) {
        _rg_down_write_fn(sem);
    }
}

int down_write_killable(struct rw_semaphore *sem)
{
    if (!sem) return -1;
    if (!_rg_down_write_killable_fn) {
        _rg_down_write_killable_fn = (_rg_rwsem_int_t)lookup_kallsyms_name_cfi("down_write_killable");
    }
    if (_rg_down_write_killable_fn) {
        return _rg_down_write_killable_fn(sem);
    }
    return -1;
}

void up_write(struct rw_semaphore *sem)
{
    if (!sem) return;
    if (!_rg_up_write_fn) {
        _rg_up_write_fn = (_rg_rwsem_void_t)lookup_kallsyms_name_cfi("up_write");
    }
    if (_rg_up_write_fn) {
        _rg_up_write_fn(sem);
    }
}

/*
 * ============================================================
 * Global variables
 * ============================================================
 */

struct kernel_offsets koffsets = {
    .task_mm_offset = -1,
    .mm_mmap_lock_offset = -1,
    .vma_vm_start_offset = -1,
    .vma_vm_end_offset = -1,
    .vma_vm_next_offset = -1,
    .vma_vm_mm_offset = -1,
    .vma_vm_flags_offset = -1,
    .vma_vm_file_offset = -1,
};

/* Kernel function pointers */
int (*kf_strcmp)(const char *, const char *);
int (*kf_strncmp)(const char *, const char *, unsigned long);
unsigned long (*kf_strlen)(const char *);
char *(*kf_strstr)(const char *, const char *);
char *(*kf_strchr)(const char *, int);
void *(*kf_memcpy)(void *, const void *, unsigned long);

const struct cred *(*kf_override_creds)(const struct cred *);
void (*kf_revert_creds)(const struct cred *);
struct cred *(*kf_prepare_kernel_cred)(struct task_struct *);

void (*kf_security_task_getsecid)(struct task_struct *, unsigned int *);
int (*kf_security_secid_to_secctx)(unsigned int, char **, unsigned int *);
void (*kf_security_release_secctx)(char *, unsigned int);

struct mm_struct *(*kf_get_task_mm)(struct task_struct *);
void (*kf_mmput)(struct mm_struct *);

int (*kf_populate_vma_page_range)(struct vm_area_struct *,
                                   unsigned long, unsigned long, int *);
int (*kf_copy_page_range)(struct vm_area_struct *, struct vm_area_struct *);
void (*kf_show_pte)(unsigned long);
struct vm_area_struct *(*kf_vm_area_dup)(struct vm_area_struct *);
void (*kf_vm_area_free)(struct vm_area_struct *);

int (*kf_sprint_symbol)(char *, unsigned long);
void (*kf_dump_stack)(void);
void (*kf_rb_erase_color)(struct rb_node *, struct rb_root *);

void *(*kf_vmalloc)(unsigned long size);
void (*kf_vfree)(const void *addr);

void (*kf_show_map_vma)(struct seq_file *, struct vm_area_struct *);
int (*kf_cap_task_fix_setuid)(struct cred *, const struct cred *, int);

unsigned long (*kf_raw_copy_from_user)(void *, const void *, unsigned long);
unsigned long (*kf_raw_copy_to_user)(void *, const void *, unsigned long);

/* kallsyms_on_each_symbol function pointer */
static int (*kf_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
                                         struct module *, unsigned long), void *data);

/*
 * ============================================================
 * Symbol lookup context
 * ============================================================
 */

struct symbol_lookup_ctx {
    const char *target_name;
    size_t target_len;
    char found;
    char check_kver;
    void *func_addr;
    void *end_addr;
};

/*
 * kallsyms_on_each_symbol callback
 */
static int kallsyms_symbol_callback(void *data, const char *name,
                                    struct module *mod, unsigned long addr)
{
    struct symbol_lookup_ctx *ctx = (struct symbol_lookup_ctx *)data;

    if (!ctx || !name || !ctx->target_name) {
        return 0;
    }

    /* Exact match */
    if (kf_strcmp) {
        if (kf_strcmp(name, ctx->target_name) == 0) {
            ctx->found = 1;
            ctx->func_addr = (void *)addr;
        }
    }

    /* Prefix match (handle .llvm or $ suffixes) */
    if (!ctx->found && kf_strncmp) {
        if (kf_strncmp(name, ctx->target_name, ctx->target_len) == 0) {
            char suffix = name[ctx->target_len];
            if (suffix == '.' || suffix == '$' || suffix == '\0') {
                ctx->found = 1;
                ctx->func_addr = (void *)addr;
            }
        }
    }

    /* Record next symbol as end address */
    if (ctx->found && ctx->end_addr == NULL &&
        (void *)addr > ctx->func_addr) {
        ctx->end_addr = (void *)addr;
        return 1;  /* Stop traversal */
    }

    return 0;
}

/*
 * Find symbol using kallsyms_on_each_symbol
 */
static int find_symbol_by_kallsyms(const char *name, void **addr, void **end_addr)
{
    struct symbol_lookup_ctx ctx = {0};

    if (!kf_kallsyms_on_each_symbol) {
        kf_kallsyms_on_each_symbol = (void *)kallsyms_lookup_name("kallsyms_on_each_symbol");
        if (!kf_kallsyms_on_each_symbol) {
            return -1;
        }
    }

    ctx.target_name = name;
    ctx.target_len = kf_strlen ? kf_strlen(name) : 0;
    ctx.found = 0;
    ctx.func_addr = NULL;
    ctx.end_addr = NULL;
    ctx.check_kver = (kver >> 10 > 0x180) ? 1 : 0;

    kf_kallsyms_on_each_symbol(kallsyms_symbol_callback, &ctx);

    if (ctx.found && ctx.func_addr) {
        if (addr) *addr = ctx.func_addr;
        if (end_addr) *end_addr = ctx.end_addr;
        return 0;
    }

    return -1;
}

/*
 * ============================================================
 * Dynamic offset discovery - AArch64 instruction analysis
 * ============================================================
 */

/*
 * Analyze AArch64 LDR instruction to extract offset
 * LDR Xn, [Xm, #offset] encoding: 0xF940xxxx
 * LDR Wn, [Xm, #offset] encoding: 0xB940xxxx
 */
static int extract_ldr_offset(uint32_t insn, int *offset, int *is_64bit)
{
    /* LDR Xn, [Xm, #imm] - 64-bit load */
    if ((insn & 0xFFC00000) == 0xF9400000) {
        *offset = ((insn >> 10) & 0xFFF) << 3;  /* multiply by 8 */
        *is_64bit = 1;
        return 1;
    }

    /* LDR Wn, [Xm, #imm] - 32-bit load */
    if ((insn & 0xFFC00000) == 0xB9400000) {
        *offset = ((insn >> 10) & 0xFFF) << 2;  /* multiply by 4 */
        *is_64bit = 0;
        return 1;
    }

    return 0;
}

/*
 * Extract 64-bit LDR (Unsigned Immediate) offset/Rn/Rt
 *
 * Form: ldr xRt, [xRn, #imm]
 */
static int extract_ldr_imm64(uint32_t insn, int *offset, int *rn, int *rt)
{
    if ((insn & 0xFFC00000) == 0xF9400000) {
        if (offset) *offset = ((insn >> 10) & 0xFFF) << 3;  /* multiply by 8 */
        if (rn) *rn = (insn >> 5) & 0x1F;
        if (rt) *rt = insn & 0x1F;
        return 1;
    }
    return 0;
}

static inline int _rg_iabs(int v)
{
    return (v < 0) ? -v : v;
}

/*
 * Return the expected task_mm_offset for the given kernel version.
 * Used for scoring candidates during dynamic scanning.
 * Does not write to koffsets directly.
 */
static int expected_task_mm_offset_from_kver(void)
{
    uint32_t ver = kver;

    if (ver >= 0x60100) {
        return 0x3a0; /* 6.1.x+ */
    }
    if (ver >= 0x50f00) {
        return 0x398; /* 5.15.x */
    }
    if (ver >= 0x50a00) {
        return 0x390; /* 5.10.x */
    }
    if (ver >= 0x50400) {
        return 0x388; /* 5.4.x */
    }
    if (ver >= 0x41300) {
        return 0x380; /* 4.19.x */
    }
    if (ver >= 0x40e00) {
        return 0x378; /* 4.14.x */
    }

    return -1;
}

static int expected_mm_mmap_lock_offset_from_kver(void)
{
    uint32_t ver = kver;

    if (ver >= 0x60100) {
        return 0x60; /* 6.1.x+ */
    }
    if (ver >= 0x50f00) {
        return 0x68; /* 5.15.x */
    }
    if (ver >= 0x50a00) {
        return 0x70; /* 5.10.x */
    }
    if (ver >= 0x50400) {
        return 0x70; /* 5.4.x */
    }
    if (ver >= 0x41300) {
        return 0x68; /* 4.19.x */
    }
    if (ver >= 0x40e00) {
        return 0x68; /* 4.14.x */
    }

    return -1;
}

static int extract_add_x_imm(uint32_t insn, int *imm, int *rd, int *rn)
{
    /* ADD (immediate), 64-bit: 0x91000000 */
    if ((insn & 0xFF000000) != 0x91000000) {
        return 0;
    }

    if (rd) *rd = insn & 0x1F;
    if (rn) *rn = (insn >> 5) & 0x1F;

    if (imm) {
        int shift = (insn >> 22) & 0x3;
        int imm12 = (insn >> 10) & 0xFFF;
        int v = imm12;
        if (shift == 1) {
            v <<= 12;
        }
        *imm = v;
    }

    return 1;
}

static int is_bl(uint32_t insn)
{
    return ((insn & 0xFC000000) == 0x94000000);
}

static void *decode_bl_target(uintptr_t pc, uint32_t insn)
{
    int64_t imm26;
    int64_t off;

    if (!is_bl(insn)) {
        return NULL;
    }

    imm26 = (int64_t)(insn & 0x03FFFFFF);
    /* sign-extend 26-bit immediate */
    imm26 = (imm26 << 38) >> 38;
    off = imm26 << 2;

    return (void *)(pc + (uintptr_t)off);
}

/*
 * discover_task_offsets - discover task_struct offsets from get_task_mm/show_map_vma
 */
static int discover_task_offsets_from_func(void *func_start, size_t func_size)
{
    uint32_t *pc;
    uint32_t *end;
    int offset;
    int is_64bit;
    int found_mm_offset = 0;
    int candidates[32];
    int cand_cnt = 0;

    if (!func_start || func_size < 16) {
        return -1;
    }

    /* Already discovered, return immediately */
    if (koffsets.task_mm_offset != -1) {
        return 0;
    }

    pc = (uint32_t *)func_start;
    end = (uint32_t *)((char *)func_start + func_size);

    /* Scan function instructions */
    while (pc < end) {
        uint32_t insn = *pc;
        int rn = -1;
        int rt = -1;

        if (extract_ldr_imm64(insn, &offset, &rn, &rt)) {
            is_64bit = 1;

            /*
             * Typical get_task_mm form: ldr x0, [x0, #task_mm_offset]
             * This is the highest confidence match condition.
             */
            if (rn == 0 && rt == 0 &&
                (offset & 7) == 0 && offset >= 0x200 && offset <= 0x800) {
                koffsets.task_mm_offset = offset;
                pr_info("[root] discovered task_mm_offset: 0x%x\n",
                        koffsets.task_mm_offset);
                return 0;
            }

            /*
             * Collect candidate offsets:
             * - Must be 64-bit load (mm pointer)
             * - 8-byte aligned
             * - task->mm common range around 0x300, widened for compatibility
             */
            if (is_64bit && (offset & 7) == 0 && offset >= 0x200 && offset <= 0x800) {
                int i;
                int dup = 0;

                for (i = 0; i < cand_cnt; i++) {
                    if (candidates[i] == offset) {
                        dup = 1;
                        break;
                    }
                }

                if (!dup && cand_cnt < (int)(sizeof(candidates) / sizeof(candidates[0]))) {
                    candidates[cand_cnt++] = offset;
                }
            }
        }

        /* Compatibility: retain old decode path (without register info) */
        else if (extract_ldr_offset(insn, &offset, &is_64bit)) {
            if (is_64bit && (offset & 7) == 0 && offset >= 0x200 && offset <= 0x800) {
                int i;
                int dup = 0;

                for (i = 0; i < cand_cnt; i++) {
                    if (candidates[i] == offset) {
                        dup = 1;
                        break;
                    }
                }

                if (!dup && cand_cnt < (int)(sizeof(candidates) / sizeof(candidates[0]))) {
                    candidates[cand_cnt++] = offset;
                }
            }
        }

        pc++;
    }

    /*
     * IMPORTANT (stability first):
     * On some devices/load timings, calling get_task_mm/mmput during
     * initialization can cause unexpected crashes (immediate reboot).
     *
     * Use static best-candidate selection instead:
     * - Pick the offset closest to the expected value for this kernel version
     * - No extra kernel API calls during init
     *
     * If no match, apply_static_offsets will provide fallback values.
     */
    if (cand_cnt > 0) {
        int expected = expected_task_mm_offset_from_kver();
        int best = -1;
        int best_score = 0x7fffffff;
        int i;

        for (i = 0; i < cand_cnt; i++) {
            int off = candidates[i];
            int score;

            if (expected >= 0) {
                score = _rg_iabs(off - expected);
            } else {
                /* Unknown version, prefer common range */
                score = _rg_iabs(off - 0x3a0);
            }

            if (score < best_score) {
                best_score = score;
                best = off;
            }
        }

        if (best != -1) {
            koffsets.task_mm_offset = best;
            found_mm_offset = 1;
            pr_info("[root] discovered task_mm_offset: 0x%x\n",
                    koffsets.task_mm_offset);
        }
    }

    return found_mm_offset ? 0 : -1;
}

/*
 * discover_mm_offsets - discover mm_struct offsets from mm_drop_all_locks
 */
static int discover_mm_offsets_from_func(void *func_start, size_t func_size)
{
    uint32_t *pc;
    uint32_t *end;
    int found_lock_offset = 0;
    int candidates[16];
    int cand_hits[16];
    int cand_cnt = 0;
    void *dw_cfi;
    void *dw;
    void *dwk_cfi;
    void *dwk;

    if (!func_start || func_size < 16) {
        return -1;
    }

    /* Already discovered, return immediately */
    if (koffsets.mm_mmap_lock_offset != -1) {
        return 0;
    }

    dw_cfi = lookup_kallsyms_name_cfi("down_write");
    dw = (void *)kallsyms_lookup_name("down_write");
    dwk_cfi = lookup_kallsyms_name_cfi("down_write_killable");
    dwk = (void *)kallsyms_lookup_name("down_write_killable");

    pc = (uint32_t *)func_start;
    end = (uint32_t *)((char *)func_start + func_size);

    /*
     * Approach: extract mmap_lock offset from argument setup before
     * calls to down_write/down_write_killable.
     *
     * Common compiled sequence:
     *   add x0, xMM, #imm
     *   bl  down_write(_killable)
     *
     * The imm gives us mm->mmap_lock offset.
     */
    while (pc < end) {
        uint32_t insn = *pc;
        uintptr_t pc_addr = (uintptr_t)pc;

        if (is_bl(insn)) {
            void *target = decode_bl_target(pc_addr, insn);

            if (target &&
                (target == dw_cfi || target == dw || target == dwk_cfi || target == dwk)) {
                int back;
                for (back = 1; back <= 8 && (pc - back) >= (uint32_t *)func_start; back++) {
                    uint32_t prev = *(pc - back);
                    int imm = 0;
                    int rd = -1;
                    int rn = -1;

                    if (extract_add_x_imm(prev, &imm, &rd, &rn) && rd == 0) {
                        /* mmap_lock offset is typically a small 8-byte aligned constant */
                        if ((imm & 7) == 0 && imm >= 0x20 && imm <= 0x200) {
                            int i;
                            int found = 0;

                            for (i = 0; i < cand_cnt; i++) {
                                if (candidates[i] == imm) {
                                    cand_hits[i]++;
                                    found = 1;
                                    break;
                                }
                            }

                            if (!found && cand_cnt < (int)(sizeof(candidates) / sizeof(candidates[0]))) {
                                candidates[cand_cnt] = imm;
                                cand_hits[cand_cnt] = 1;
                                cand_cnt++;
                            }
                        }
                        break;
                    }
                }
            }
        }

        pc++;
    }

    if (cand_cnt > 0) {
        int expected = expected_mm_mmap_lock_offset_from_kver();
        int best = candidates[0];
        int best_score = 0x7fffffff;
        int best_hits = -1;
        int i;

        for (i = 0; i < cand_cnt; i++) {
            int off = candidates[i];
            int hits = cand_hits[i];
            int score;

            if (expected >= 0) {
                score = _rg_iabs(off - expected);
            } else {
                score = _rg_iabs(off - 0x70);
            }

            /* Prefer higher hit count, then closer to expected */
            if (hits > best_hits || (hits == best_hits && score < best_score)) {
                best_hits = hits;
                best_score = score;
                best = off;
            }
        }

        koffsets.mm_mmap_lock_offset = best;
        found_lock_offset = 1;
        pr_info("[root] discovered mm_mmap_lock_offset: 0x%x\n",
                koffsets.mm_mmap_lock_offset);
    }

    return found_lock_offset ? 0 : -1;
}

/*
 * discover_vma_offsets - discover vm_area_struct offsets from show_map_vma
 */
static int discover_vma_offsets_from_func(void *func_start, size_t func_size)
{
    uint32_t *pc;
    uint32_t *end;
    int offset;
    int is_64bit;
    int found_count = 0;

    if (!func_start || func_size < 16) {
        return -1;
    }

    pc = (uint32_t *)func_start;
    end = (uint32_t *)((char *)func_start + func_size);

    while (pc < end) {
        uint32_t insn = *pc;

        if (extract_ldr_offset(insn, &offset, &is_64bit)) {
            /* vm_start is typically at offset 0 */
            if (offset == 0 && koffsets.vma_vm_start_offset == -1) {
                koffsets.vma_vm_start_offset = 0;
                found_count++;
            }
            /* vm_end is typically at offset 8 */
            else if (offset == 8 && koffsets.vma_vm_end_offset == -1) {
                koffsets.vma_vm_end_offset = 8;
                found_count++;
            }
            /* vm_file offset is typically in 0x80-0xB0 range */
            else if (offset >= 0x80 && offset <= 0xB0 && koffsets.vma_vm_file_offset == -1) {
                koffsets.vma_vm_file_offset = offset;
                found_count++;
                pr_info("[root] discovered vma_vm_file_offset: 0x%x\n", offset);
            }
        }

        pc++;
    }

    return found_count > 0 ? 0 : -1;
}

/*
 * ============================================================
 * install_vfs_mm_hooks - dynamic offset discovery entry point
 * ============================================================
 */

int install_vfs_mm_hooks(void)
{
    void *func_addr = NULL;
    void *func_end = NULL;
    size_t func_size;
    int ret;

    pr_info("[root] starting dynamic offset discovery...\n");

    /* 1. Discover task_mm_offset from get_task_mm */
    ret = find_symbol_by_kallsyms("get_task_mm", &func_addr, &func_end);
    if (ret == 0 && func_addr) {
        if (func_end && func_end > func_addr) {
            func_size = (size_t)((char *)func_end - (char *)func_addr);
        } else {
            /* end_addr may not be reliably available, use conservative scan window */
            func_size = 0x400;
            pr_debug("[root] get_task_mm end_addr missing, using 0x%zx bytes window\n",
                     func_size);
        }
        if (func_size > 0 && func_size < 0x1000) {
            (void)discover_task_offsets_from_func(func_addr, func_size);
        }
    } else {
        pr_warn("[root] get_task_mm not found\n");
    }

    /* 2. Discover mm_mmap_lock_offset from mm_drop_all_locks */
    func_addr = NULL;
    func_end = NULL;
    ret = find_symbol_by_kallsyms("mm_drop_all_locks", &func_addr, &func_end);
    if (ret == 0 && func_addr) {
        if (func_end && func_end > func_addr) {
            func_size = (size_t)((char *)func_end - (char *)func_addr);
        } else {
            func_size = 0x800;
            pr_debug("[root] mm_drop_all_locks end_addr missing, using 0x%zx bytes window\n",
                     func_size);
        }
        if (func_size > 0 && func_size < 0x2000) {
            (void)discover_mm_offsets_from_func(func_addr, func_size);
        }
    } else {
        pr_warn("[root] mm_drop_all_locks not found\n");
    }

    /* 3. Discover VMA offsets from show_map_vma */
    func_addr = NULL;
    func_end = NULL;
    ret = find_symbol_by_kallsyms("show_map_vma", &func_addr, &func_end);
    if (ret == 0 && func_addr) {
        if (func_end && func_end > func_addr) {
            func_size = (size_t)((char *)func_end - (char *)func_addr);
        } else {
            func_size = 0x1000;
            pr_debug("[root] show_map_vma end_addr missing, using 0x%zx bytes window\n",
                     func_size);
        }
        if (func_size > 0 && func_size < 0x4000) {
            (void)discover_vma_offsets_from_func(func_addr, func_size);
            (void)discover_task_offsets_from_func(func_addr, func_size);  /* may also contain task offsets */
        }
    } else {
        pr_warn("[root] show_map_vma not found\n");
    }

    /* Report discovery results */
    pr_info("[root] offset discovery results:\n");
    pr_info("[root]   task_mm_offset: 0x%x\n", koffsets.task_mm_offset);
    pr_info("[root]   mm_mmap_lock_offset: 0x%x\n", koffsets.mm_mmap_lock_offset);
    pr_info("[root]   vma_vm_file_offset: 0x%x\n", koffsets.vma_vm_file_offset);

    return SUCCESS;
}

/*
 * ============================================================
 * Static offset fallback (used when dynamic discovery fails)
 * ============================================================
 */

static void apply_static_offsets(void)
{
    uint32_t ver = kver;

    pr_info("[root] applying static offsets for kernel 0x%x...\n", ver);

    if (ver >= 0x60100) {
        /* 6.1.x+ */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x3a0;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x60;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0x88;
    } else if (ver >= 0x50f00) {
        /* 5.15.x */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x398;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x68;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0xa0;
    } else if (ver >= 0x50a00) {
        /* 5.10.x */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x390;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x70;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0xa0;
    } else if (ver >= 0x50400) {
        /* 5.4.x */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x388;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x70;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0xa0;
    } else if (ver >= 0x41300) {
        /* 4.19.x */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x380;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x68;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0xa0;
    } else if (ver >= 0x40e00) {
        /* 4.14.x */
        if (koffsets.task_mm_offset == -1) koffsets.task_mm_offset = 0x378;
        if (koffsets.mm_mmap_lock_offset == -1) koffsets.mm_mmap_lock_offset = 0x68;
        if (koffsets.vma_vm_file_offset == -1) koffsets.vma_vm_file_offset = 0xa0;
    }

    /* Set fixed offsets */
    if (koffsets.vma_vm_start_offset == -1) koffsets.vma_vm_start_offset = 0;
    if (koffsets.vma_vm_end_offset == -1) koffsets.vma_vm_end_offset = 8;
    if (koffsets.vma_vm_next_offset == -1) koffsets.vma_vm_next_offset = 0x10;
    if (koffsets.vma_vm_mm_offset == -1) koffsets.vma_vm_mm_offset = 0x40;
    if (koffsets.vma_vm_flags_offset == -1) koffsets.vma_vm_flags_offset = 0x50;
}

/*
 * ============================================================
 * Symbol initialization
 * ============================================================
 */

struct symbol_entry {
    const char *name;
    const char *alt_name;
    void **addr;
    int required;
};

int init_symbols(void)
{
    static struct symbol_entry symbols[] = {
        /* String operations */
        {"strcmp",   NULL, (void **)&kf_strcmp,   0},
        {"strncmp",  NULL, (void **)&kf_strncmp,  0},
        {"strlen",   NULL, (void **)&kf_strlen,   0},
        {"strstr",   NULL, (void **)&kf_strstr,   0},
        {"strchr",   NULL, (void **)&kf_strchr,   0},
        {"memcpy",   NULL, (void **)&kf_memcpy,   0},

        /* Credential operations */
        {"override_creds",      NULL, (void **)&kf_override_creds,      0},
        {"revert_creds",        NULL, (void **)&kf_revert_creds,        0},
        {"prepare_kernel_cred", NULL, (void **)&kf_prepare_kernel_cred, 0},

        /* SELinux */
        {"security_task_getsecid", "security_task_getsecid_obj",
                                    (void **)&kf_security_task_getsecid, 0},
        {"security_secid_to_secctx",  NULL,
                                    (void **)&kf_security_secid_to_secctx, 0},
        {"security_release_secctx",   NULL,
                                    (void **)&kf_security_release_secctx, 0},

        /* Memory management */
        {"get_task_mm",  NULL, (void **)&kf_get_task_mm,  0},
        {"mmput",        NULL, (void **)&kf_mmput,        0},

        /* Memory allocation */
        {"vmalloc",  NULL, (void **)&kf_vmalloc,  0},
        {"vfree",    NULL, (void **)&kf_vfree,    0},

        /* VMA operations */
        {"populate_vma_page_range", NULL, (void **)&kf_populate_vma_page_range, 0},
        {"copy_page_range",         NULL, (void **)&kf_copy_page_range,         0},
        {"show_pte",                NULL, (void **)&kf_show_pte,                0},
        {"vm_area_dup",             NULL, (void **)&kf_vm_area_dup,             0},
        {"vm_area_free",            NULL, (void **)&kf_vm_area_free,            0},

        /* Debug */
        {"sprint_symbol",    NULL, (void **)&kf_sprint_symbol,   0},
        {"dump_stack",       NULL, (void **)&kf_dump_stack,      0},
        {"__rb_erase_color", NULL, (void **)&kf_rb_erase_color,  0},

        /* Hook targets */
        {"show_map_vma",        NULL, (void **)&kf_show_map_vma,        0},
        {"cap_task_fix_setuid", NULL, (void **)&kf_cap_task_fix_setuid, 0},

        /* User space data access */
        {"_copy_from_user", "raw_copy_from_user", (void **)&kf_raw_copy_from_user, 0},
        {"_copy_to_user",   "raw_copy_to_user",   (void **)&kf_raw_copy_to_user,   0},

        {NULL, NULL, NULL, 0}
    };

    struct symbol_entry *entry;
    int failed = 0;

    pr_info("[root] resolving kernel symbols...\n");

    for (entry = symbols; entry->name; entry++) {
        *entry->addr = lookup_kallsyms_name_or_alt(entry->name, entry->alt_name);

        if (!*entry->addr) {
            if (entry->required) {
                pr_err("[root] required symbol '%s' not found\n", entry->name);
                failed = 1;
            } else {
                pr_info("[root] optional symbol '%s' not found\n", entry->name);
            }
        }
    }

    pr_info("[root] symbol resolution %s\n", failed ? "failed" : "completed");
    return failed ? FAILED : SUCCESS;
}

/*
 * Initialize kernel structure offsets
 */
int init_kernel_offsets(void)
{
    pr_info("[root] detecting kernel offsets for version 0x%x...\n", kver);

    /* First try dynamic discovery */
    install_vfs_mm_hooks();

    /* Apply static fallback for undiscovered offsets */
    apply_static_offsets();

    /* Verify critical offsets */
    if (koffsets.task_mm_offset == -1 || koffsets.mm_mmap_lock_offset == -1) {
        pr_err("[root] critical offsets not discovered\n");
        return FAILED;
    }

    pr_info("[root] final offsets: task_mm=0x%x, mm_mmap_lock=0x%x\n",
            koffsets.task_mm_offset, koffsets.mm_mmap_lock_offset);

    return SUCCESS;
}

/*
 * ============================================================
 * SELinux context detection
 * ============================================================
 */

static const char ZYGOTE_CONTEXT[] = "u:r:zygote:s0";

int get_current_selinux_context(char *buf, unsigned long buflen)
{
    unsigned int secid = 0;
    char *secctx = NULL;
    unsigned int secctx_len = 0;
    int ret;
    struct task_struct *task;
    unsigned long i;

    if (buflen == 0 || !buf) {
        return FAILED;
    }

    buf[0] = '\0';

    task = current;
    if (!task) {
        return FAILED;
    }

    /* Use only dynamically resolved symbols to avoid kfunc wrapper dependency */
    if (kf_security_task_getsecid) {
        kf_security_task_getsecid(task, &secid);
    } else {
        /* Kernel lacks security_task_getsecid, cannot get SELinux context */
        pr_debug("[root] security_task_getsecid not available\n");
        return FAILED;
    }

    if (secid == 0) {
        return FAILED;
    }

    if (kf_security_secid_to_secctx) {
        ret = kf_security_secid_to_secctx(secid, &secctx, &secctx_len);
    } else {
        /* Kernel lacks security_secid_to_secctx */
        pr_debug("[root] security_secid_to_secctx not available\n");
        return FAILED;
    }

    if (ret != 0 || !secctx || secctx_len == 0) {
        return FAILED;
    }

    if (secctx_len >= buflen) {
        secctx_len = buflen - 1;
    }

    for (i = 0; i < secctx_len; i++) {
        buf[i] = secctx[i];
    }
    buf[secctx_len] = '\0';

    if (kf_security_release_secctx) {
        kf_security_release_secctx(secctx, secctx_len);
    }
    /* If no release function, skip release (minor memory leak but no crash) */

    return SUCCESS;
}

int is_zygote_context(void)
{
    char context[64];
    int i;

    if (get_current_selinux_context(context, sizeof(context)) != SUCCESS) {
        return 0;
    }

    if (kf_strncmp) {
        return kf_strncmp(context, ZYGOTE_CONTEXT, 13) == 0;
    }

    for (i = 0; i < 13; i++) {
        if (context[i] != ZYGOTE_CONTEXT[i]) {
            return 0;
        }
    }

    return 1;
}

int is_magisk_context(void)
{
    char context[64];

    if (get_current_selinux_context(context, sizeof(context)) != SUCCESS) {
        return 0;
    }

    if (kf_strstr) {
        if (kf_strstr(context, "magisk") || kf_strstr(context, ":su:")) {
            return 1;
        }
    }

    return 0;
}

int is_system_core_context(void)
{
    char context[64];

    if (get_current_selinux_context(context, sizeof(context)) != SUCCESS) {
        return 0;
    }

    if (kf_strstr) {
        if (kf_strstr(context, "u:r:init:") ||
            kf_strstr(context, "u:r:kernel:") ||
            kf_strstr(context, "u:r:vold:") ||
            kf_strstr(context, "u:r:system_server:")) {
            return 1;
        }
    }

    return 0;
}
