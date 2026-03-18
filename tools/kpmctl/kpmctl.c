/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpmctl - KPM Module Loader CLI Tool
 *
 * A lightweight command-line tool for loading, unloading, listing,
 * and controlling KernelPatch modules via the supercall interface.
 *
 * Usage:
 *   kpmctl <superkey> hello                          - Check if KernelPatch is active
 *   kpmctl <superkey> load <path> [args]             - Load a KPM module
 *   kpmctl <superkey> unload <name>                  - Unload a KPM module
 *   kpmctl <superkey> list                           - List loaded modules
 *   kpmctl <superkey> info <name>                    - Show module info
 *   kpmctl <superkey> control <name> <ctl_args>      - Send control command
 *   kpmctl <superkey> kpver                          - Show KernelPatch version
 *   kpmctl <superkey> kver                           - Show kernel version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

/* ========================================================================== */
/* Supercall definitions (from KernelPatch uapi/scdefs.h)                     */
/* ========================================================================== */

#define __NR_supercall 45

#define SUPERCALL_HELLO             0x1000
#define SUPERCALL_KLOG              0x1004
#define SUPERCALL_KERNELPATCH_VER   0x1008
#define SUPERCALL_KERNEL_VER        0x1009

#define SUPERCALL_KPM_LOAD          0x1020
#define SUPERCALL_KPM_UNLOAD        0x1021
#define SUPERCALL_KPM_CONTROL       0x1022
#define SUPERCALL_KPM_NUMS          0x1030
#define SUPERCALL_KPM_LIST          0x1031
#define SUPERCALL_KPM_INFO          0x1032

#define SUPERCALL_HELLO_MAGIC       0x11581158
#define SUPERCALL_KEY_MAX_LEN       0x40

/* Version from KernelPatch source */
#define KP_MAJOR 0
#define KP_MINOR 12
#define KP_PATCH 0

#define BUF_SIZE 4096

/* ========================================================================== */
/* Supercall helpers                                                          */
/* ========================================================================== */

static inline long ver_and_cmd(long cmd)
{
    uint32_t version_code = (KP_MAJOR << 16) + (KP_MINOR << 8) + KP_PATCH;
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

static long sc_hello(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_HELLO));
}

static bool sc_ready(const char *key)
{
    return sc_hello(key) == SUPERCALL_HELLO_MAGIC;
}

static long sc_kp_ver(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KERNELPATCH_VER));
}

static long sc_k_ver(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KERNEL_VER));
}

static long sc_kpm_load(const char *key, const char *path, const char *args)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LOAD), path, args, NULL);
}

static long sc_kpm_unload(const char *key, const char *name)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_UNLOAD), name, NULL);
}

static long sc_kpm_nums(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_NUMS));
}

static long sc_kpm_list(const char *key, char *buf, int buf_len)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LIST), buf, buf_len);
}

static long sc_kpm_info(const char *key, const char *name, char *buf, int buf_len)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_INFO), name, buf, buf_len);
}

static long sc_kpm_control(const char *key, const char *name, const char *ctl_args,
                           char *out_msg, long outlen)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_CONTROL),
                   name, ctl_args, out_msg, outlen);
}

/* ========================================================================== */
/* Command implementations                                                    */
/* ========================================================================== */

static int cmd_hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        printf("[+] KernelPatch is active! (magic: 0x%lx)\n", ret);
        return 0;
    } else {
        printf("[-] KernelPatch not detected (ret: %ld)\n", ret);
        return 1;
    }
}

static int cmd_kpver(const char *key)
{
    long ret = sc_kp_ver(key);
    if (ret < 0) {
        printf("[-] Failed to get KernelPatch version (ret: %ld)\n", ret);
        return 1;
    }
    uint32_t ver = (uint32_t)ret;
    printf("[*] KernelPatch version: %d.%d.%d (0x%x)\n",
           (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF, ver);
    return 0;
}

static int cmd_kver(const char *key)
{
    long ret = sc_k_ver(key);
    if (ret < 0) {
        printf("[-] Failed to get kernel version (ret: %ld)\n", ret);
        return 1;
    }
    uint32_t ver = (uint32_t)ret;
    printf("[*] Kernel version: %d.%d.%d\n",
           (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF);
    return 0;
}

static int cmd_load(const char *key, const char *path, const char *args)
{
    printf("[*] Loading KPM: %s\n", path);
    if (args) {
        printf("[*] Arguments: %s\n", args);
    }

    long ret = sc_kpm_load(key, path, args);
    if (ret == 0) {
        printf("[+] Module loaded successfully!\n");
        return 0;
    } else {
        printf("[-] Failed to load module (ret: %ld)\n", ret);
        if (ret == -EEXIST)
            printf("    Module with the same name is already loaded\n");
        else if (ret == -ENOENT)
            printf("    File not found: %s\n", path);
        else if (ret == -EPERM)
            printf("    Permission denied - check your superkey\n");
        return 1;
    }
}

static int cmd_unload(const char *key, const char *name)
{
    printf("[*] Unloading KPM: %s\n", name);

    long ret = sc_kpm_unload(key, name);
    if (ret == 0) {
        printf("[+] Module unloaded successfully!\n");
        return 0;
    } else {
        printf("[-] Failed to unload module (ret: %ld)\n", ret);
        return 1;
    }
}

static int cmd_list(const char *key)
{
    long nums = sc_kpm_nums(key);
    if (nums < 0) {
        printf("[-] Failed to get module count (ret: %ld)\n", nums);
        return 1;
    }

    printf("[*] Loaded modules: %ld\n", nums);

    if (nums == 0) {
        printf("    (none)\n");
        return 0;
    }

    char buf[BUF_SIZE] = {0};
    long ret = sc_kpm_list(key, buf, sizeof(buf) - 1);
    if (ret < 0) {
        printf("[-] Failed to list modules (ret: %ld)\n", ret);
        return 1;
    }

    /* Ensure NUL termination using returned length */
    if (ret < (long)sizeof(buf))
        buf[ret] = '\0';

    printf("----------------------------\n");
    /* Module names are newline-separated */
    char *line = buf;
    int idx = 1;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (*line) {
            printf("  %d. %s\n", idx++, line);
        }
        if (!nl) break;
        line = nl + 1;
    }
    printf("----------------------------\n");

    return 0;
}

static int cmd_info(const char *key, const char *name)
{
    char buf[BUF_SIZE] = {0};
    long ret = sc_kpm_info(key, name, buf, sizeof(buf) - 1);
    if (ret < 0) {
        printf("[-] Failed to get info for '%s' (ret: %ld)\n", name, ret);
        return 1;
    }

    if (ret < (long)sizeof(buf))
        buf[ret] = '\0';

    printf("[*] Module info: %s\n", name);
    printf("----------------------------\n");
    printf("%s\n", buf);
    printf("----------------------------\n");
    return 0;
}

static int cmd_control(const char *key, const char *name, const char *ctl_args)
{
    char out_msg[BUF_SIZE] = {0};

    printf("[*] Sending control to '%s': %s\n", name, ctl_args);

    long ret = sc_kpm_control(key, name, ctl_args, out_msg, sizeof(out_msg));
    if (ret < 0) {
        printf("[-] Control failed (ret: %ld)\n", ret);
        return 1;
    }

    printf("[+] Control succeeded (ret: %ld)\n", ret);
    if (out_msg[0]) {
        printf("[*] Output:\n%s\n", out_msg);
    }
    return 0;
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

static void usage(const char *prog)
{
    printf("kpmctl - KernelPatch Module Control Tool\n\n");
    printf("Usage:\n");
    printf("  %s <superkey> hello                       Check KernelPatch status\n", prog);
    printf("  %s <superkey> kpver                       Show KernelPatch version\n", prog);
    printf("  %s <superkey> kver                        Show kernel version\n", prog);
    printf("  %s <superkey> load <path> [args]          Load a KPM module\n", prog);
    printf("  %s <superkey> unload <name>               Unload a KPM module\n", prog);
    printf("  %s <superkey> list                        List loaded modules\n", prog);
    printf("  %s <superkey> info <name>                 Show module info\n", prog);
    printf("  %s <superkey> control <name> <ctl_args>   Send control command\n", prog);
    printf("\nExamples:\n");
    printf("  %s mykey123 hello\n", prog);
    printf("  %s mykey123 load /data/local/tmp/hello.kpm\n", prog);
    printf("  %s mykey123 load /data/local/tmp/hello.kpm \"arg1,arg2\"\n", prog);
    printf("  %s mykey123 list\n", prog);
    printf("  %s mykey123 unload kpm-hello\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *key = argv[1];
    const char *cmd = argv[2];

    /* Validate key length */
    if (strlen(key) >= SUPERCALL_KEY_MAX_LEN) {
        printf("[-] Superkey too long (max %d chars)\n", SUPERCALL_KEY_MAX_LEN - 1);
        return 1;
    }

    if (strcmp(cmd, "hello") == 0) {
        return cmd_hello(key);
    }
    else if (strcmp(cmd, "kpver") == 0) {
        return cmd_kpver(key);
    }
    else if (strcmp(cmd, "kver") == 0) {
        return cmd_kver(key);
    }
    else if (strcmp(cmd, "load") == 0) {
        if (argc < 4) {
            printf("[-] Usage: %s <key> load <path> [args]\n", argv[0]);
            return 1;
        }
        const char *path = argv[3];
        const char *args = (argc > 4) ? argv[4] : NULL;
        return cmd_load(key, path, args);
    }
    else if (strcmp(cmd, "unload") == 0) {
        if (argc < 4) {
            printf("[-] Usage: %s <key> unload <name>\n", argv[0]);
            return 1;
        }
        return cmd_unload(key, argv[3]);
    }
    else if (strcmp(cmd, "list") == 0) {
        return cmd_list(key);
    }
    else if (strcmp(cmd, "info") == 0) {
        if (argc < 4) {
            printf("[-] Usage: %s <key> info <name>\n", argv[0]);
            return 1;
        }
        return cmd_info(key, argv[3]);
    }
    else if (strcmp(cmd, "control") == 0) {
        if (argc < 5) {
            printf("[-] Usage: %s <key> control <name> <ctl_args>\n", argv[0]);
            return 1;
        }
        return cmd_control(key, argv[3], argv[4]);
    }
    else {
        printf("[-] Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
