#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("System call interceptor - minimal");

/* 系统调用地址 */
static uintptr_t addr_pread64;
static uintptr_t addr_pwrite64;
static uintptr_t addr_process_vm_readv;
static uintptr_t addr_process_vm_writev;

/* pread64 参数: fd, buf, count, pos */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    printk(KERN_INFO "KMS| pread64 | FD=%llu BUF=%llx COUNT=%llu POS=%lld\n",
           fargs->arg0, fargs->arg1, fargs->arg2, (long long)fargs->arg3);
}

/* pwrite64 参数: fd, buf, count, pos */
static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    printk(KERN_INFO "KMS| pwrite64 | FD=%llu BUF=%llx COUNT=%llu POS=%lld\n",
           fargs->arg0, fargs->arg1, fargs->arg2, (long long)fargs->arg3);
}

/* process_vm_readv 参数: pid, local_iov, liovcnt, remote_iov, riovcnt, flags */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    printk(KERN_INFO "KMS| process_vm_readv | TARGET=%llu LIOV=%llx LCNT=%llu RIOV=%llx RCNT=%llu FLAGS=%llu\n",
           fargs->arg0, fargs->arg1, fargs->arg2, fargs->arg3, fargs->arg4, fargs->arg5);
}

/* process_vm_writev 参数: pid, local_iov, liovcnt, remote_iov, riovcnt, flags */
static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    printk(KERN_INFO "KMS| process_vm_writev | TARGET=%llu LIOV=%llx LCNT=%llu RIOV=%llx RCNT=%llu FLAGS=%llu\n",
           fargs->arg0, fargs->arg1, fargs->arg2, fargs->arg3, fargs->arg4, fargs->arg5);
}

static long my_init(const char *args, const char *event, void __user *reserved)
{
    hook_err_t err;

    addr_pread64            = (uintptr_t)kallsyms_lookup_name("sys_pread64");
    addr_pwrite64           = (uintptr_t)kallsyms_lookup_name("sys_pwrite64");
    addr_process_vm_readv   = (uintptr_t)kallsyms_lookup_name("sys_process_vm_readv");
    addr_process_vm_writev  = (uintptr_t)kallsyms_lookup_name("sys_process_vm_writev");

    if (!addr_pread64 || !addr_pwrite64 || !addr_process_vm_readv || !addr_process_vm_writev) {
        printk(KERN_ERR "KMS: syscall lookup failed\n");
        return -1;
    }

    err = fp_hook_wrap4(addr_pread64, before_pread64, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook pread64 err %d\n", err); return err; }
    err = fp_hook_wrap4(addr_pwrite64, before_pwrite64, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook pwrite64 err %d\n", err); return err; }
    err = fp_hook_wrap6(addr_process_vm_readv, before_process_vm_readv, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook process_vm_readv err %d\n", err); return err; }
    err = fp_hook_wrap6(addr_process_vm_writev, before_process_vm_writev, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook process_vm_writev err %d\n", err); return err; }

    printk(KERN_INFO "KernelMemorySky: interceptor loaded\n");
    return 0;
}

static long my_exit(void __user *reserved)
{
    if (addr_pread64)            fp_hook_unwrap(addr_pread64, before_pread64, NULL);
    if (addr_pwrite64)           fp_hook_unwrap(addr_pwrite64, before_pwrite64, NULL);
    if (addr_process_vm_readv)   fp_hook_unwrap(addr_process_vm_readv, before_process_vm_readv, NULL);
    if (addr_process_vm_writev)  fp_hook_unwrap(addr_process_vm_writev, before_process_vm_writev, NULL);
    printk(KERN_INFO "KernelMemorySky: interceptor unloaded\n");
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);