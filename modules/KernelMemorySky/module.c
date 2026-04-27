#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>  // 为了一些类型定义

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("System call interceptor for pread64/pwrite64/process_vm_readv/writev");

/* ---- 系统调用地址 (动态查找) ---- */
static uintptr_t addr_pread64;
static uintptr_t addr_pwrite64;
static uintptr_t addr_process_vm_readv;
static uintptr_t addr_process_vm_writev;

/* ---- 记录拦截信息的回调 ---- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    pid_t pid = current->pid;
    unsigned int fd = (unsigned int)fargs->arg0;
    void __user *buf = (void __user *)fargs->arg1;
    size_t count = (size_t)fargs->arg2;
    loff_t pos = (loff_t)fargs->arg3;

    printk(KERN_INFO "KMS| pread64 | PID=%d FD=%u BUF=%px COUNT=%zu POS=%lld\n",
           pid, fd, buf, count, pos);
}

static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    pid_t pid = current->pid;
    unsigned int fd = (unsigned int)fargs->arg0;
    const void __user *buf = (const void __user *)fargs->arg1;
    size_t count = (size_t)fargs->arg2;
    loff_t pos = (loff_t)fargs->arg3;

    printk(KERN_INFO "KMS| pwrite64 | PID=%d FD=%u BUF=%px COUNT=%zu POS=%lld\n",
           pid, fd, buf, count, pos);
}

static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t pid = current->pid;
    pid_t target_pid = (pid_t)fargs->arg0;
    const struct iovec __user *local_iov = (const struct iovec __user *)fargs->arg1;
    unsigned long liovcnt = (unsigned long)fargs->arg2;
    const struct iovec __user *remote_iov = (const struct iovec __user *)fargs->arg3;
    unsigned long riovcnt = (unsigned long)fargs->arg4;
    unsigned long flags = (unsigned long)fargs->arg5;

    printk(KERN_INFO "KMS| process_vm_readv | PID=%d TARGET=%d LOCAL_IOV=%px LIOVCNT=%lu REMOTE_IOV=%px RIOVCNT=%lu FLAGS=%lu\n",
           pid, target_pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t pid = current->pid;
    pid_t target_pid = (pid_t)fargs->arg0;
    const struct iovec __user *local_iov = (const struct iovec __user *)fargs->arg1;
    unsigned long liovcnt = (unsigned long)fargs->arg2;
    const struct iovec __user *remote_iov = (const struct iovec __user *)fargs->arg3;
    unsigned long riovcnt = (unsigned long)fargs->arg4;
    unsigned long flags = (unsigned long)fargs->arg5;

    printk(KERN_INFO "KMS| process_vm_writev | PID=%d TARGET=%d LOCAL_IOV=%px LIOVCNT=%lu REMOTE_IOV=%px RIOVCNT=%lu FLAGS=%lu\n",
           pid, target_pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

/* ---- 模块生命周期 ---- */
static long my_init(const char *args, const char *event, void __user *reserved)
{
    hook_err_t err;

    // 动态查找系统调用地址
    addr_pread64 = (uintptr_t)kallsyms_lookup_name("sys_pread64");
    addr_pwrite64 = (uintptr_t)kallsyms_lookup_name("sys_pwrite64");
    addr_process_vm_readv = (uintptr_t)kallsyms_lookup_name("sys_process_vm_readv");
    addr_process_vm_writev = (uintptr_t)kallsyms_lookup_name("sys_process_vm_writev");

    if (!addr_pread64 || !addr_pwrite64 || !addr_process_vm_readv || !addr_process_vm_writev) {
        printk(KERN_ERR "KernelMemorySky: failed to find syscall addresses\n");
        return -1;
    }

    // 安装钩子 (fp_hook_wrap 自动调用原函数)
    err = fp_hook_wrap4(addr_pread64, before_pread64, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook pread64 failed %d\n", err); return err; }

    err = fp_hook_wrap4(addr_pwrite64, before_pwrite64, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook pwrite64 failed %d\n", err); return err; }

    err = fp_hook_wrap6(addr_process_vm_readv, before_process_vm_readv, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook process_vm_readv failed %d\n", err); return err; }

    err = fp_hook_wrap6(addr_process_vm_writev, before_process_vm_writev, NULL, NULL);
    if (err) { printk(KERN_ERR "KMS: hook process_vm_writev failed %d\n", err); return err; }

    printk(KERN_INFO "KernelMemorySky: interceptor loaded successfully\n");
    return 0;
}

static long my_exit(void __user *reserved)
{
    // 卸载钩子
    if (addr_pread64)            fp_hook_unwrap(addr_pread64, before_pread64, NULL);
    if (addr_pwrite64)           fp_hook_unwrap(addr_pwrite64, before_pwrite64, NULL);
    if (addr_process_vm_readv)   fp_hook_unwrap(addr_process_vm_readv, before_process_vm_readv, NULL);
    if (addr_process_vm_writev)  fp_hook_unwrap(addr_process_vm_writev, before_process_vm_writev, NULL);

    printk(KERN_INFO "KernelMemorySky: interceptor unloaded\n");
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);