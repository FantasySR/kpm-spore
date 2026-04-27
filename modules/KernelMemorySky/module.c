#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/gfp.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel memory r/w via KPM_CTL0");

/* 手动声明 KernelPatch 风格的内核函数指针 */
extern typeof(find_task_by_vpid) *kf_find_task_by_vpid;
extern typeof(get_task_mm)      *kf_get_task_mm;
extern typeof(mmput)            *kf_mmput;
extern typeof(access_process_vm) *kf_access_process_vm;
extern typeof(copy_from_user)   *kf_copy_from_user;
extern typeof(copy_to_user)     *kf_copy_to_user;
extern typeof(kmalloc)          *kf_kmalloc;
extern typeof(kfree)            *kf_kfree;

/* 将函数调用重定向到函数指针 */
#define find_task_by_vpid   (*kf_find_task_by_vpid)
#define get_task_mm         (*kf_get_task_mm)
#define mmput               (*kf_mmput)
#define access_process_vm   (*kf_access_process_vm)
#define copy_from_user      (*kf_copy_from_user)
#define copy_to_user        (*kf_copy_to_user)
#define kmalloc             (*kf_kmalloc)
#define kfree               (*kf_kfree)

/* 缺失的宏 */
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0U
#endif
#ifndef FOLL_FORCE
#define FOLL_FORCE 0x10
#endif
#ifndef FOLL_WRITE
#define FOLL_WRITE 0x01
#endif

/* 命令定义 */
#define CMD_READ_MEM  0x1001
#define CMD_WRITE_MEM 0x1002

struct mem_data {
    pid_t pid;
    unsigned long addr;
    unsigned long size;
    void __user *buf;
};

static long amf_ctl0(const char *args, char __user *out_msg, int outlen)
{
    unsigned int cmd;
    struct mem_data __user *user_data;
    struct mem_data data;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf = NULL;
    long ret = 0;
    int bytes;

    if (!args || outlen < sizeof(cmd))
        return -EINVAL;

    if (copy_from_user(&cmd, args, sizeof(cmd)))
        return -EFAULT;

    if (cmd != CMD_READ_MEM && cmd != CMD_WRITE_MEM)
        return -ENOTTY;

    user_data = (struct mem_data __user *)(args + sizeof(cmd));

    if (copy_from_user(&data, user_data, sizeof(data)))
        return -EFAULT;

    if (data.size > 0x100000)
        return -EINVAL;

    task = find_task_by_vpid(data.pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm)
        return -EINVAL;

    kbuf = kmalloc(data.size, GFP_KERNEL);
    if (!kbuf) {
        mmput(mm);
        return -ENOMEM;
    }

    switch (cmd) {
    case CMD_READ_MEM:
        bytes = access_process_vm(task, data.addr, kbuf, data.size, FOLL_FORCE);
        if (bytes > 0) {
            if (copy_to_user(data.buf, kbuf, bytes))
                ret = -EFAULT;
            else
                ret = bytes;
        } else if (bytes == 0) {
            ret = 0;
        } else {
            ret = bytes;
        }
        break;

    case CMD_WRITE_MEM:
        if (copy_from_user(kbuf, data.buf, data.size)) {
            ret = -EFAULT;
            break;
        }
        bytes = access_process_vm(task, data.addr, kbuf, data.size,
                                  FOLL_FORCE | FOLL_WRITE);
        if (bytes >= 0)
            ret = bytes;
        else
            ret = bytes;
        break;
    }

    kfree(kbuf);
    mmput(mm);
    return ret;
}

static long my_init(const char *args, const char *event, void __user *reserved)
{
    printk(KERN_INFO "KernelMemorySky: loaded (CTL0 mode)\n");
    return 0;
}

static long my_exit(void __user *reserved)
{
    printk(KERN_INFO "KernelMemorySky: unloaded\n");
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);
KPM_CTL0(amf_ctl0);