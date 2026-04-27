#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/slab.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel memory r/w via KPM_CTL0");

/* 用 kfunc_def 声明所需的内核函数，KernelPatch 自动绑定 */
kfunc_def(find_task_by_vpid)
kfunc_def(get_task_mm)
kfunc_def(mmput)
kfunc_def(access_process_vm)
kfunc_def(copy_from_user)
kfunc_def(copy_to_user)
kfunc_def(kmalloc)
kfunc_def(kfree)

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

    /* 获取命令 */
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