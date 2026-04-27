#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <hook.h>
#include <ktypes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel memory read/write via misc device");

#define DEVICE_NAME "my_misc_device"

// ---------- 命令定义 ----------
#define CMD_READ_MEM  0x1001
#define CMD_WRITE_MEM 0x1002

struct mem_data {
    pid_t pid;
    unsigned long addr;
    unsigned long size;
    void __user *buf;
};

// ---------- 内核函数指针 ----------
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t pid);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *task);
typedef void (*mmput_ptr)(struct mm_struct *mm);
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, unsigned int gup_flags);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from, unsigned long n);

static find_task_by_vpid_t find_task_by_vpid_func;
static get_task_mm_t get_task_mm_func;
static mmput_ptr mmput_func;
static access_process_vm_t access_process_vm_func;
static copy_from_user_t copy_from_user_func;
static copy_to_user_t copy_to_user_func;

// ---------- 杂项设备相关 ----------
#ifdef MODULE
struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

struct miscdevice {
    int minor;
    const char *name;
    const struct file_operations *fops;
    struct list_head list;
    struct device *parent;
    struct device *this_device;
    const struct attribute_group **groups;
    const char *nodename;
    umode_t mode;
};

typedef int (*misc_register_t)(struct miscdevice *misc);
typedef void (*misc_deregister_t)(struct miscdevice *misc);
static misc_register_t misc_register_func;
static misc_deregister_t misc_deregister_func;

// ---------- 设备操作函数 ----------
static int my_misc_open(struct inode *inode, struct file *file)
{
    pr_info("KernelMemorySky: device opened\n");
    return 0;
}

static int my_misc_release(struct inode *inode, struct file *file)
{
    pr_info("KernelMemorySky: device closed\n");
    return 0;
}

// ---------- ioctl 分发（核心读写逻辑） ----------
static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct mem_data __user *user_data = (struct mem_data __user *)arg;
    struct mem_data data;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf = NULL;
    long ret = 0;
    int bytes;

    if (!user_data)
        return -EINVAL;

    if (copy_from_user_func(&data, user_data, sizeof(data)))
        return -EFAULT;

    if (data.size > 0x100000)
        return -EINVAL;

    // 获取目标进程 mm
    task = find_task_by_vpid_func(data.pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm_func(task);
    if (!mm)
        return -EINVAL;

    kbuf = kmalloc(data.size, GFP_KERNEL);
    if (!kbuf) {
        mmput_func(mm);
        return -ENOMEM;
    }

    switch (cmd) {
    case CMD_READ_MEM:
        bytes = access_process_vm_func(task, data.addr, kbuf, data.size, 0x10 /* FOLL_FORCE */);
        if (bytes > 0) {
            if (copy_to_user_func(data.buf, kbuf, bytes))
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
        if (copy_from_user_func(kbuf, data.buf, data.size)) {
            ret = -EFAULT;
            break;
        }
        bytes = access_process_vm_func(task, data.addr, kbuf, data.size,
                                       0x10 | 0x01 /* FOLL_FORCE | FOLL_WRITE */);
        if (bytes >= 0)
            ret = bytes;
        else
            ret = bytes;
        break;

    default:
        ret = -ENOTTY;
        break;
    }

    kfree(kbuf);
    mmput_func(mm);
    return ret;
}

static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_misc_open,
    .release = my_misc_release,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &my_fops,
};

// ---------- KPM 控制入口（保留，可备用） ----------
static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

// ---------- 模块初始化/退出 ----------
static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    // 动态查找所需符号
    find_task_by_vpid_func = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    get_task_mm_func = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    mmput_func = (mmput_ptr)kallsyms_lookup_name("mmput");
    access_process_vm_func = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    copy_from_user_func = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    copy_to_user_func = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    misc_register_func = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_deregister_func = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");

    if (!find_task_by_vpid_func || !get_task_mm_func || !mmput_func ||
        !access_process_vm_func || !copy_from_user_func || !copy_to_user_func ||
        !misc_register_func || !misc_deregister_func) {
        pr_err("KernelMemorySky: Failed to find required kernel symbols\n");
        return -1;
    }

    int ret = misc_register_func(&my_misc_device);
    if (ret < 0) {
        pr_err("KernelMemorySky: Failed to register misc device, ret=%d\n", ret);
        return ret;
    }

    pr_info("KernelMemorySky: device /dev/%s registered, minor=%d\n", DEVICE_NAME, my_misc_device.minor);
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    if (misc_deregister_func)
        misc_deregister_func(&my_misc_device);
    pr_info("KernelMemorySky: device unregistered\n");
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);