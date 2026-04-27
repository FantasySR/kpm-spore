#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <hook.h>
#include <ktypes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>

/* 前向声明 struct device 和 struct list_head，避免包含 linux/device.h */
struct device;
struct kiocb;
struct iov_iter;
struct poll_table_struct;
struct vm_area_struct;
struct file_lock;
struct page;
struct pipe_inode_info;
struct seq_file;

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel memory read/write via misc device");

/* 手动补充缺失的宏和类型 */
#define GFP_KERNEL 0xcc0U
#define FOLL_FORCE 0x10
#define FOLL_WRITE 0x01
#define MISC_DYNAMIC_MINOR 255
#define THIS_MODULE ((struct module *)0)

/* 补全 struct file_operations（同之前） */
struct file_operations {
    struct module *owner;
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *kiocb, bool spin);
    int (*iterate)(struct file *, struct dir_context *);
    int (*iterate_shared)(struct file *, struct dir_context *);
    __poll_t (*poll)(struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
    long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
    int (*mmap)(struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open)(struct inode *, struct file *);
    int (*flush)(struct file *, fl_owner_t id);
    int (*release)(struct inode *, struct file *);
    int (*fsync)(struct file *, loff_t, loff_t, int datasync);
    int (*fasync)(int, struct file *, int);
    int (*lock)(struct file *, int, struct file_lock *);
    ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock)(struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out, loff_t len, unsigned int remap_flags);
    int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;

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

/* 命令定义 */
#define CMD_READ_MEM  0x1001
#define CMD_WRITE_MEM 0x1002

struct mem_data {
    pid_t pid;
    unsigned long addr;
    unsigned long size;
    void __user *buf;
};

/* 函数指针类型 */
typedef struct task_struct *(*find_task_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef int (*misc_register_t)(struct miscdevice *);
typedef void (*misc_deregister_t)(struct miscdevice *);
typedef void *(*kmalloc_t)(size_t, gfp_t);
typedef void (*kfree_t)(const void *);

static find_task_t find_task_by_vpid_func;
static get_task_mm_t get_task_mm_func;
static mmput_t mmput_func;
static access_process_vm_t access_process_vm_func;
static copy_from_user_t copy_from_user_func;
static copy_to_user_t copy_to_user_func;
static misc_register_t misc_register_func;
static misc_deregister_t misc_deregister_func;
static kmalloc_t kmalloc_func;
static kfree_t kfree_func;

static int my_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "KernelMemorySky: device opened\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "KernelMemorySky: device closed\n");
    return 0;
}

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

    task = find_task_by_vpid_func(data.pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm_func(task);
    if (!mm)
        return -EINVAL;

    kbuf = kmalloc_func(data.size, GFP_KERNEL);
    if (!kbuf) {
        mmput_func(mm);
        return -ENOMEM;
    }

    switch (cmd) {
    case CMD_READ_MEM:
        bytes = access_process_vm_func(task, data.addr, kbuf, data.size, FOLL_FORCE);
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
                                       FOLL_FORCE | FOLL_WRITE);
        if (bytes >= 0)
            ret = bytes;
        else
            ret = bytes;
        break;

    default:
        ret = -ENOTTY;
        break;
    }

    kfree_func(kbuf);
    mmput_func(mm);
    return ret;
}

static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "my_misc_device",
    .fops = &my_fops,
};

static long control0(const char *args, char __user *out_msg, int outlen)
{
    return 0;
}

static long init(const char *args, const char *event, void __user *reserved)
{
    find_task_by_vpid_func = (find_task_t)kallsyms_lookup_name("find_task_by_vpid");
    get_task_mm_func = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    mmput_func = (mmput_t)kallsyms_lookup_name("mmput");
    access_process_vm_func = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    copy_from_user_func = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    copy_to_user_func = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    misc_register_func = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_deregister_func = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");
    kmalloc_func = (kmalloc_t)kallsyms_lookup_name("kmalloc");
    kfree_func = (kfree_t)kallsyms_lookup_name("kfree");

    if (!find_task_by_vpid_func || !get_task_mm_func || !mmput_func ||
        !access_process_vm_func || !copy_from_user_func || !copy_to_user_func ||
        !misc_register_func || !misc_deregister_func || !kmalloc_func || !kfree_func) {
        printk(KERN_ERR "KernelMemorySky: symbol lookup failed\n");
        return -1;
    }

    int ret = misc_register_func(&my_misc_device);
    if (ret < 0) {
        printk(KERN_ERR "KernelMemorySky: register failed\n");
        return ret;
    }
    printk(KERN_INFO "KernelMemorySky: /dev/%s registered\n", my_misc_device.name);
    return 0;
}

static long exit(void __user *reserved)
{
    if (misc_deregister_func)
        misc_deregister_func(&my_misc_device);
    printk(KERN_INFO "KernelMemorySky: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_CTL0(control0);
KPM_EXIT(exit);