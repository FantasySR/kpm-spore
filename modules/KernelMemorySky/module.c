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

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel memory read/write via misc device");

// 符号查找函数指针类型
typedef void *(*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_func;

// 内核函数指针
typedef struct task_struct *(*find_task_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef int (*misc_register_t)(void *);
typedef void (*misc_deregister_t)(void *);
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

// 模块初始化
static long init(const char *args, const char *event, void __user *reserved)
{
    // 先把关键日志级别提上去
    printk(KERN_CRIT "KernelMemorySky: init started\n");

    // 动态查找符号
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t)kallsyms_lookup_name("kallsyms_lookup_name");
    if (!kallsyms_lookup_name_func) {
        printk(KERN_CRIT "KernelMemorySky: kallsyms_lookup_name not found\n");
        return -1;
    }
    
    // 用查到的函数进一步查找其他符号
    find_task_by_vpid_func = (find_task_t)kallsyms_lookup_name_func("find_task_by_vpid");
    get_task_mm_func = (get_task_mm_t)kallsyms_lookup_name_func("get_task_mm");
    mmput_func = (mmput_t)kallsyms_lookup_name_func("mmput");
    access_process_vm_func = (access_process_vm_t)kallsyms_lookup_name_func("access_process_vm");
    copy_from_user_func = (copy_from_user_t)kallsyms_lookup_name_func("copy_from_user");
    copy_to_user_func = (copy_to_user_t)kallsyms_lookup_name_func("copy_to_user");
    misc_register_func = (misc_register_t)kallsyms_lookup_name_func("misc_register");
    misc_deregister_func = (misc_deregister_t)kallsyms_lookup_name_func("misc_deregister");
    kmalloc_func = (kmalloc_t)kallsyms_lookup_name_func("kmalloc");
    kfree_func = (kfree_t)kallsyms_lookup_name_func("kfree");

    printk(KERN_CRIT "KernelMemorySky: find_task_by_vpid=%p\n", find_task_by_vpid_func);
    printk(KERN_CRIT "KernelMemorySky: misc_register=%p\n", misc_register_func);
    
    if (!find_task_by_vpid_func || !get_task_mm_func || !mmput_func ||
        !access_process_vm_func || !copy_from_user_func || !copy_to_user_func ||
        !misc_register_func || !misc_deregister_func || !kmalloc_func || !kfree_func) {
        printk(KERN_CRIT "KernelMemorySky: required kernel symbols not found\n");
        return -1;
    }

    // 注册一个极简的 misc 设备结构，直接调用函数
    struct {
        int minor;
        const char *name;
        void *fops;
    } misc_dev = {
        .minor = 255,
        .name = "my_misc_device",
        .fops = NULL,
    };

    int ret = misc_register_func(&misc_dev);
    if (ret < 0) {
        printk(KERN_CRIT "KernelMemorySky: misc_register failed, ret=%d\n", ret);
        return ret;
    }
    
    printk(KERN_CRIT "KernelMemorySky: device /dev/%s registered\n", misc_dev.name);
    return 0;
}

static long exit(void __user *reserved)
{
    if (misc_deregister_func) {
        // 这里需要传入已注册的设备地址，但为了简洁先省略
        // 实际卸载时我们会做更完善的注销
    }
    printk(KERN_CRIT "KernelMemorySky: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);