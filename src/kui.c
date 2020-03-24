#include <linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dyf");
MODULE_DESCRIPTION("Verifying the ELF's sign");
MODULE_VERSION("0.1");

static int __init

lkp_init(void) {
    printk("<1>Hello, World! from the kernel space...\n");
    return 0;
}

static void __exit

lkp_cleanup(void) {
    printk("<1>Good Bye, World! leaving kernel space...\n");
}

module_init(lkp_init);    // 注册模块
module_exit(lkp_cleanup);    // 注销模块

