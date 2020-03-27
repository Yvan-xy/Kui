/*
* This kernel module locates the sys_call_table by kallsyms_lookup_name("sys_call_table");
*/

#include "../include/elf_32.h"
#include "../include/test.h"

/*
** module macros
*/
MODULE_LICENSE("GPL");


// initialize the module
static int hooked_init(void) {
    // Elf32BaseTester();
    // Elf64BaseTester();
    make_dir("/tmp/sign/");
    Sign64Tester();
    return 0;
}

static void hooked_exit(void) {
    rm_dir("/tmp/sign/");
    pr_info("Exit");
}

/*
** entry/exit macros
*/
module_init(hooked_init);
module_exit(hooked_exit);
