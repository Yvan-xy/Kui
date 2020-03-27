#include "../include/file.h"
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/time.h>

struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) {
    filp_close(file, NULL);
}

bool make_dir(const char *path) {
    char *argv_rm[] = {"/bin/rmdir", path, NULL};
    char *argv[]={"/bin/mkdir", "-m", "700", path, NULL};
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    pr_info("Make directory %s\n", path);
    int ret = call_usermodehelper(argv_rm[0], argv_rm, envp, UMH_WAIT_PROC);
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    pr_info("ret=%d\n", ret);
    if (ret != 0) {
        pr_err("Make dir failed");
        return false;
    }
    return true;
}


bool rm_dir(const char *path) {
    char *argv_rm[] = {"/bin/rm", "-rf", path, NULL};
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    pr_info("Remove directory %s\n", path);
    int ret = call_usermodehelper(argv_rm[0], argv_rm, envp, UMH_WAIT_PROC);
    return true;
}


long int GetTimeStamp(void) {
    struct timespec tm;
    getnstimeofday(&tm);
    return tm.tv_sec;
}