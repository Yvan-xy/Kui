#include "../include/sign.h"
#include "../include/sha1.h"


bool CheckSign(const char* checkBin, const char *elfPath) {
    char path[51];
    long int time = GetTimeStamp(); 
    unsigned char result[SHA_DIGEST_LENGTH];
    char resultPath[41], checkResult[1];
    pr_info("call_usermodehelper module isstarting..!\n");
    
    memset(path, 0, 51);

    SHA1(result, (const char *) &time, sizeof(time));
    for(int i = 0; i < 20; i++) {
        sprintf( ( resultPath + (2*i)), "%02x", result[i]&0xff);
    }
    
    char *argv[]={checkBin, elfPath, resultPath, NULL};
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    pr_info("Check sign64 ret=%d\n", ret);

    strcat(path, "/tmp/sign/");
    strcat(path, resultPath);
    pr_info("Result file %s", path);
    struct file *fd = file_open(path, O_RDONLY, 0);
    if (!fd) {
        pr_err("Can not open file %s", path);
        return false;
    }
    loff_t pos = fd->f_pos;
    ret = kernel_read(fd, checkResult, 1, &pos);
    file_close(fd);
    if (ret != 1) {
        pr_err("Read check result %s failed", path);
        return false;
    }

    pr_info("Check result is %d\n", checkResult[0]);
    if (checkResult[0] == 1)
        return true;
    else
        return false;    
}
