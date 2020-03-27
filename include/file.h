//
// Created by root on 2020/3/26.
//

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/buffer_head.h>

struct file *file_open(const char *path, int flags, int rights);

void file_close(struct file *file);

bool make_dir(const char *path);

bool rm_dir(const char *path);

long int GetTimeStamp(void);
