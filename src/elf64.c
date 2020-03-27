//
// Created by root on 2020/3/26.
//


#include "../include/elf_64.h"

bool IsELF64(const char *file) {
    int ret;
    loff_t pos;
    unsigned char ident[EI_NIDENT];
    struct file *fd = file_open(file, O_RDONLY, 0);
    if (!fd) {
        pr_err("Can not open file %s", file);
        return false;
    }
    pos = fd->f_pos;
    ret = kernel_read(fd, ident, EI_NIDENT, &pos);
    file_close(fd);
    if (ret != EI_NIDENT) {
        pr_err("Read ELF magic failed!");
        return false;
    }
    if (ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F') {
        if (ident[4] == 2)
            return true;
        else
            return false;
    } else {
        return false;
    }
}


void SetElf64Path(Elf64 *elf64, const char *path) {
    int len = strlen(path);
    elf64->path = (char *) kmalloc(len, GFP_KERNEL);
    strcpy(elf64->path, path);
}

bool GetEhdr64(Elf64 *elf64) {
    if (elf64->path == NULL) {
        pr_err("ELF file not set");
        return false;
    }
    struct file *fd = file_open(elf64->path, O_RDONLY, 0);
    if (!fd) {
        pr_err("Can not open file %s", elf64->path);
        return false;
    }
    loff_t pos = fd->f_pos;
    int ret = kernel_read(fd, &elf64->ehdr, sizeof(Elf64_Ehdr), &pos);
    file_close(fd);
    if (ret != sizeof(Elf64_Ehdr)) {
        pr_err("Read ELF Header failed");
        return false;
    }
    return true;
}

bool Getshstrtabhdr64(Elf64 *elf64) {
    int offset = 0;
    if (elf64->path == NULL) {
        pr_err("ELF file not set");
        return false;
    }
    struct file *fd = file_open(elf64->path, O_RDONLY, 0);
    if (!fd) {
        pr_err("Can not open file %s", elf64->path);
        return false;
    }
    offset = elf64->ehdr.e_shoff + elf64->ehdr.e_shentsize * elf64->ehdr.e_shstrndx;
    vfs_llseek(fd, offset, SEEK_SET);
    loff_t pos = fd->f_pos;
    int ret = kernel_read(fd, &elf64->shstrtabhdr, sizeof(Elf64_Shdr), &pos);
    file_close(fd);
    if (ret != sizeof(Elf64_Shdr)) {
        pr_err("Read Section Header Table failed");
        return false;
    }
    return true;
}

bool Getshstrtab64(Elf64 *elf64) {
    if (elf64->path == NULL) {
        pr_err("ELF file not set");
        return false;
    }
    struct file *fd = file_open(elf64->path, O_RDONLY, 0);
    if (!fd) {
        pr_err("Can not open file %s", elf64->path);
        return false;
    }
    elf64->shstrtab = (char *) kmalloc(elf64->shstrtabhdr.sh_size, GFP_KERNEL);
    vfs_llseek(fd, elf64->shstrtabhdr.sh_offset, SEEK_SET);
    loff_t pos = fd->f_pos;
    int ret = kernel_read(fd, elf64->shstrtab, elf64->shstrtabhdr.sh_size, &pos);
    file_close(fd);
    if (ret != elf64->shstrtabhdr.sh_size) {
        pr_err("Read shstrtab Section failed");
        return false;
    }
    return true;
}

// Get orign file size
int GetFileSize64(Elf64 *elf64) {
    mm_segment_t fs;
    struct kstat stat;
    if (!elf64->path) {
        pr_err("ELF file not set");
        return -1;
    }

    fs = get_fs();
    set_fs(KERNEL_DS);
    vfs_stat(elf64->path, &stat);
    set_fs(fs);
    pr_info("stat size %lld", stat.size);
    elf64->size = stat.size;
    return elf64->size;
}

bool HashText64(Elf64 *elf64) {
    Elf64_Shdr tmp;
    int textOffset;
    char name[20];
    Elf64_Off sectionHeaderTable = elf64->ehdr.e_shoff;

    struct file *fd = file_open(elf64->path, O_RDONLY, 0);
    if (!fd) {
        pr_err("Open file %s failed", elf64->path);
        return false;
    }

    // Find the .text section header item
    vfs_llseek(fd, sectionHeaderTable, SEEK_SET);
    loff_t pos = fd->f_pos;
    do {
        int ret = kernel_read(fd, &tmp, sizeof(Elf64_Shdr), &pos);
        if (ret != sizeof(Elf64_Shdr)) {
            pr_err("Read section header failed");
            return false;
        }
        strcpy(name, elf64->shstrtab + tmp.sh_name);
       pr_info("Section name is %s", name);
    } while (strcmp(name, ".text"));
    if (strcmp(name, ".text")) {
        pr_err("Not found .text section");
        return false;
    }

    char *text = (char *) kmalloc(tmp.sh_size, GFP_KERNEL);
    textOffset = tmp.sh_offset;
    vfs_llseek(fd, textOffset, SEEK_SET);
    pos = fd->f_pos;
    int ret = kernel_read(fd, text, tmp.sh_size, &pos);
    file_close(fd);
    if (ret != tmp.sh_size) {
        pr_err("Read .text section failed");
        return false;
    }

    SHA1(elf64->digest, text, tmp.sh_size);

    kfree(text);
    return true;
}

void Destract64(Elf64 *elf64) {
    if (elf64->path != NULL) {
        kfree(elf64->path);
    }
    if (elf64->shstrtab != NULL) {
        kfree(elf64->shstrtab);
    }
}












