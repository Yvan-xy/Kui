//
// Created by root on 2020/3/21.
//


#include <elf_64.h>

bool IsELF64(const char *file) {
    unsigned char ident[EI_NIDENT];
    FILE *fd = fopen(file, "rb");
    if (!fd) {
        err_msg("Can not open file %s", file);
        return false;
    }
    int ret = fread(ident, 1, EI_NIDENT, fd);
    fclose(fd);
    if (ret != EI_NIDENT) {
        err_msg("Read ELF magic failed!");
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
    elf64->path = (char *) malloc(len);
    strcpy(elf64->path, path);
}

bool GetEhdr64(Elf64 *elf64) {
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    int ret = fread(&elf64->ehdr, 1, sizeof(Elf64_Ehdr), fd);
    fclose(fd);
    if (ret != sizeof(Elf64_Ehdr)) {
        err_msg("Read ELF Header failed");
        return false;
    }
    return true;
}

bool Getshstrtabhdr64(Elf64 *elf64) {
    int offset = 0;
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    offset = elf64->ehdr.e_shoff + elf64->ehdr.e_shentsize * elf64->ehdr.e_shstrndx;
    fseek(fd, offset, SEEK_SET);
    int ret = fread(&elf64->shstrtabhdr, 1, sizeof(Elf64_Shdr), fd);
    if (ret != sizeof(Elf64_Shdr)) {
        err_msg("Read Section Header Table failed");
        return false;
    }
    return true;
}

bool Getshstrtab64(Elf64 *elf64) {
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    elf64->shstrtab = (char *) malloc(elf64->shstrtabhdr.sh_size);
    fseek(fd, elf64->shstrtabhdr.sh_offset, SEEK_SET);
    int ret = fread(elf64->shstrtab, 1, elf64->shstrtabhdr.sh_size, fd);
    fclose(fd);
    if (ret != elf64->shstrtabhdr.sh_size) {
        err_msg("Read shstrtab Section failed");
        return false;
    }
    return true;
}

// Get orign file size
int GetFileSize64(Elf64 *elf64) {
    if (!elf64->path) {
        err_msg("ELF file not set");
        return -1;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return -1;
    }
    fseek(fd, 0, SEEK_END);
    elf64->size = ftell(fd);
    return elf64->size;
}


bool HashText64(Elf64 *elf64) {
    Elf64_Off sectionHeaderTable = elf64->ehdr.e_shoff;
    Elf64_Shdr tmp;
    int textOffset;
    char name[20];
    unsigned char buf[1];

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, sectionHeaderTable, SEEK_SET);
    do {
        int ret = fread(&tmp, 1, sizeof(Elf64_Shdr), fd);
        if (ret != sizeof(Elf64_Shdr)) {
            err_msg("Read section header failed");
            return false;
        }
        strcpy(name, elf64->shstrtab + tmp.sh_name);
//        log_msg("Section name is %s", name);
    } while (strcmp(name, ".text"));
    if (strcmp(name, ".text")) {
        err_msg("Not found .text section");
        return false;
    }
    textOffset = tmp.sh_offset;
    fseek(fd, textOffset, SEEK_SET);

    for (int i = 0; i < tmp.sh_size; i++) {
        int ret = fread(buf, 1, 1, fd);
        if (ret != 1) {
            err_msg("Read .text section failed");
            return false;
        }
        SHA1_Update(&ctx, buf, 1);
    }
    fclose(fd);
    SHA1_Final(elf64->digest, &ctx);
    return true;
}

void Destract64(Elf64 *elf64) {
    if (elf64->path != NULL) {
        free(elf64->path);
    }
    if (elf64->shstrtab != NULL) {
        free(elf64->shstrtab);
    }
}



















