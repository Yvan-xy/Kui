//
// Created by root on 2020/3/21.
//


#include <elf_32.h>

bool IsELF32(const char *file) {
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
        if (ident[4] == 1)
            return true;
        else
            return false;
    } else {
        return false;
    }
}

void SetElf32Path(Elf32 *elf32, const char *path) {
    int len = strlen(path);
    elf32->path = (char *) malloc(len);
    strcpy(elf32->path, path);
}

bool GetEhdr32(Elf32 *elf32) {
    if (elf32->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    int ret = fread(&elf32->ehdr, 1, sizeof(Elf32_Ehdr), fd);
    fclose(fd);
    if (ret != sizeof(Elf32_Ehdr)) {
        err_msg("Read ELF Header failed");
        return false;
    }
    return true;
}

bool Getshstrtabhdr32(Elf32 *elf32) {
    int offset = 0;
    if (elf32->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    offset = elf32->ehdr.e_shoff + elf32->ehdr.e_shentsize * elf32->ehdr.e_shstrndx;
    fseek(fd, offset, SEEK_SET);
    int ret = fread(&elf32->shstrtabhdr, 1, sizeof(Elf32_Shdr), fd);
    if (ret != sizeof(Elf32_Shdr)) {
        err_msg("Read Section Header Table failed");
        return false;
    }
    return true;
}

bool Getshstrtab32(Elf32 *elf32) {
    if (elf32->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    elf32->shstrtab = (char *) malloc(elf32->shstrtabhdr.sh_size);
    fseek(fd, elf32->shstrtabhdr.sh_offset, SEEK_SET);
    int ret = fread(elf32->shstrtab, 1, elf32->shstrtabhdr.sh_size, fd);
    fclose(fd);
    if (ret != elf32->shstrtabhdr.sh_size) {
        err_msg("Read shstrtab Section failed");
        return false;
    }
    return true;
}

// Get orign file size
int GetFileSize32(Elf32 *elf32) {
    if (!elf32->path) {
        err_msg("ELF file not set");
        return -1;
    }
    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return -1;
    }
    fseek(fd, 0, SEEK_END);
    elf32->size = ftell(fd);
    return elf32->size;
}


bool HashText32(Elf32 *elf32) {
    Elf32_Off sectionHeaderTable = elf32->ehdr.e_shoff;
    Elf32_Shdr tmp;
    int textOffset;
    char name[20];
    unsigned char buf[1];

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    fseek(fd, sectionHeaderTable, SEEK_SET);
    do {
        int ret = fread(&tmp, 1, sizeof(Elf32_Shdr), fd);
        if (ret != sizeof(Elf32_Shdr)) {
            err_msg("Read section header failed");
            return false;
        }
        strcpy(name, elf32->shstrtab + tmp.sh_name);
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
    SHA1_Final(elf32->digest, &ctx);
    return true;
}

void Destract32(Elf32 *elf32) {
    if (elf32->path != NULL) {
        free(elf32->path);
    }
    if (elf32->shstrtab != NULL) {
        free(elf32->shstrtab);
    }
}



















