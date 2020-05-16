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
    Elf64_Off programHeaderTable = elf64->ehdr.e_phoff;
    Elf64_Phdr tmp;
    char name[20];
    unsigned char *content = NULL;
    unsigned char buf[1];

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, programHeaderTable, SEEK_SET);
    for (int count = 0; count < elf64->ehdr.e_phnum; ++count) {

        size_t ret = fread(&tmp, 1, sizeof(Elf64_Phdr), fd);
        if (ret != sizeof(Elf64_Phdr)) {
            err_msg("Read Program Header failed");
            return false;
        }

        /* Judge if Load Segment */
        if (tmp.p_type != PT_LOAD || tmp.p_offset == 0)
            continue;

        content = GetLoadSegment64(elf64, &tmp);

        SHA1_Update(&ctx, content, tmp.p_filesz);

        if (content != NULL)
            free(content);

        content = NULL;
    }

    fclose(fd);
    SHA1_Final(elf64->digest, &ctx);
    return true;
}

unsigned char *GetLoadSegment64(Elf64 *elf64, Elf64_Phdr *phdr) {
    if (phdr == NULL) {
        err_msg("phdr not exist");
        return false;
    }
    Elf64_Off p_offset = phdr->p_offset;
    Elf64_Word p_filesz = phdr->p_filesz;

    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return NULL;
    }

    char *content = malloc(p_filesz);

    fseek(fd, p_offset, SEEK_SET);

    int ret = fread(content, 1, p_filesz, fd);
    fclose(fd);
    if (ret != p_filesz) {
        err_msg("Read Program Header -> content failed");
        return NULL;
    }
    return content;
}

void Destract64(Elf64 *elf64) {
    if (elf64->path != NULL) {
        free(elf64->path);
    }
    if (elf64->shstrtab != NULL) {
        free(elf64->shstrtab);
    }
}



















