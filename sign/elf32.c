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
    Elf32_Off programHeaderTable = elf32->ehdr.e_phoff;
    Elf32_Phdr tmp;
    char name[20];
    unsigned char *content = NULL;

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    fseek(fd, programHeaderTable, SEEK_SET);
    for (int count = 0; count < elf32->ehdr.e_phnum; ++count) {

        size_t ret = fread(&tmp, 1, sizeof(Elf32_Phdr), fd);
        if (ret != sizeof(Elf32_Phdr)) {
            err_msg("Read Program Header failed");
            return false;
        }

#if(LOG_MODE == 1)
        log_msg("p_type is %d", tmp.p_type);
        log_msg("p_offset is %p", tmp.p_offset);
        log_msg("p_vaddr is %p", tmp.p_vaddr);
        log_msg("p_filez is %p", tmp.p_filesz);
        log_msg("----------->");
#endif

        /* Judge if Load Segment */
        if (tmp.p_type != PT_LOAD || tmp.p_offset == 0)
            continue;

        content = GetLoadSegment32(elf32, &tmp);

#if(LOG_MODE == 1)
        printf("\n----------> Load Segment Content\n");
        for (int i = 0; i < tmp.p_filesz; i++) {
            printf("%p ", content[i]);
        }
#endif

        SHA1_Update(&ctx, content, tmp.p_filesz);

        if (content != NULL)
            free(content);

        content = NULL;
    }

    fclose(fd);
    SHA1_Final(elf32->digest, &ctx);
    return true;
}

unsigned char *GetLoadSegment32(Elf32 *elf32, Elf32_Phdr *phdr) {
    if (phdr == NULL) {
        err_msg("phdr not exist");
        return false;
    }
    Elf32_Off p_offset = phdr->p_offset;
    Elf32_Word p_filesz = phdr->p_filesz;

    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
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

void Destract32(Elf32 *elf32) {
    if (elf32->path != NULL) {
        free(elf32->path);
    }
    if (elf32->shstrtab != NULL) {
        free(elf32->shstrtab);
    }
}



















