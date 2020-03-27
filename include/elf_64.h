//
// Created by root on 2020/3/26.
//

#ifndef KUI_ELF_64_H
#define KUI_ELF_64_H

// #include <stdbool.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#include "file.h"
#include "sha1.h"

#define SHA_DIGEST_LENGTH 21

typedef struct {
    long int size;
    char *path;
    Elf64_Ehdr ehdr;
    Elf64_Shdr shstrtabhdr;
    char *shstrtab;
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char sign[256];
} Elf64;


bool IsELF64(const char *file);

void SetElf64Path(Elf64 *elf64, const char *path);

bool GetEhdr64(Elf64 *elf64);

bool Getshstrtabhdr64(Elf64 *elf64);

bool Getshstrtab64(Elf64 *elf64);

int GetFileSize64(Elf64 *elf64);

bool HashText64(Elf64 *elf64);

void Destract64(Elf64 *elf64);

#endif //KUI_ELF_64_H
