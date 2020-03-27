//
// Created by root on 2020/3/26.
//

#ifndef KUI_ELF_32_H
#define KUI_ELF_32_H

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
    Elf32_Ehdr ehdr;
    Elf32_Shdr shstrtabhdr;
    char *shstrtab;
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char sign[256];
} Elf32;

bool IsELF32(const char *file);

void SetElf32Path(Elf32 *elf32, const char *path);

bool GetEhdr32(Elf32 *elf32);

bool Getshstrtabhdr32(Elf32 *elf32);

bool Getshstrtab32(Elf32 *elf32);

int GetFileSize32(Elf32 *elf32);

bool HashText32(Elf32 *elf32);

void Destract32(Elf32 *elf32);

#endif //KUI_ELF_32_H
