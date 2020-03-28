//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_SIGN32_H
#define ELFSIGN_SIGN32_H

#include <sign.h>
#include <string.h>
#include <elf_32.h>

Elf32 *InitELF32(const char *path);

bool ReadELF32Sign(Elf32 *elf32);

bool CheckSignELF32(Elf32 *elf32, RSA *pub);

bool CheckSign32(const char *pub, const char *elfPath);

bool X509CheckSign32(const char *x509Path, const char *elfPath);

#endif //ELFSIGN_SIGN32_H
