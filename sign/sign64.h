//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_SIGN64_H
#define ELFSIGN_SIGN64_H

#include <sign.h>
#include <string.h>
#include <elf_64.h>

Elf64 *InitELF64(const char *path);

bool ReadELF64Sign(Elf64 *elf64);

bool CheckSignELF64(Elf64 *elf64, RSA *pub);

bool CheckSign64(const char *pub, const char *elfPath);

bool X509CheckSign64(const char *x509Path, const char *elfPath);

#endif //ELFSIGN_SIGN64_H
