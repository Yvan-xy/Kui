//
// Created by root on 2020/3/21.
//

#include <apue.h>
#include <sign.h>
#include <elf_64.h>
#include <sign64.h>
#include <stdbool.h>

Elf64 *InitELF64(const char *path) {
    Elf64 *elf64 = (Elf64 *) malloc(sizeof(Elf64));
    SetElf64Path(elf64, path);
    bool ret = GetEhdr64(elf64);
    if (!ret)
        return NULL;

    ret = Getshstrtabhdr64(elf64);
    if (!ret)
        return NULL;

    ret = Getshstrtab64(elf64);
    if (!ret)
        return NULL;

    ret = GetFileSize64(elf64);
    if (!ret)
        return NULL;

    return elf64;
}

bool ReadELF64Sign(Elf64 *elf64) {
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, -256, SEEK_END);
    int ret = fread(elf64->sign, 1, 256, fd);
    if (ret != 256) {
        err_msg("Read digest failed");
        return false;
    }
    return true;
}

bool CheckSignELF64(Elf64 *elf64, RSA *pub) {
    return RSA_verify(NID_sha1, elf64->digest, SHA_DIGEST_LENGTH, elf64->sign, 256, pub);
}

bool CheckSign64(const char *pub, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign ----------\033[0m\n");
    Elf64 *elf64;

    elf64 = InitELF64(elfPath);
    RSA *public = ReadPublicKey(pub);
    if (public == NULL)
        return false;

    ReadELF64Sign(elf64);
    HashText64(elf64);

    int ret = CheckSignELF64(elf64, public);
    if (ret == false) {
        err_msg("ELF64 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF64 %s verify success!\n", elfPath);
    Destract64(elf64);
    return ret;
}

bool X509CheckSign64(const char *x509Path, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign with X509----------\033[0m\n");

    RSA *public;
    X509 *x509;
    Elf64 *elf64;
    EVP_PKEY *pubKey;

    elf64 = InitELF64(elfPath);

    x509 = ReadX509File(x509Path);
    pubKey = X509_get_pubkey(x509);

    if (pubKey == NULL) {
        err_msg("Get public key failed\n");
        return false;
    }

    public = EVP_PKEY_get1_RSA(pubKey);
    EVP_PKEY_free(pubKey);
    if (public == NULL) {
        err_msg("Get public key failed\n");
        return false;
    }

    ReadELF64Sign(elf64);
    HashText64(elf64);
    int ret = CheckSignELF64(elf64, public);
    if (ret == false) {
        err_msg("ELF64 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF64 %s verify success!\n", elfPath);
    Destract64(elf64);
    X509_free(x509);
    return ret;
}

