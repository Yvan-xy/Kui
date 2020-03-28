#ifndef SIGN_H
#define SIGN_H

#include <apue.h>
#include <dirent.h>
#include <config.h>
#include <errno.h>  // for definition of errno
#include <stdarg.h> // ISO C variable aruments
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

// ---- rsa非对称加解密 ---- //


char *READ_PUB_KEY_PATH;
char *READ_PRIV_KEY_PATH;

void SetPublicKeyPath(const char *path);

void SetPrivateKeyPath(const char *path);

char *GetPublicKeyPath();

char *GetPrivateKeyPath();

RSA *ReadPublicKey(const char *path);

int GetSign(unsigned char *hash, unsigned char *sign, RSA *pri);

int RSACheckSign(const char *contain, unsigned char *sign, int signLen, RSA *pub);

char *Base64Encode(const unsigned char *input, int length);

char *Base64Decode(const char *input, int length);

X509 *ReadX509File(const char *path);

void WriteResult(const char *path, bool result);

char *GetKeyFullPath(const char *pub);

char *GetX509FullPath(const char *pub);

DIR *GetAllFiles(const char *path);


#endif
