#include <sign.h>

void SetPublicKeyPath(const char *path) {
    unsigned long len = strlen(path);
    if (READ_PUB_KEY_PATH != NULL)
        free(READ_PUB_KEY_PATH);
    READ_PUB_KEY_PATH = (char *) malloc(len);
    if (READ_PUB_KEY_PATH == NULL)
        err_msg("Set public key path failed");
    strcpy(READ_PUB_KEY_PATH, path);
}

void SetPrivateKeyPath(const char *path) {
    unsigned long len = strlen(path);
    if (READ_PRIV_KEY_PATH != NULL)
        free(READ_PRIV_KEY_PATH);
    READ_PRIV_KEY_PATH = (char *) malloc(len);
    if (READ_PRIV_KEY_PATH == NULL)
        err_msg("Set private key path failed");
    strcpy(READ_PRIV_KEY_PATH, path);
}

char *GetPublicKeyPath() {
    return READ_PUB_KEY_PATH;
}

char *GetPrivateKeyPath() {
    return READ_PRIV_KEY_PATH;
}

/*读取公匙*/
RSA *ReadPublicKey(const char *path) {
    BIO *pub = NULL;

    RSA *pubRsa = NULL;

    log_msg("PublicKeyPath [%s]", path);

    pub = BIO_new(BIO_s_file());

    /*	打开密钥文件 */
    BIO_read_filename(pub, path);
    pubRsa = PEM_read_bio_RSAPublicKey(pub, NULL, NULL, NULL);
    if (pubRsa == NULL) {
        err_msg("Read error");
        return NULL;
    }

    BIO_free_all(pub);

    return pubRsa;
}

int GetSign(unsigned char *hash, unsigned char *sign, RSA *pri) {
    unsigned int signLen;
    int ret;
    ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &signLen, pri);
    if (ret != 1)
        err_msg("RSA sign failed");
    return signLen;
}

int RSACheckSign(const char *contain, unsigned char *sign, int signLen, RSA *pub) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);

    SHA1_Update(&ctx, contain, 12);
    SHA1_Final(digest, &ctx);
    return RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, sign,
                      signLen,
                      pub);//==1
}


// Read contain of X509 pem
X509 *ReadX509File(const char *path) {
    X509 *x509 = X509_new();
    FILE *x509File = NULL;
    log_msg("X509 certificate [%s]", path);

    /* Open X509 File */
    BIO* bio_cert = BIO_new_file(path, "rb");
    PEM_read_bio_X509(bio_cert, &x509, NULL, NULL);

    /* Read contain */
    if (x509 == NULL)
        err_msg("Read X509 file failed\n");

    BIO_free_all(bio_cert);
    return x509;
}

void WriteResult(const char* path, bool result) {
    const char * tmp = CHECK_DIR;
    int len = strlen(tmp);
    char *finalPath = (char *) malloc(len + strlen(path));
    memset(finalPath, 0, len + strlen(path));
    strcat(finalPath, tmp);
    strcat(finalPath, path);
    FILE *fd = fopen(finalPath, "w");

    if (!fd)
        err_msg("Open %s failed", finalPath);
    
    int ret = fwrite(&result, 1, sizeof(result), fd);
    fclose(fd);
    if (ret != sizeof(result))
        err_msg("Write result error");
    log_msg("Sign result is %d, result path is %s", result, finalPath);
}

char *GetKeyFullPath(const char *pub) {
    const char *dir = PUB_KEY_DIR;
    char *path = (char *) malloc(strlen(dir) + strlen(pub));
    strcpy(path, dir);
    strcpy(path+strlen(dir), pub);
    log_msg("path is %s", path);
    return path;
}

char *GetX509FullPath(const char *pub) {
    const char *dir = X509_DIR;
    char *path = (char *) malloc(strlen(dir) + strlen(pub));
    strcpy(path, dir);
    strcpy(path+strlen(dir), pub);
    log_msg("path is %s", path);
    return path;
}

DIR *GetAllFiles(const char * path) {
    DIR             *dp;
    struct dirent   *dirp;

    if ((dp = opendir(path)) == NULL)
        err_quit("Can not open %s", path);

    return dp;
}

















