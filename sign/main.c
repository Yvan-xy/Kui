#include <sign32.h>
#include <sign64.h>

int main(int argc, char *argv[]) {
    DIR *dp;
    char * pubPath;
    struct dirent *dirp;
    bool result = false;
    int type = IsELF32(argv[1]);
    if (type) {
        dp = GetAllFiles(PUB_KEY_DIR);
        while ((dirp = readdir(dp)) != NULL) {
            if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                continue;

            pubPath = GetKeyFullPath(dirp->d_name);
            result = CheckSign32(pubPath,argv[1]);
            free(pubPath);
            WriteResult(argv[2], result);
            if (result){
                return 0;
            } else {
            }
        }
        dp = GetAllFiles(X509_DIR);
        while ((dirp = readdir(dp)) != NULL) {
             if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                continue;

            pubPath = GetX509FullPath(dirp->d_name);
            result = X509CheckSign32(pubPath,argv[1]);
            free(pubPath);
            if (result){
                WriteResult(argv[2], result);
                return 0;
            }                           
        }
        log_msg("Sign check not pass!");
        return 0;
    } else {
        type = IsELF64(argv[1]);
        if (type){

            dp = GetAllFiles(PUB_KEY_DIR);
            while ((dirp = readdir(dp)) != NULL) {
                if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                    continue;

                pubPath = GetKeyFullPath(dirp->d_name);
                result = CheckSign64(pubPath,argv[1]);
                free(pubPath);
                WriteResult(argv[2], result);
                if (result){
                    return 0;
                } else {
                }
            }
            dp = GetAllFiles(X509_DIR);
            while ((dirp = readdir(dp)) != NULL) {
                 if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                    continue;

                pubPath = GetX509FullPath(dirp->d_name);
                result = X509CheckSign64(pubPath,argv[1]);
                free(pubPath);
                if (result){
                    WriteResult(argv[2], result);
                    return 0;
                }                           
            }
            log_msg("Sign check not pass!");
            return 0;
        } else {
            log_msg("%s is not ELF file!", argv[1]);
            return 0;
        }
    }    
    return 0;
}
