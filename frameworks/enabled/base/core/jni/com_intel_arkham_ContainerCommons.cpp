#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <android_runtime/AndroidRuntime.h>
#include "JNIHelp.h"

namespace android {

static int myCopyFile(const char *from, const char *to) {
    int fd_to = -1, fd_from = -1;
    char buf[4096];
    ssize_t nread;
    int saved_errno;
    mode_t old_mask;

    old_mask = umask(022);

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0) {
        goto in_error;
    }

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0) {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR) {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0) {
        if (close(fd_to) < 0) {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);
        
        umask(old_mask);
        /* Success! */
        return 0;
    }

in_error:
out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    umask(old_mask);
    return -1;
}


// ARKHAM-226 - Add support for creating symbolic links
jint com_intel_arkham_ContainerCommons_createSymLink(JNIEnv* env, jobject clazz,
                                        jstring oldpath, jstring newpath)
{
    const jchar* str_old = env->GetStringCritical(oldpath, 0);
    const jchar* str_new = env->GetStringCritical(newpath, 0);
    String8 file_old;
    String8 file_new;
    if (str_old && str_new) {
        file_old = String8(str_old, env->GetStringLength(oldpath));
        env->ReleaseStringCritical(oldpath, str_old);
        file_new = String8(str_new, env->GetStringLength(newpath));
        env->ReleaseStringCritical(newpath, str_new);
    }
    if (file_new.size() <= 0 || file_old.size() <= 0) {
        return ENOENT;
    }
    
    //return symlink(file_old.string(), file_new.string());
    return myCopyFile(file_old.string(), file_new.string());
}

static const JNINativeMethod methods[] = {
    {"createSymLink",   "(Ljava/lang/String;Ljava/lang/String;)I",
            (void*)com_intel_arkham_ContainerCommons_createSymLink},
};

static const char* const kFileUtilsPathName = "com/intel/arkham/ContainerCommons";

int register_com_intel_arkham_ContainerCommons(JNIEnv* env)
{
    return AndroidRuntime::registerNativeMethods(
        env, kFileUtilsPathName,
        methods, NELEM(methods));
}

}
