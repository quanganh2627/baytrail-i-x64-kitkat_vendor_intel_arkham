
#include <android_runtime/AndroidRuntime.h>
#include "JNIHelp.h"

namespace android {
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
    return symlink(file_old.string(), file_new.string());
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
