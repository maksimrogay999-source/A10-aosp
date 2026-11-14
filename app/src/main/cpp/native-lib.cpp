#include <jni.h>
#include <string>
#include <android/log.h>
#include "loader.h"
#include "ptrace_intercept.h"
#include "image_extractor.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_emulA10_MainActivity_nativeHello(
        JNIEnv* env, jobject /* this */) {
    return env->NewStringUTF("A10 Native Emulator Engine v1.0");
}

extern "C" JNIEXPORT void JNICALL
Java_com_android_emulA10_MainActivity_nativeLog(
        JNIEnv* env, jobject /* this */, jstring message) {
    const char* msg = env->GetStringUTFChars(message, nullptr);
    __android_log_print(ANDROID_LOG_INFO, "A10_Emulator", "%s", msg);
    env->ReleaseStringUTFChars(message, msg);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_emulA10_MainActivity_loaderLastError(
        JNIEnv* env, jobject /* this */) {
    return env->NewStringUTF(loader_last_error().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_emulA10_MainActivity_nativeExtractSystem(
        JNIEnv* env, jobject /* this */, jstring systemImgPath, jstring outDir) {
    const char* img = env->GetStringUTFChars(systemImgPath, nullptr);
    const char* out = env->GetStringUTFChars(outDir, nullptr);
    std::string err;
    bool ok = image_extract_system(img, out, err);
    env->ReleaseStringUTFChars(systemImgPath, img);
    env->ReleaseStringUTFChars(outDir, out);
    if (ok) return env->NewStringUTF("ok");
    return env->NewStringUTF(err.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_android_emulA10_MainActivity_loaderInit(
        JNIEnv* env, jobject /* this */, jstring aospPath) {
    const char* path = env->GetStringUTFChars(aospPath, nullptr);
    bool ok = loader_init(path);
    env->ReleaseStringUTFChars(aospPath, path);
    return ok ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_android_emulA10_MainActivity_loaderInitWithNativeDir(
        JNIEnv* env, jobject /* this */, jstring aospPath, jstring nativeLibDir) {
    const char* path = env->GetStringUTFChars(aospPath, nullptr);
    const char* nld = env->GetStringUTFChars(nativeLibDir, nullptr);
    bool ok = loader_init(path, nld ? nld : "");
    env->ReleaseStringUTFChars(aospPath, path);
    env->ReleaseStringUTFChars(nativeLibDir, nld);
    return ok ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_android_emulA10_MainActivity_loaderStartInit(
        JNIEnv* env, jobject /* this */) {
    return loader_start_init();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_android_emulA10_MainActivity_loaderGuestAlive(
        JNIEnv* env, jobject /* this */) {
    return loader_guest_alive() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_emulA10_MainActivity_loaderStatus(
        JNIEnv* env, jobject /* this */) {
    return env->NewStringUTF(loader_status().c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_android_emulA10_MainActivity_loaderShutdown(
        JNIEnv* env, jobject /* this */) {
    loader_shutdown();
}