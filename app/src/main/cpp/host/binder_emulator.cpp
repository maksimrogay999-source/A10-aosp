#include <jni.h>
#include "binder_emulator.h"
#include <android/log.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/android/binder.h>

#define TAG "A10_Binder"
#define BINDER_DEVICE "/dev/binder"

static void* g_context = nullptr;
static pthread_t g_binder_thread;
static bool g_initialized = false;
static int g_binder_fd = -1;

// JNI-метод для логирования в Kotlin
extern "C" JNIEXPORT void JNICALL
Java_com_android_emulA10_MainActivity_nativeLog(JNIEnv* env, jobject /* this */, jstring message);

// Обработка транзакции
static void handle_transaction(binder_transaction_data* txn) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Binder transaction: code=%d, target=%d, data_size=%llu, offsets_size=%llu", 
             txn->code, txn->target.handle, txn->data_size, txn->offsets_size);
    
    // Логируем в Android log
    __android_log_print(ANDROID_LOG_INFO, TAG, "%s", log_msg);
    
    // Логируем в Kotlin
    // nativeLog(nullptr, log_msg);
    
    // Обрабатываем транзакцию в зависимости от кода
    switch (txn->code) {
        case 1: // SERVICE_START
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service start transaction");
            break;
        case 2: // SERVICE_STOP
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service stop transaction");
            break;
        case 3: // SERVICE_BIND
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service bind transaction");
            break;
        case 4: // SERVICE_UNBIND
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service unbind transaction");
            break;
        case 5: // SERVICE_CALL
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service call transaction");
            break;
        case 6: // SERVICE_REPLY
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service reply transaction");
            break;
        case 7: // SERVICE_DUMP
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service dump transaction");
            break;
        case 8: // SERVICE_LIST
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service list transaction");
            break;
        case 9: // SERVICE_GET
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service get transaction");
            break;
        case 10: // SERVICE_ADD
            __android_log_print(ANDROID_LOG_INFO, TAG, "Service add transaction");
            break;
        default:
            snprintf(log_msg, sizeof(log_msg), "Unknown transaction: code=%d, target=%d, data_size=%llu, offsets_size=%llu", 
                     txn->code, txn->target.handle, txn->data_size, txn->offsets_size);
            __android_log_print(ANDROID_LOG_INFO, TAG, "%s", log_msg);
            break;
    }
}

// Виртуальный binder: транзакции обрабатываются при перехвате ioctl в ptrace
static void* binder_thread_func(void* arg) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Virtual binder emulator thread started");
    while (g_initialized) {
        sleep(1);
    }
    return nullptr;
}

bool binder_emulator_init() {
    if (g_initialized) return true;
    
    // Виртуальный binder: не открываем реальное /dev/binder, эмулируем через перехват syscalls
    g_binder_fd = -1;
    g_context = malloc(1024);
    if (!g_context) {
        return false;
    }
    
    g_initialized = true;
    pthread_create(&g_binder_thread, nullptr, binder_thread_func, nullptr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Virtual binder emulator initialized");
    return true;
}

void binder_emulator_shutdown() {
    if (!g_initialized) return;
    g_initialized = false;
    pthread_join(g_binder_thread, nullptr);
    free(g_context);
    g_context = nullptr;
    if (g_binder_fd != -1) {
        close(g_binder_fd);
        g_binder_fd = -1;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "Binder emulator shutdown");
}

void* binder_emulator_get_context() {
    return g_context;
}

int binder_emulator_get_fd() {
    return g_binder_fd;
}