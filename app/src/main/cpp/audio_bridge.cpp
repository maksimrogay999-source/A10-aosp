#include "audio_bridge.h"
#include <android/log.h>
#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>

#define TAG "A10_Audio"

static SLObjectItf g_engine = nullptr;
static SLEngineItf g_engineItf = nullptr;
static bool g_initialized = false;

bool audio_bridge_init() {
    if (g_initialized) return true;
    SLresult res = slCreateEngine(&g_engine, 0, nullptr, 0, nullptr, nullptr);
    if (res != SL_RESULT_SUCCESS) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to create OpenSL ES engine");
        return false;
    }
    (*g_engine)->Realize(g_engine, SL_BOOLEAN_FALSE);
    (*g_engine)->GetInterface(g_engine, SL_IID_ENGINE, &g_engineItf);
    g_initialized = true;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Audio bridge initialized (OpenSL ES)");
    return true;
}

void audio_bridge_shutdown() {
    if (!g_initialized) return;
    if (g_engine) {
        (*g_engine)->Destroy(g_engine);
        g_engine = nullptr;
        g_engineItf = nullptr;
    }
    g_initialized = false;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Audio bridge shutdown");
}

void* audio_bridge_get_context() {
    return (void*)g_engineItf;
}