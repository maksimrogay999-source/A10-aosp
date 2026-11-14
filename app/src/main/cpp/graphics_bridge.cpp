#include "graphics_bridge.h"
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <dlfcn.h>

#define TAG "A10_Graphics"

static EGLDisplay g_display = EGL_NO_DISPLAY;
static EGLContext g_context = EGL_NO_CONTEXT;
static EGLSurface g_surface = EGL_NO_SURFACE;
static bool g_initialized = false;

// Проброс OpenGL ES вызовов
void* graphics_bridge_get_egl_display() {
    return (void*)g_display;
}

void* graphics_bridge_get_egl_context() {
    return (void*)g_context;
}

void* graphics_bridge_get_egl_surface() {
    return (void*)g_surface;
}

bool graphics_bridge_init() {
    if (g_initialized) return true;
    g_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (g_display == EGL_NO_DISPLAY) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get EGL display");
        return false;
    }
    EGLint major, minor;
    if (!eglInitialize(g_display, &major, &minor)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to initialize EGL");
        return false;
    }
    
    // Конфигурация EGL
    EGLint config_attribs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8,
        EGL_DEPTH_SIZE, 16,
        EGL_STENCIL_SIZE, 8,
        EGL_NONE
    };
    
    EGLConfig config;
    EGLint num_configs;
    if (!eglChooseConfig(g_display, config_attribs, &config, 1, &num_configs)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to choose EGL config");
        return false;
    }
    
    // Контекст
    EGLint context_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };
    g_context = eglCreateContext(g_display, config, EGL_NO_CONTEXT, context_attribs);
    if (g_context == EGL_NO_CONTEXT) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to create EGL context");
        return false;
    }
    
    g_initialized = true;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Graphics bridge initialized (EGL %d.%d)", major, minor);
    return true;
}

void graphics_bridge_shutdown() {
    if (!g_initialized) return;
    if (g_display != EGL_NO_DISPLAY) {
        eglMakeCurrent(g_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        if (g_context != EGL_NO_CONTEXT) {
            eglDestroyContext(g_display, g_context);
            g_context = EGL_NO_CONTEXT;
        }
        eglTerminate(g_display);
        g_display = EGL_NO_DISPLAY;
    }
    g_initialized = false;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Graphics bridge shutdown");
}