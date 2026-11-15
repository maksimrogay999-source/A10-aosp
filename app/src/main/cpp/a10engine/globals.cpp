// globals.cpp — общее состояние движка эмуляции гостя.
#include "a10engine.h"

int g_console_fd = -1;
char g_rootfs[512];
char g_mounts_file[512];

// Сохраняем окружение гостя: init первой стадии делает clearenv() — без восстановления
// LD_PRELOAD вторая стадия (selinux_setup) стартовала БЕЗ нашей эмуляции (лог 14:55).
char g_preload[1024];
char g_console_env[64];
char g_android_root[512];
char g_ld_library_path[1024];
char g_path[512];

// Таблица гостя (заполняется из файла a10_mounts).
a10mount::Entry g_mounts[128];
int g_mount_count = 0;

// Трекинг открытых fd гостя (для эмуляции /proc/self/fd, устройств и виртуальных файлов).
int g_track_fd[A10_TRACK_MAX];
int g_track_mount[A10_TRACK_MAX];
int g_track_kind[A10_TRACK_MAX];
char g_track_path[A10_TRACK_MAX][A10_PATH_MAX];
int g_track_proc[A10_TRACK_MAX];
char* g_virt_data[A10_TRACK_MAX];
size_t g_virt_len[A10_TRACK_MAX];
size_t g_virt_pos[A10_TRACK_MAX];

// Контексты гостя (список и правила file_contexts).
char g_ctx_cache[65536];
int g_ctx_count = 0;
void* g_fc_rules = nullptr;
int g_fc_count = 0;

int g_trace_count = 0;
