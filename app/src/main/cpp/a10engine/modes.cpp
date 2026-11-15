// modes.cpp — реестр ПРАВ файлов гостя.
//
// Зачем: гость работает как root, но мы — обычное приложение. Чтобы гость мог писать в
// свои файлы, мы расширяем реальные права (0664). Но тогда гость в stat() увидит
// «неправильные» права (и, например, propertyinfoparser откажется грузить property_info:
// он требует, чтобы файл НЕ был доступен на запись группе/остальным).
//
// Поэтому программа СЛЕДИТ за исходными правами каждого файла, который мы расширили:
//   * при расширении — запоминаем исходный режим в реестре (<rootfs>/a10_modes);
//   * при stat() — гостю показываем ИСХОДНЫЙ режим (тот, что он сам задал), а не
//     расширенный; реальный файл остаётся записываемым.
//
// Реестр живёт в гостевой ФС (файл a10_modes рядом с a10_mounts) и переживает перезапуск
// приложения — иначе после перезапуска «исходные» права были бы забыты.
#include "a10engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define A10_MODES_MAX 512

struct A10Mode {
    char path[256];
    unsigned mode;
};

static A10Mode g_modes[A10_MODES_MAX];
static int g_modes_count = 0;
char g_modes_file[512] = {0};

// Загрузить реестр из файла гостя (путь — из A10_MODES_FILE).
void modes_init(const char* file) {
    if (!file || !file[0]) return;
    snprintf(g_modes_file, sizeof(g_modes_file), "%s", file);
    FILE* f = fopen(g_modes_file, "r");
    if (!f) return;
    char line[400];
    while (fgets(line, sizeof(line), f) && g_modes_count < A10_MODES_MAX) {
        char* sp = strrchr(line, ' ');
        if (!sp) continue;
        *sp = '\0';
        unsigned m = (unsigned)strtoul(sp + 1, nullptr, 8);
        snprintf(g_modes[g_modes_count].path, sizeof(g_modes[0].path), "%s", line);
        g_modes[g_modes_count].mode = m;
        g_modes_count++;
    }
    fclose(f);
    plog("A10_Preload: реестр прав гостя загружен: %d записей", g_modes_count);
}

// Сохранить реестр в файл гостя.
void modes_save(void) {
    if (!g_modes_file[0]) return;
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.new", g_modes_file);
    FILE* f = fopen(tmp, "w");
    if (!f) return;
    for (int i = 0; i < g_modes_count; i++) {
        fprintf(f, "%s %o\n", g_modes[i].path, g_modes[i].mode);
    }
    fclose(f);
    rename(tmp, g_modes_file);
}

// Запомнить ИСХОДНЫЕ права файла (если ещё не запомнены).
void modes_record(const char* path, unsigned mode) {
    if (!path || !path[0] || !g_modes_file[0]) return;
    for (int i = 0; i < g_modes_count; i++) {
        if (strcmp(g_modes[i].path, path) == 0) return;   // первый (исходный) режим важен
    }
    if (g_modes_count >= A10_MODES_MAX) return;
    snprintf(g_modes[g_modes_count].path, sizeof(g_modes[0].path), "%s", path);
    g_modes[g_modes_count].mode = mode & 07777;
    g_modes_count++;
    modes_save();
}

// Исходные права файла (если знаем) — иначе false.
bool modes_lookup(const char* path, unsigned* mode) {
    if (!path || !path[0]) return false;
    for (int i = 0; i < g_modes_count; i++) {
        if (strcmp(g_modes[i].path, path) == 0) {
            if (mode) *mode = g_modes[i].mode;
            return true;
        }
    }
    return false;
}
