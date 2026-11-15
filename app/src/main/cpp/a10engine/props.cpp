// props.cpp — свойства гостя.
//
// Свойства Android хранятся в ОБЩЕЙ памяти (shared memory) — она была бы памятью
// ТЕЛЕФОНА (shared!). Поэтому свойства гостя живут в ЕГО файле в гостевой ФС:
// "/dev/__properties__/guest_properties" (key=value). Общая область хоста не
// используется совсем.
#include "a10engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* guest_props_path() {
    static char p[900];
    if (!p[0]) {
        char gp[256];
        snprintf(gp, sizeof(gp), "/dev/__properties__/guest_properties");
        if (!host_path_of(gp, p, sizeof(p))) p[0] = '\0';
    }
    return p[0] ? p : nullptr;
}

// Прочитать свойство гостя из его файла.
static bool guest_props_get(const char* name, char* value) {
    const char* p = guest_props_path();
    if (!p || !name) return false;
    FILE* f = fopen(p, "r");
    if (!f) return false;
    char line[1024];
    size_t nl = strlen(name);
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nl) != 0 || line[nl] != '=') continue;
        char* v = line + nl + 1;
        size_t len = strlen(v);
        while (len && (v[len - 1] == '\n' || v[len - 1] == '\r')) v[--len] = 0;
        if (value) snprintf(value, 128, "%s", v);
        found = true;
        break;
    }
    fclose(f);
    return found;
}

// Записать свойство гостя в его файл (перезапись существующего).
static void guest_props_set(const char* name, const char* value) {
    const char* p = guest_props_path();
    if (!p || !name) return;
    char dir[900];
    snprintf(dir, sizeof(dir), "%s", p);
    char* slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(dir);
    }
    FILE* f = fopen(p, "r");
    if (f) {
        char line[1024];
        size_t nl = strlen(name);
        char tmp[900];
        snprintf(tmp, sizeof(tmp), "%s.new", p);
        FILE* out = fopen(tmp, "w");
        if (out) {
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, name, nl) == 0 && line[nl] == '=') continue;
                fputs(line, out);
            }
            fprintf(out, "%s=%s\n", name, value ? value : "");
            fclose(out);
            rename(tmp, p);
        }
        fclose(f);
        return;
    }
    FILE* out = fopen(p, "w");
    if (!out) return;
    fprintf(out, "%s=%s\n", name, value ? value : "");
    fclose(out);
}

// Инициализация области свойств: у гостя своя (файл), общая область хоста не трогаем.
extern "C" int __system_property_area_init() {
    plog("A10_Preload: __system_property_area_init -> ok (свойства гостя — свой файл)");
    return 0;
}

// Свойства гостя: find всегда "не найдено" -> init идёт по пути add (в наш файл).
extern "C" void* __system_property_find(const char* name) {
    (void)name;
    return nullptr;
}

extern "C" int __system_property_add(const char* name, size_t name_len, const char* value,
                                     size_t valuelen) {
    (void)name_len;
    (void)valuelen;
    if (!name) return -1;
    guest_props_set(name, value ? value : "");
    return 0;
}

extern "C" int __system_property_update(void* pi, const char* value, size_t valuelen) {
    (void)pi;
    (void)valuelen;
    return 0;
}

// Гость спрашивает свойства через bionic — отвечаем ТОЛЬКО из файла гостя.
// Общая область свойств телефона не читается: никакого shared с хостом.
extern "C" int __system_property_get(const char* name, char* value) {
    if (value) value[0] = '\0';
    if (name && guest_props_get(name, value)) return (int)strlen(value);
    if (name && strcmp(name, "ro.boot.selinux") == 0) {
        if (value) strcpy(value, "0");   // 1 = SELinux включен
        return 0;
    }
    return 0;
}
