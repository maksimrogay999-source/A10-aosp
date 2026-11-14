// a10mounts.h — ОБЩИЙ разбор mount-таблицы гостя.
//
// ЕДИНЫЙ ИСТОЧНИК ПРАВДЫ ПО ПУТЯМ. Таблицу собирает стаб (stub_main.cpp) и кладёт
// в файл <rootfs>/a10_mounts; preload читает её по env A10_MOUNTS_FILE.
// Формат строки (пробелы — разделители):
//
//     <guest-путь> <host-путь> [флаги...]
//
// ХАРДКОДА ПУТЕЙ НЕТ НИГДЕ: ни в preload, ни в стабе. Все пути гостя (open, stat,
// fstatfs, chmod, connect, ...) переводятся по таблице. Поведение тоже задаётся
// флагами записи, а не «магическими» путями в коде.
//
// Флаги записи:
//   console        — open() отдаёт консольный pipe гостя (логи init)
//   selinux        — эмулированный selinuxfs: запись и ioctl считаются успехом
//   magic=0xHEX    — f_type, который отдаёт statfs/fstatfs для этого mount
//   fallback=путь  — host-путь, если основной недоступен (например /dev/null)
//   rw             — гость может создавать/удалять/менять файлы в этом mount
//   chmod_ok       — chmod/chown в этом mount эмулируются успехом (ядро запрещает)
//   logd           — путь сокета logd (перехват connect)
//   link=цель      — создать симлинк <host-путь> -> цель (устройства хоста)
//   lib64,lib      — этот mount даёт <host>/lib64 и <host>/lib в LD_LIBRARY_PATH
//   bin            — гостевой путь добавляется в PATH

#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace a10mount {

struct Entry {
    char guest[192];
    char host[512];
    char flags[256];
};

// Разбор строки таблицы: "<guest> <host> [flags...]".
inline void parse_line(const char* line, Entry* e) {
    e->guest[0] = 0;
    e->host[0] = 0;
    e->flags[0] = 0;
    if (!line) return;
    const char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t gi = 0;
    while (*p && *p != ' ' && *p != '\t' && gi + 1 < sizeof(e->guest)) e->guest[gi++] = *p++;
    e->guest[gi] = 0;
    while (*p == ' ' || *p == '\t') p++;
    size_t hi = 0;
    while (*p && *p != ' ' && *p != '\t' && hi + 1 < sizeof(e->host)) e->host[hi++] = *p++;
    e->host[hi] = 0;
    while (*p == ' ' || *p == '\t') p++;
    snprintf(e->flags, sizeof(e->flags), "%s", p);
}

// Есть ли флаг-ключ (без значения).
inline bool has_flag(const Entry* e, const char* key) {
    if (!e) return false;
    char buf[sizeof(e->flags)];
    snprintf(buf, sizeof(buf), "%s", e->flags);
    const size_t kl = strlen(key);
    char* save = nullptr;
    for (char* t = strtok_r(buf, " \t", &save); t; t = strtok_r(nullptr, " \t", &save)) {
        if (strncmp(t, key, kl) == 0 && t[kl] == 0) return true;
    }
    return false;
}

// Есть ли ключ флага (как "key" так и "key=...").
inline bool flag_present(const Entry* e, const char* key) {
    if (!e) return false;
    char buf[sizeof(e->flags)];
    snprintf(buf, sizeof(buf), "%s", e->flags);
    const size_t kl = strlen(key);
    char* save = nullptr;
    for (char* t = strtok_r(buf, " \t", &save); t; t = strtok_r(nullptr, " \t", &save)) {
        if (strncmp(t, key, kl) == 0 && (t[kl] == 0 || t[kl] == '=')) return true;
    }
    return false;
}

// Значение флага "key=value".
inline bool get_flag(const Entry* e, const char* key, char* out, size_t outsz) {
    if (!e || !out || outsz == 0) return false;
    out[0] = 0;
    char buf[sizeof(e->flags)];
    snprintf(buf, sizeof(buf), "%s", e->flags);
    const size_t kl = strlen(key);
    char* save = nullptr;
    for (char* t = strtok_r(buf, " \t", &save); t; t = strtok_r(nullptr, " \t", &save)) {
        if (strncmp(t, key, kl) == 0 && t[kl] == '=') {
            snprintf(out, outsz, "%s", t + kl + 1);
            return true;
        }
    }
    return false;
}

// f_type для mount'а (0 — если не задан).
inline unsigned long magic_of(const Entry* e) {
    char v[64];
    if (!get_flag(e, "magic", v, sizeof(v))) return 0;
    return strtoul(v, nullptr, 0);
}

// Совпадение по границе компонента пути: "/system" подходит для "/system/x",
// но не для "/systemfoo".
inline bool path_prefix(const char* path, const char* prefix) {
    const size_t n = strlen(prefix);
    if (n == 0) return false;
    if (strncmp(path, prefix, n) != 0) return false;
    return path[n] == 0 || path[n] == '/';
}

}  // namespace a10mount
