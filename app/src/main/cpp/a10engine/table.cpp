#include "a10engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

void load_mount_table(const char* path) {
    if (!path || !*path) return;
    // Читаем таблицу raw-сисколлами: перехваченный нами fopen() сюда не годится.
    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char buf[8192];
    ssize_t got = 0;
    char line[900];
    size_t used = 0;
    while (g_mount_count < (int)(sizeof(g_mounts) / sizeof(g_mounts[0])) &&
           (got = (ssize_t)syscall(__NR_read, fd, buf, sizeof(buf) - 1)) > 0) {
        buf[got] = 0;
        size_t i = 0;
        while (i < (size_t)got) {
            if (buf[i] == '\n') {
                line[used] = 0;
                size_t len = used;
                while (len && (line[len - 1] == '\r')) line[--len] = '\0';
                if (len && line[0] != '#') {
                    Entry e {};
                    parse_line(line, &e);
                    if (e.guest[0] && e.host[0]) g_mounts[g_mount_count++] = e;
                }
                used = 0;
            } else if (used < sizeof(line) - 1) {
                line[used++] = buf[i];
            }
            i++;
        }
    }
    syscall(__NR_close, fd);
    (void)used;
}

// Самая длинная подходящая запись таблицы (префикс по границе компонента).
const Entry* lookup_mount(const char* path) {
    if (!path) return nullptr;
    const Entry* best = nullptr;
    size_t bestlen = 0;
    for (int i = 0; i < g_mount_count; i++) {
        if (!path_prefix(path, g_mounts[i].guest)) continue;
        size_t gl = strlen(g_mounts[i].guest);
        if (gl > bestlen) {
            bestlen = gl;
            best = &g_mounts[i];
        }
    }
    return best;
}

// Запись таблицы для пути ГОСТЯ. Для УЖЕ переведённого (host) пути возвращает
// nullptr: такой путь повторно не переводится. Иначе корень гостя (он же /data/...)
// налезал бы сам на себя: "/data/data/…/aosp/system/…" -> "<rootfs>/data/data/…".
const Entry* lookup_guest(const char* path) {
    if (!path) return nullptr;
    if (g_rootfs[0] && strncmp(path, g_rootfs, strlen(g_rootfs)) == 0) return nullptr;
    return lookup_mount(path);
}

// Перевод гостевого пути в реальный по таблице. true — путь переведён.
bool translate(const char* p, char* out, size_t outsz) {
    const Entry* e = lookup_guest(p);
    if (!e) return false;
    snprintf(out, outsz, "%s%s", e->host, p + strlen(e->guest));
    return true;
}

// Запись таблицы по точному guest-пути.
const Entry* table_find_exact(const char* guest) {
    for (int i = 0; i < g_mount_count; i++) {
        if (strcmp(g_mounts[i].guest, guest) == 0) return &g_mounts[i];
    }
    return nullptr;
}

// Добавить/обновить запись таблицы.
void table_set(const char* guest, const char* host, const char* flags) {
    for (int i = 0; i < g_mount_count; i++) {
        if (strcmp(g_mounts[i].guest, guest) == 0) {
            snprintf(g_mounts[i].host, sizeof(g_mounts[i].host), "%s", host);
            snprintf(g_mounts[i].flags, sizeof(g_mounts[i].flags), "%s", flags ? flags : "");
            return;
        }
    }
    if (g_mount_count >= (int)(sizeof(g_mounts) / sizeof(g_mounts[0]))) return;
    Entry& e = g_mounts[g_mount_count++];
    snprintf(e.guest, sizeof(e.guest), "%s", guest);
    snprintf(e.host, sizeof(e.host), "%s", host);
    snprintf(e.flags, sizeof(e.flags), "%s", flags ? flags : "");
}

// Сохранить таблицу в файл (чтобы её видела и вторая стадия init'а).
void table_save(void) {
    if (!g_mounts_file[0]) return;
    int fd = (int)syscall(__NR_openat, AT_FDCWD, g_mounts_file,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    char buf[1024];
    for (int i = 0; i < g_mount_count; i++) {
        int n = snprintf(buf, sizeof(buf), "%s %s %s\n", g_mounts[i].guest, g_mounts[i].host,
                         g_mounts[i].flags);
        if (n > 0) syscall(__NR_write, fd, buf, (size_t)n);
    }
    syscall(__NR_close, fd);
}

// Корень гостя — host-путь записи "/" (из таблицы, без хардкода).
bool guest_root(char* out, size_t outsz) {
    const Entry* e = table_find_exact("/");
    if (!e) return false;
    snprintf(out, outsz, "%s", e->host);
    return true;
}

// Перевод пути гостя в host-путь. УЖЕ ПЕРЕВЕДЁННЫЙ (host) путь не трогаем:
// иначе двойной перевод (fopen -> bionic -> наш __openat) ломает доступ —
// файл существует, но второй перевод даёт ENOENT.
