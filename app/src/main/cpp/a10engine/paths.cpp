#include "a10engine.h"

#include <string.h>
#include <sys/stat.h>

bool host_path_of(const char* p, char* out, size_t outsz) {
    if (!p) return false;
    if (g_rootfs[0] && strncmp(p, g_rootfs, strlen(g_rootfs)) == 0) {
        snprintf(out, outsz, "%s", p);
        return true;
    }
    return translate(p, out, outsz);
}

// magic (f_type) для пути: ищем в записи и в её ПРЕДКАХ по цепочке mount-точек
// ("/sys/fs/selinux" -> "/sys/fs" -> "/sys" -> "/"). Так значение не теряется,
// даже если сама точка в таблице неполна.
unsigned long magic_for_path(const char* path) {
    unsigned long best = 0;
    size_t bestlen = 0;
    if (!path) return 0;
    for (int i = 0; i < g_mount_count; i++) {
        unsigned long mg = magic_of(&g_mounts[i]);
        if (!mg) continue;
        if (!path_prefix(path, g_mounts[i].guest)) continue;
        size_t gl = strlen(g_mounts[i].guest);
        if (gl >= bestlen) {
            bestlen = gl;
            best = mg;
        }
    }
    return best;
}

// magic для записи и её предков.
unsigned long magic_for_entry(const Entry* e) {
    if (!e) return 0;
    unsigned long mg = magic_of(e);
    if (mg) return mg;
    char acc[256];
    snprintf(acc, sizeof(acc), "%s", e->guest);
    while (strlen(acc) > 1) {
        char* slash = strrchr(acc, '/');
        if (!slash || slash == acc) break;
        *slash = '\0';
        const Entry* p = lookup_guest(acc);
        if (p) {
            mg = magic_of(p);
            if (mg) return mg;
        }
    }
    return 0;
}

// ---------------------------------------------------------------- SIGSYS
// Хостовый seccomp телефона отвечает SIGSYS (SECCOMP_RET_TRAP) на некоторые syscall'ы
// (например pkey_alloc = 219 на aarch64). Обработчик, установленный в стабе, при
// execve СБРАСЫВАЕТСЯ (POSIX) — значит, ставим его здесь: preload грузится уже внутри
// процесса init'а, и обработчик живёт до следующего exec (где preload загрузится снова).
#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc 219
#endif
#ifndef __NR_pkey_free
#define __NR_pkey_free 220
#endif

bool writable_target(const char* pathname, char* host, size_t hostsz) {
    if (!pathname) return false;
    // Уже переведённый (host) путь гостя: пускаем как есть (внутри гостевой ФС).
    if (g_rootfs[0] && strncmp(pathname, g_rootfs, strlen(g_rootfs)) == 0) {
        snprintf(host, hostsz, "%s", pathname);
        return true;
    }
    const Entry* e = lookup_guest(pathname);
    if (!e) return false;
    if (!has_flag(e, "rw") && !has_flag(e, "chmod_ok")) return false;
    snprintf(host, hostsz, "%s%s", e->host, pathname + strlen(e->guest));
    return true;
}

