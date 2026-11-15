#include "a10engine.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// ---------------------------------------------------------------- контексты гостя
// Правила file_contexts гостя: из его ФС ("/system/etc/selinux/plat_file_contexts").
// Путь и контекст разделены ПРОБЕЛОМ или ТАБУЛИАЦИЕЙ (в AOSP — табами).
struct GuestFcRule {
    char path[256];
    char ctx[192];
};

void load_guest_file_contexts() {
    if (g_fc_rules) return;
    char host[900];
    if (!host_path_of("/system/etc/selinux/plat_file_contexts", host, sizeof(host))) return;
    FILE* f = fopen(host, "r");
    if (!f) return;
    int cap = 2048;
    g_fc_rules = calloc((size_t)cap, sizeof(GuestFcRule));
    if (!g_fc_rules) {
        fclose(f);
        return;
    }
    GuestFcRule* rules = (GuestFcRule*)g_fc_rules;
    char line[512];
    while (fgets(line, sizeof(line), f) && g_fc_count < cap) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || !*p) continue;
        char* sep = p;
        while (*sep && *sep != ' ' && *sep != '\t') sep++;
        if (!*sep) continue;
        *sep = '\0';
        char* ctx = sep + 1;
        while (*ctx == ' ' || *ctx == '\t') ctx++;
        char* e = strpbrk(ctx, " \t\r\n");
        if (e) *e = '\0';
        if (!ctx[0]) continue;
        char rp[256];
        snprintf(rp, sizeof(rp), "%s", p);
        // Отрезаем регулярное выражение правила (оставляем литеральный префикс).
        for (size_t k = 0; k < strlen(rp); k++) {
            char c = rp[k];
            if (c == '(' || c == '[' || c == '*' || c == '?' || c == '\\' || c == '$') {
                rp[k] = '\0';
                break;
            }
        }
        if (!rp[0]) continue;
        snprintf(rules[g_fc_count].path, sizeof(rules[0].path), "%s", rp);
        snprintf(rules[g_fc_count].ctx, sizeof(rules[0].ctx), "%s", ctx);
        g_fc_count++;
    }
    fclose(f);
    plog("A10_Preload: правила file_contexts гостя загружены: %d", g_fc_count);
}

// Контекст гостя для пути: правило с наибольшим совпадающим префиксом.
const char* guest_file_context(const char* path) {
    load_guest_file_contexts();
    if (!g_fc_rules || !path) return nullptr;
    GuestFcRule* rules = (GuestFcRule*)g_fc_rules;
    const char* best = nullptr;
    size_t bestlen = 0;
    for (int i = 0; i < g_fc_count; i++) {
        const char* rp = rules[i].path;
        size_t rl = strlen(rp);
        if (rl == 0) continue;
        if (strncmp(path, rp, rl) != 0) continue;
        if (path[rl] != '\0' && path[rl] != '/') continue;
        if (rl >= bestlen) {
            bestlen = rl;
            best = rules[i].ctx;
        }
    }
    return best;
}

// Есть ли контекст в списке контекстов гостя.
bool guest_context_exists(const char* ctx) {
    ensure_ctx_cache();
    if (!ctx || !g_ctx_cache[0]) return false;
    const char* p = g_ctx_cache;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len == strlen(ctx) && strncmp(p, ctx, len) == 0) return true;
        if (!nl) break;
        p = nl + 1;
    }
    return guest_file_context(ctx) != nullptr;
}

// ---------------------------------------------------------------- перехваты гостевой libselinux
// Гость грузит libselinux из rootfs (гостевая), поэтому её символы перехватываются.
// Без перехвата libselinux спрашивает контексты у ЯДРА ХОСТА (политика AOSP-16, контекста
// гостя там нет) -> проверки не проходят -> restorecon/property area падают.
extern "C" int sepol_context_to_sid(void* policy, const char* context, uint32_t* sid) {
    (void)policy;
    int s = guest_sid_for(context);
    plog("A10_Preload: sepol_context_to_sid(%s) -> %d", context ? context : "?", s);
    if (sid) *sid = (uint32_t)s;
    return 0;
}

extern "C" int sepol_check_context(void* policy, const char* context) {
    (void)policy;
    const char* c = guest_file_context(context);
    plog("A10_Preload: sepol_check_context(%s) -> %s", context ? context : "?", c ? "ok" : "нет");
    return c ? 0 : -1;
}

// Проверка доступа SELinux у гостя. Политика гостя — наша (гостевая, собранная его же
// secilc), но ЯДРО хоста не знает гостевых классов (в частности property_service), поэтому
// гостевая libselinux получает "Unknown class property_service" и отказывает в установке
// свойств ("Init cannot set 'ro.bootmode' ...: SELinux permission check failed").
// Решение принимаем сами: доступ разрешаем.
extern "C" int selinux_check_access(const char* scon, const char* tcon, const char* tclass,
                                    const char* perm, void* audit_data) {
    (void)audit_data;
    plog("A10_Preload: selinux_check_access(%s, %s, %s, %s) -> разрешено",
         scon ? scon : "?", tcon ? tcon : "?", tclass ? tclass : "?", perm ? perm : "?");
    return 0;
}

extern "C" int selinux_check_context(const char* context) {
    bool found = guest_context_exists(context);
    plog("A10_Preload: selinux_check_context(%s) -> %s", context ? context : "?",
         found ? "ok" : "нет");
    if (!found) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

extern "C" int security_context_to_sid(const char* ctx, uint32_t* sid) {
    int s = guest_sid_for(ctx);
    plog("A10_Preload: security_context_to_sid(%s) -> %d", ctx ? ctx : "?", s);
    if (sid) *sid = (uint32_t)s;
    return 0;
}

// lgetfilecon: контекст гостя считаем сами (по правилам file_contexts гостя).
extern "C" int lgetfilecon(const char* path, char** con) {
    const char* ctx = guest_file_context(path);
    plog("A10_Preload: lgetfilecon(%s) -> %s", path ? path : "?", ctx ? ctx : "(нет правила)");
    if (!ctx) {
        errno = ENODATA;
        return -1;
    }
    if (con) {
        char* dup = strdup(ctx);
        if (!dup) {
            errno = ENOMEM;
            return -1;
        }
        *con = dup;
    }
    return 0;
}

// xattr-контекст гостя (security.selinux) — по правилам гостя, не по хосту.
static ssize_t guest_selinux_xattr(const char* path, const char* name, void* value, size_t size) {
    if (!name || strcmp(name, "security.selinux") != 0) return -2;   // не наш xattr
    const char* ctx = guest_file_context(path);
    if (!ctx) {
        errno = ENODATA;
        return -1;
    }
    size_t len = strlen(ctx) + 1;
    if (len > size) {
        errno = ERANGE;
        return -1;
    }
    if (value) memcpy(value, ctx, len);
    return (ssize_t)len;
}

extern "C" ssize_t lgetxattr(const char* path, const char* name, void* value, size_t size) {
    static ssize_t (*real)(const char*, const char*, void*, size_t) = nullptr;
    if (!real) real = (ssize_t (*)(const char*, const char*, void*, size_t))dlsym(RTLD_NEXT, "lgetxattr");
    ssize_t r = guest_selinux_xattr(path, name, value, size);
    if (r != -2) return r;
    if (!real) { errno = ENOSYS; return -1; }
    return real(path, name, value, size);
}

extern "C" ssize_t fgetxattr(int fd, const char* name, void* value, size_t size) {
    static ssize_t (*real)(int, const char*, void*, size_t) = nullptr;
    if (!real) real = (ssize_t (*)(int, const char*, void*, size_t))dlsym(RTLD_NEXT, "fgetxattr");
    const char* p = track_path_of(fd);
    ssize_t r = guest_selinux_xattr(p, name, value, size);
    if (r != -2) return r;
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, name, value, size);
}

const char* guest_ctx_for_sid(int sid) {
    ensure_ctx_cache();
    const char* p = g_ctx_cache;
    int cur = 1;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (cur == sid) {
            static char buf[512];
            size_t n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
            memcpy(buf, p, n);
            buf[n] = 0;
            return buf;
        }
        cur++;
        if (!nl) break;
        p = nl + 1;
    }
    return "u:object_r:system_prop:s0";
}

// Кэш списка контекстов гостя + собственное SID-пространство (контекст <-> SID).
void ensure_ctx_cache() {
    if (g_ctx_count) return;
    g_ctx_count = (int)build_guest_contexts(g_ctx_cache, sizeof(g_ctx_cache));
}

// SID гостя для контекста (нумерация с 1 — по порядку в списке контекстов гостя).
int guest_sid_for(const char* ctx) {
    if (!ctx || !*ctx) return 1;
    ensure_ctx_cache();
    const char* p = g_ctx_cache;
    int sid = 1;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len == strlen(ctx) && strncmp(p, ctx, len) == 0) return sid;
        sid++;
        if (!nl) break;
        p = nl + 1;
    }
    return 1;
}
