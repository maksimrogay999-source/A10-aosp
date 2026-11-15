#include "a10engine.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// Типы ФС, которые эмулятор поддерживает — их гость видит в /proc/filesystems.
static const char* kGuestFsTypes[] = {"tmpfs", "proc", "sysfs", "selinuxfs", "devpts"};

ssize_t build_guest_contexts(char* out, size_t outsz) {
    size_t used = 0;
    char seen[65536];
    seen[0] = 0;
    const char* dirs[3] = {"/system/etc/selinux", "/vendor/etc/selinux", "/product/etc/selinux"};
    const char* suffix = "_contexts";
    size_t sl = strlen(suffix);
    for (int d = 0; d < 3; d++) {
        char dir[700];
        if (!host_path_of(dirs[d], dir, sizeof(dir))) continue;
        DIR* dp = opendir(dir);
        if (!dp) continue;
        struct dirent* de;
        while ((de = readdir(dp)) != nullptr) {
            const char* name = de->d_name;
            size_t nl = strlen(name);
            if (nl <= sl || strcmp(name + nl - sl, suffix) != 0) continue;
            char fp[900];
            snprintf(fp, sizeof(fp), "%s/%s", dir, name);
            FILE* f = fopen(fp, "r");
            if (!f) continue;
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                char* sp = strchr(line, ' ');
                if (!sp) continue;
                while (*sp == ' ') sp++;
                char* e = strpbrk(sp, " \t\r\n");
                if (e) *e = 0;
                if (!sp[0] || sp[0] == '#') continue;
                // Значение — SELinux-контекст (u:object_r:xxx:s0).
                if (strncmp(sp, "u:", 2) != 0) continue;
                if (strstr(seen, sp)) continue;
                size_t need = strlen(sp) + 2;
                if (strlen(seen) + need >= sizeof(seen)) continue;
                snprintf(seen + strlen(seen), sizeof(seen) - strlen(seen), "%s\n", sp);
                int n = snprintf(out + used, outsz - used, "%s\n", sp);
                if (n > 0) used += (size_t)n;
            }
            fclose(f);
        }
        closedir(dp);
    }
    return (ssize_t)used;
}

// Типы файлов procfs/selinuxfs гостя (по базовому имени файла внутри mount'а).
int proc_kind_of_name(const char* base) {
    if (strcmp(base, "filesystems") == 0) return PROC_FILESYSTEMS;
    if (strcmp(base, "mounts") == 0) return PROC_MOUNTS;
    if (strcmp(base, "cmdline") == 0) return PROC_CMDLINE;
    if (strcmp(base, "enforce") == 0) return SEL_ENFORCE;
    if (strcmp(base, "status") == 0) return SEL_STATUS;
    if (strcmp(base, "contexts") == 0) return SEL_CONTEXTS;
    return PROC_NONE;
}

// ---------------------------------------------------------------- конструктор
ssize_t build_guest_filesystems(char* out, size_t outsz) {
    size_t used = 0;
    // Сначала типы из таблицы (объявлены самим гостем через mount).
    for (int i = 0; i < g_mount_count; i++) {
        char fs[64];
        if (!get_flag(&g_mounts[i], "fs", fs, sizeof(fs))) continue;
        bool dup = false;
        for (size_t k = 0; k < sizeof(kGuestFsTypes) / sizeof(kGuestFsTypes[0]); k++) {
            if (strcmp(kGuestFsTypes[k], fs) == 0) dup = true;
        }
        if (dup) continue;
        int n = snprintf(out + used, outsz - used, "nodev\t%s\n", fs);
        if (n > 0) used += (size_t)n;
    }
    for (size_t k = 0; k < sizeof(kGuestFsTypes) / sizeof(kGuestFsTypes[0]); k++) {
        int n = snprintf(out + used, outsz - used, "nodev\t%s\n", kGuestFsTypes[k]);
        if (n > 0) used += (size_t)n;
    }
    return (ssize_t)used;
}

// Содержимое /proc/mounts гостя: точки монтирования из таблицы.
ssize_t build_guest_mounts(char* out, size_t outsz) {
    size_t used = 0;
    for (int i = 0; i < g_mount_count; i++) {
        char fs[64];
        if (!get_flag(&g_mounts[i], "fs", fs, sizeof(fs))) continue;
        int n = snprintf(out + used, outsz - used, "none %s %s mode=0755 0 0\n",
                         g_mounts[i].guest, fs);
        if (n > 0) used += (size_t)n;
    }
    return (ssize_t)used;
}

// fd из selinuxfs-mount'а: запись в него эмулируется успехом.
bool is_selinux_fd(int fd) {
    const Entry* e = mount_of_fd(fd);
    return e && has_flag(e, "selinux");
}

int close(int fd) {
    track_del(fd);
    return (int)syscall(__NR_close, fd);
}

// ---------------------------------------------------------------- ошибки вызовов
// Лог ОШИБКИ перехваченного вызова (макрос A10_FAIL) — в a10engine.h: по нему видно,
// какой CHECKCALL гостя упал (init пишет "Init encountered errors starting first stage").

// ---------------------------------------------------------------- ФС: открытие
// Трассировка обращений гостя: показываем пути, куда гость пошёл (первые N).
