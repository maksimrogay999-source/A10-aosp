#include "a10engine.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void __attribute__((constructor)) a10preload_init(void) {
    const char* cf = getenv("A10_CONSOLE_FD");
    if (cf && *cf) g_console_fd = atoi(cf);
    const char* rf = getenv("A10_ROOTFS");
    if (rf && *rf) snprintf(g_rootfs, sizeof(g_rootfs), "%s", rf);
    // Раскладка гостя — из файла, который собрал стаб (никакого хардкода путей).
    const char* mf = getenv("A10_MOUNTS_FILE");
    if (mf && *mf) {
        snprintf(g_mounts_file, sizeof(g_mounts_file), "%s", mf);
        load_mount_table(mf);
    }
    // Реестр прав гостя (исходные режимы файлов, которые мы расширили ради записи).
    const char* mo = getenv("A10_MODES_FILE");
    if (mo && *mo) {
        snprintf(g_modes_file, sizeof(g_modes_file), "%s", mo);
        modes_init(mo);
    }

    // SIGSYS-handler: живёт в процессе init'а (обработчик из стаба сбрасывается при exec).
    install_sigsys_handler();

    // Состояние процесса гостя: seccomp-фильтр и NoNewPrivs. Если seccomp активен и
    // epoll_ctl не проходит — это и есть причина EPERM (фильтр мог поставить сам гость).
    {
        int fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char buf[8192];
            ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                const char* keys[] = {"Seccomp:", "NoNewPrivs:", "Uid:", "Gid:", "CapEff:"};
                for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
                    const char* p = strstr(buf, keys[k]);
                    if (!p) continue;
                    const char* e = strchr(p, '\n');
                    char line[256];
                    size_t len = e ? (size_t)(e - p) : strlen(p);
                    if (len > sizeof(line) - 1) len = sizeof(line) - 1;
                    memcpy(line, p, len);
                    line[len] = '\0';
                    plog("A10_Preload: %s", line);
                }
            }
        }
    }

    // Запоминаем переменные, которые init сотрёт через clearenv().
    // Дамп таблицы: видно, что реально прочитал preload (диагностика путей гостя).
    {
        char line[512];
        int n = snprintf(line, sizeof(line), "=== a10preload.so: таблица гостя: %d записей ===\n",
                         g_mount_count);
        if (n > 0) console_raw(line, (size_t)n);
        for (int i = 0; i < g_mount_count && i < 90; i++) {
            n = snprintf(line, sizeof(line), "таб: %s -> %s [%s]\n", g_mounts[i].guest,
                         g_mounts[i].host, g_mounts[i].flags);
            if (n > 0) console_raw(line, (size_t)n);
        }
    }
    const char* pv = getenv("LD_PRELOAD");
    if (pv) snprintf(g_preload, sizeof(g_preload), "%s", pv);
    if (cf && *cf) snprintf(g_console_env, sizeof(g_console_env), "%s", cf);
    const char* ar = getenv("ANDROID_ROOT");
    if (ar) snprintf(g_android_root, sizeof(g_android_root), "%s", ar);
    const char* llp = getenv("LD_LIBRARY_PATH");
    if (llp) snprintf(g_ld_library_path, sizeof(g_ld_library_path), "%s", llp);
    const char* pth = getenv("PATH");
    if (pth) snprintf(g_path, sizeof(g_path), "%s", pth);

    // 1) ok-файл exec-пробы: ДОКАЗАТЕЛЬСТВО, что линкер загрузил preload при exec.
    //    Родитель-стаб поллит его каждые 20мс.
    const char* okf = getenv("A10_PROBE_OK_FILE");
    if (okf && *okf) {
        long fd = syscall(__NR_openat, AT_FDCWD, okf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            const char* msg = "ok";
            syscall(__NR_write, fd, msg, 2);
            syscall(__NR_close, fd);
        }
    }

    // 2) маркер в консоль: виден и в пробе (A10_PROBE_LABEL), и в init после exec.
    if (g_console_fd >= 0) {
        const char* lbl = getenv("A10_PROBE_LABEL");
        char buf[200];
        int n = (lbl && *lbl)
            ? snprintf(buf, sizeof(buf), "=== a10preload.so LOADED at exec (probe %s), console_fd=%d ===\n", lbl, g_console_fd)
            : snprintf(buf, sizeof(buf), "=== a10preload.so LOADED (constructor), console_fd=%d, rootfs=%s ===\n", g_console_fd, g_rootfs);
        if (n > 0) {
            ssize_t wn = (ssize_t)syscall(__NR_write, g_console_fd, buf, (size_t)n);
            (void)wn;
        }
        plog("a10preload.so loaded: EMULATION mode (paths -> rootfs, real syscalls)");
    }
}

// ---------------------------------------------------------------- мелочи
