// a10preload.so — LD_PRELOAD: ЭМУЛЯЦИЯ гостевой AOSP на хосте.
//
// Задача: гость (init из GSI) должен видеть СВОЮ файловую систему и получать
// осмысленные результаты syscall'ов. Раньше перехваченные вызовы просто
// "блокировались" (возвращали 0), из-за чего init принимал неверные решения:
//   * mkdir("/dev/pts") -> EEXIST -> CHECKCALL -> "Init encountered errors ... aborting";
//   * mknod("/dev/kmsg") -> EEXIST, chmod("/proc/cmdline") -> EPERM  (то же самое);
//   * statfs("/sys/fs/selinux") -> SELINUX_MAGIC -> init считал selinuxfs смонтированной.
//
// Теперь — эмуляция:
//     -> <rootfs>/... (A10_ROOTFS).
//   * файловые операции ВЫПОЛНЯЮТСЯ по-настоящему (raw syscall), а не имитируются;
//   * то, что на хосте невозможно (mount, mknod, setgroups, загрузка SELinux-политики),
//     эмулируется осмысленно: успех + запись в консоль;
//   * SELinux-подсистема эмулируется: политика отдаётся гостю, загрузка в ядро — успех.
//
// Окружение:
//   A10_CONSOLE_FD  — fd консольного pipe (write-only): логи и /dev/kmsg
//   A10_ROOTFS      — корень гостевой ФС (префикс для перевода путей)
//   A10_PROBE_OK_FILE — если задан, конструктор пишет ok-файл (exec-проба линкера)

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sched.h>
#include <signal.h>
#include <ucontext.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "a10mounts.h"

#ifndef __NR_getrandom
#define __NR_getrandom 278
#endif

extern char** environ;

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

// ---------------------------------------------------------------- REAL_FN макрос
#define REAL_FN(var, name, rettype, params)     \
    static rettype (*var) params = nullptr;     \
    if (!var) var = (rettype (*) params)dlsym(RTLD_NEXT, name)

static int g_console_fd = -1;
static char g_rootfs[512];
// Сохраняем окружение гостя: init первой стадии делает clearenv() — без восстановления
// LD_PRELOAD вторая стадия (selinux_setup) стартовала БЕЗ нашей эмуляции (лог 14:55).
static char g_preload[1024];
static char g_console_env[64];
static char g_android_root[512];
static char g_ld_library_path[1024];
static char g_path[512];
static char g_mounts_file[512];

// ---------------------------------------------------------------- логи гостя
// Гость (init) пишет сообщения через android::base -> __android_log_write -> гостевой
// liblog -> сокет /dev/socket/logdw. В гостевом /dev этого сокета нет, и сообщение
// ТЕРЯЛОСЬ (лог 14:36: init молча умирал на SIGABRT). Перехватываем запись и печатаем
// в нашу консоль: так видно каждый LOG() гостя, включая LOG(FATAL) с текстом ошибки.
static void console_raw(const char* buf, size_t n) {
    if (g_console_fd < 0 || n == 0) return;
    ssize_t wn = (ssize_t)syscall(__NR_write, g_console_fd, buf, n);
    (void)wn;
}

// Ловим ВСЁ, что гость пишет в свои stdout/stderr — даже если fd уведён в /dev/null.
// Иначе текст LOG(FATAL) теряется (лог 14:40: abort поймали, а текст — нет).
static void guest_out(const char* prefix, int fd, const char* buf, size_t n) {
    if (fd < 0 || fd > 3 || !buf || n == 0) return;
    char tmp[400];
    size_t len = n < sizeof(tmp) - 1 ? n : sizeof(tmp) - 1;
    memcpy(tmp, buf, len);
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '\n' || tmp[i] == '\r') tmp[i] = '|';
        else if (tmp[i] < 32) tmp[i] = '.';
    }
    tmp[len] = '\0';
    char out[520];
    int m = snprintf(out, sizeof(out), "%s fd=%d: %s", prefix, fd, tmp);
    if (m > 0) console_raw(out, (size_t)m);
}

extern "C" int __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) {
    char body[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    char buf[768];
    int n = snprintf(buf, sizeof(buf), "[guest %s ASSERT] %s : %s", tag ? tag : "?", cond ? cond : "?",
                     body);
    if (n > 0) console_raw(buf, (size_t)n);
    return 0;
}

extern "C" int __android_log_write(int prio, const char* tag, const char* text) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[guest %s prio=%d] %s", tag ? tag : "?", prio,
                     text ? text : "");
    if (n > 0) console_raw(buf, (size_t)n);
    return 0;
}

extern "C" int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
    char body[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[guest %s prio=%d] %s", tag ? tag : "?", prio, body);
    if (n > 0) console_raw(buf, (size_t)n);
    return 0;
}

extern "C" int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
    char body[768];
    vsnprintf(body, sizeof(body), fmt, ap);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[guest %s prio=%d] %s", tag ? tag : "?", prio, body);
    if (n > 0) console_raw(buf, (size_t)n);
    return 0;
}

// Android передаёт сюда ТЕКСТ фатальной ошибки перед abort() (libbase -> DefaultAborter).
// Это единственный надёжный источник сообщения гостя: его liblog шлёт в /dev/socket/logdw,
// которого в гостевом /dev нет, и всё теряется (лог 14:45).
extern "C" void android_set_abort_message(const char* message) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[guest FATAL] %s", message ? message : "(empty)");
    if (n > 0) console_raw(buf, (size_t)n);
    REAL_FN(real, "android_set_abort_message", void, (const char*));
    if (real) real(message);
}

// abort() гостя — печатаем маркер (текст LOG(FATAL) уже ушёл в __android_log_write).
extern "C" void abort(void) {
    console_raw("[guest] abort() вызван гостём\n", 32);
    REAL_FN(real, "abort", void, (void));
    if (real) real();
    __builtin_unreachable();
}

// ---------------------------------------------------------------- виртуальный netlink
// init первой стадии обязан создать NETLINK_KOBJECT_UEVENT-сокет и сделать bind() на
// группу 1 (uevent_listener.cpp: UeventSocket::Create) — на хосте bind упирается в EPERM
// (нужен CAP_NET_ADMIN) -> LOG(FATAL) "Could not open uevent socket" -> abort (лог 14:50).
// Эмулируем: настоящий netlink-сокет (если создался) или unix-сокет вместо него;
// bind/setsockopt для таких fd считаем успешными. Событий uevent не будет — но init
// пройдёт дальше.
#define A10_MAX_NETLINK 16
static int g_netlink_fd[A10_MAX_NETLINK];

static void mark_netlink(int fd) {
    if (fd < 0) return;
    for (int i = 0; i < A10_MAX_NETLINK; i++) {
        if (g_netlink_fd[i] == 0) {
            g_netlink_fd[i] = fd;
            return;
        }
    }
}

static bool is_netlink_fd(int fd) {
    for (int i = 0; i < A10_MAX_NETLINK; i++) {
        if (g_netlink_fd[i] == fd) return true;
    }
    return false;
}

// Сокет logd гостя (/dev/socket/logdw): сообщения гостя уходят туда, но протокол
// несовместим с logd Android 16 — поэтому ловим их сами и печатаем в консоль.
#define A10_MAX_LOGFD 8
static int g_logfd[A10_MAX_LOGFD];

static void mark_logfd(int fd) {
    if (fd < 0) return;
    for (int i = 0; i < A10_MAX_LOGFD; i++) {
        if (g_logfd[i] == 0) {
            g_logfd[i] = fd;
            return;
        }
    }
}

static bool is_logfd(int fd) {
    for (int i = 0; i < A10_MAX_LOGFD; i++) {
        if (g_logfd[i] == fd) return true;
    }
    return false;
}

int socket(int domain, int type, int protocol) {
    REAL_FN(real, "socket", int, (int, int, int));
    if (!real) { errno = ENOSYS; return -1; }
    int fd = real(domain, type, protocol);
    if (domain != AF_NETLINK) return fd;
    if (fd >= 0) {
        mark_netlink(fd);
        return fd;
    }
    // netlink-сокет создать не дали -> подменяем на unix-datagram (работает как «пустой»)
    int p[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, p) == 0) {
        mark_netlink(p[0]);
        close(p[1]);
        char msg[96];
        int n = snprintf(msg, sizeof(msg), "A10_Preload: netlink-сокет заменён на unix-socketpair (fd=%d)\n", p[0]);
        if (n > 0) console_raw(msg, (size_t)n);
        return p[0];
    }
    return -1;
}

int bind(int fd, const struct sockaddr* addr, socklen_t len) {
    REAL_FN(real, "bind", int, (int, const struct sockaddr*, socklen_t));
    if (is_netlink_fd(fd)) return 0;   // bind на netlink-группу = EPERM на хосте
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, addr, len);
}

int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    REAL_FN(real, "setsockopt", int, (int, int, int, const void*, socklen_t));
    if (is_netlink_fd(fd) && level == SOL_NETLINK) return 0;
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, level, optname, optval, optlen);
}

// ---------------------------------------------------------------- вывод в консоль
static void plog(const char* fmt, ...) {
    if (g_console_fd < 0) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf) - 2) n = (int)sizeof(buf) - 2;
    buf[n] = '\n';
    ssize_t wn = (ssize_t)syscall(__NR_write, g_console_fd, buf, (size_t)n + 1);
    (void)wn;
}

// ---------------------------------------------------------------- таблица раскладки
// ХАРДКОДА ПУТЕЙ НЕТ. Таблицу гостя (guest-путь -> host-путь + флаги) собирает стаб
// (скан корня гостевой ФС), она лежит в файле <rootfs>/a10_mounts и передаётся гостю
// через A10_MOUNTS_FILE. Гость может пополнять её на лету: mount() регистрирует точку
// монтирования, mknod() — устройство. Изменения сохраняются в тот же файл.
using a10mount::Entry;
using a10mount::flag_present;
using a10mount::has_flag;
using a10mount::get_flag;
using a10mount::magic_of;
using a10mount::parse_line;
using a10mount::path_prefix;

static Entry g_mounts[128];
static int g_mount_count = 0;

// Тип ФС selinuxfs: f_type для statfs/fstatfs. Значение — константа uapi ядра
// (linux/selinux.h), а не «информация о путях».
#ifndef SELINUX_MAGIC
#define SELINUX_MAGIC 0xf97cff8c
#endif

static void load_mount_table(const char* path) {
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
static const Entry* lookup_mount(const char* path) {
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

// Перевод гостевого пути в реальный по таблице. true — путь переведён.
static bool translate(const char* p, char* out, size_t outsz) {
    const Entry* e = lookup_mount(p);
    if (!e) return false;
    snprintf(out, outsz, "%s%s", e->host, p + strlen(e->guest));
    return true;
}

// Запись таблицы по точному guest-пути.
static const Entry* table_find_exact(const char* guest) {
    for (int i = 0; i < g_mount_count; i++) {
        if (strcmp(g_mounts[i].guest, guest) == 0) return &g_mounts[i];
    }
    return nullptr;
}

// Добавить/обновить запись таблицы.
static void table_set(const char* guest, const char* host, const char* flags) {
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
static void table_save(void) {
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
static bool guest_root(char* out, size_t outsz) {
    const Entry* e = table_find_exact("/");
    if (!e) return false;
    snprintf(out, outsz, "%s", e->host);
    return true;
}

// Перевод пути гостя в host-путь. УЖЕ ПЕРЕВЕДЁННЫЙ (host) путь не трогаем:
// иначе двойной перевод (fopen -> bionic -> наш __openat) ломает доступ —
// файл существует, но второй перевод даёт ENOENT.
static bool host_path_of(const char* p, char* out, size_t outsz) {
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
static unsigned long magic_for_path(const char* path) {
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
static unsigned long magic_for_entry(const Entry* e) {
    if (!e) return 0;
    unsigned long mg = magic_of(e);
    if (mg) return mg;
    char acc[256];
    snprintf(acc, sizeof(acc), "%s", e->guest);
    while (strlen(acc) > 1) {
        char* slash = strrchr(acc, '/');
        if (!slash || slash == acc) break;
        *slash = '\0';
        const Entry* p = lookup_mount(acc);
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

static void a10_preload_sigsys_handler(int sig, siginfo_t* info, void* uctx) {
    (void)sig;
    long nr = info ? (long)info->si_syscall : -1;
    // pkey_alloc/pkey_free гостю не критичны (защита стека) — отвечаем успехом.
    if (uctx && (nr == __NR_pkey_alloc || nr == __NR_pkey_free)) {
        ucontext_t* uc = (ucontext_t*)uctx;
        uc->uc_mcontext.regs[0] = 0;   // x0 = результат syscall'а
        return;
    }
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "=== SIGSYS: syscall %ld -> ENOSYS ===\n", nr);
    if (n > 0) console_raw(buf, (size_t)n);
}

static void install_sigsys_handler() {
    struct sigaction sa {};
    sa.sa_sigaction = a10_preload_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) == 0) {
        plog("a10preload.so: SIGSYS-handler установлен (внутри init'а)");
    }
}

// ---------------------------------------------------------------- конструктор
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

    // SIGSYS-handler: живёт в процессе init'а (обработчик из стаба сбрасывается при exec).
    install_sigsys_handler();

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
static void mkdir_p(const char* path) {
    static int (*real_mkdir)(const char*, mode_t) = nullptr;
    if (!real_mkdir) real_mkdir = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "mkdir");
    if (!real_mkdir) return;
    char tmp[700];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t n = strlen(tmp);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            real_mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    }
    real_mkdir(tmp, 0755);
}

// Отслеживаемые fd: помним, из какого MOUNT'а таблицы fd получен и что это за
// устройство — по нему определяются эмулируемые свойства (selinuxfs, kmsg, ...).
#define A10_TRACK_MAX 64
static int g_track_fd[A10_TRACK_MAX];
static int g_track_mount[A10_TRACK_MAX];
static int g_track_kind[A10_TRACK_MAX];

// Виды эмулируемых устройств гостя (по номерам major/minor).
enum DevKind {
    DEVK_PLAIN = 0,   // обычный узел гостевой ФС
    DEVK_NULL,        // чтение -> EOF, запись -> успех
    DEVK_ZERO,        // чтение -> нули
    DEVK_FULL,        // запись -> успех, чтение -> EOF
    DEVK_RANDOM,      // чтение -> энтропия
    DEVK_URANDOM,     // чтение -> энтропия
    DEVK_KMSG,        // запись -> консоль гостя
};

// Устройство по номерам major/minor (нумерация Linux). Хостовые устройства при этом
// НЕ используются — всё эмулируется.
static int dev_kind_by_numbers(int major, int minor) {
    if (major != 1) return DEVK_PLAIN;   // не mem-устройство
    switch (minor) {
        case 3: return DEVK_NULL;
        case 5: return DEVK_ZERO;
        case 7: return DEVK_FULL;
        case 8: return DEVK_RANDOM;
        case 9: return DEVK_URANDOM;
        case 11: return DEVK_KMSG;
        default: return DEVK_PLAIN;
    }
}

static void track_add(int fd, int mount_index, int kind) {
    if (fd < 0) return;
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == 0) {
            g_track_fd[i] = fd;
            g_track_mount[i] = mount_index;
            g_track_kind[i] = kind;
            return;
        }
    }
}

static void track_del(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) {
            g_track_fd[i] = 0;
            g_track_mount[i] = -1;
            g_track_kind[i] = DEVK_PLAIN;
        }
    }
}

// Mount таблицы, из которого получен fd (nullptr — неизвестно/не из таблицы).
static const Entry* mount_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd && g_track_mount[i] >= 0) return &g_mounts[g_track_mount[i]];
    }
    return nullptr;
}

// Вид устройства по fd (DEVK_PLAIN — обычный).
static int dev_kind_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) return g_track_kind[i];
    }
    return DEVK_PLAIN;
}

// Виртуальные файлы procfs ГОСТЯ: содержимое эмулируется (procfs хоста — это shared,
// гостю он не принадлежит). Тип ФС proc гость объявляет сам, через mount() — тогда
// preload создаёт у него файлы procfs и подменяет их содержимое.
enum ProcKind { PROC_NONE = 0, PROC_FILESYSTEMS, PROC_MOUNTS, PROC_CMDLINE };
static int g_track_proc[A10_TRACK_MAX];

static void track_set_proc(int fd, int kind) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) {
            g_track_proc[i] = kind;
            return;
        }
    }
}

static int proc_kind_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) return g_track_proc[i];
    }
    return PROC_NONE;
}

// Типы ФС, которые эмулятор поддерживает — их гость видит в /proc/filesystems.
static const char* kGuestFsTypes[] = {"tmpfs", "proc", "sysfs", "selinuxfs", "devpts"};

// Содержимое /proc/filesystems гостя: поддерживаемые типы ФС.
static ssize_t build_guest_filesystems(char* out, size_t outsz) {
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
static ssize_t build_guest_mounts(char* out, size_t outsz) {
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
static bool is_selinux_fd(int fd) {
    const Entry* e = mount_of_fd(fd);
    return e && has_flag(e, "selinux");
}

int close(int fd) {
    track_del(fd);
    return (int)syscall(__NR_close, fd);
}

// ---------------------------------------------------------------- ошибки вызовов
// Лог ОШИБКИ перехваченного вызова: по нему видно, какой CHECKCALL гостя упал
// (init пишет "Init encountered errors starting first stage" без указания места).
#define A10_FAIL(what, path)                                                   \
    plog("A10_Preload: %s(%s) FAILED errno=%d (%s)", what, (path) ? (path) : "?", \
         errno, strerror(errno))

// ---------------------------------------------------------------- ФС: открытие
// Трассировка обращений гостя: показываем пути, куда гость пошёл (первые N).
#define A10_TRACE_MAX 400
static int g_trace_count = 0;
static bool trace_slot() {
    if (g_trace_count >= A10_TRACE_MAX) return false;
    g_trace_count++;
    return true;
}

// Путь гостя переводится ТОЛЬКО по mount-таблице. Пути вне таблицы недоступны:
// ничего общего у хоста и гостя (в ФС телефона гость не попадает).
// Поведение задаётся флагами записи: chr=major:minor (устройство гостя),
// selinux (эмулированный selinuxfs), fs=<тип> (тип ФС), trace (диагностика).
static int a10_open_common(int dirfd, const char* path, int flags, mode_t mode) {
    if (!path) { errno = EFAULT; return -1; }
    const Entry* e = lookup_mount(path);
    const int idx = e ? (int)(e - g_mounts) : -1;

    char host[900];
    const char* use = path;
    bool translated = false;
    if (e) {
        snprintf(host, sizeof(host), "%s%s", e->host, path + strlen(e->guest));
        use = host;
        translated = true;
    } else if (!(g_rootfs[0] && strncmp(path, g_rootfs, strlen(g_rootfs)) == 0)) {
        // Путь гостя вне таблицы: в ФС телефона гость не попадает.
        errno = ENOENT;
        return -1;
    }

    // Устройство гостя (создано mknod): эмулируем по номерам major/minor.
    char devnum[64];
    if (get_flag(e, "chr", devnum, sizeof(devnum))) {
        int maj = 0, min = 0;
        sscanf(devnum, "%d:%d", &maj, &min);
        int kind = dev_kind_by_numbers(maj, min);
        int fd = (int)syscall(__NR_openat, dirfd, use, flags | O_CREAT, mode);
        if (fd >= 0) track_add(fd, idx, kind);
        plog("A10_Preload: %s -> устройство гостя %d:%d (эмуляция, fd=%d errno=%d)", path, maj, min,
             fd, fd < 0 ? errno : 0);
        return fd;
    }

    // Эмулированный selinuxfs: файла может не быть — создаём узел в гостевой ФС,
    // запись в него считаем успехом (политику в ядро хоста не грузим).
    if (has_flag(e, "selinux")) {
        int fd = (int)syscall(__NR_openat, dirfd, use, (flags & ~O_CREAT) | O_CREAT, 0644);
        if (fd >= 0) {
            // Запоминаем ТОЧКУ МОНТИРОВАНИЯ selinuxfs (по ней — magic для fstatfs).
            int sidx = idx;
            for (int i = 0; i < g_mount_count; i++) {
                if (has_flag(&g_mounts[i], "selinux") && path_prefix(path, g_mounts[i].guest)) {
                    sidx = i;
                    break;
                }
            }
            track_add(fd, sidx, DEVK_PLAIN);
            plog("A10_Preload: %s -> эмулированный selinuxfs (fd=%d, запись принимается)", path, fd);
        }
        return fd;
    }

    int fd = (int)syscall(__NR_openat, dirfd, use, flags, mode);
    if (fd >= 0) {
        track_add(fd, idx, DEVK_PLAIN);
        // Виртуальные файлы procfs гостя: помечаем, чтобы read() отдавал эмуляцию.
        if (flag_present(e, "procfs")) {
            const char* base = strrchr(path, '/');
            base = base ? base + 1 : path;
            int pk = PROC_NONE;
            if (strcmp(base, "filesystems") == 0) pk = PROC_FILESYSTEMS;
            else if (strcmp(base, "mounts") == 0) pk = PROC_MOUNTS;
            else if (strcmp(base, "cmdline") == 0) pk = PROC_CMDLINE;
            if (pk != PROC_NONE) track_set_proc(fd, pk);
        }
    }
    if (fd < 0) {
        A10_FAIL("open", path);
    } else if (flag_present(e, "trace") || trace_slot()) {
        plog("A10_Preload: open(%s) -> fd=%d", path, fd);
    }
    return fd;
}

int open(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return a10_open_common(AT_FDCWD, pathname, flags, mode);
}

int openat(int dirfd, const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return a10_open_common(dirfd, pathname, flags, mode);
}

// bionic: fortify-обёртки (__open_2 / __openat_2) вызывают ВНУТРЕННИЙ __openat
// напрямую — мимо публичных open/openat. Гость собран с _FORTIFY_SOURCE, поэтому
// без этого перехвата он читал файлы ХОСТОВЫМИ путями (например sha-политики
// SELinux) и молча получал false -> "Unable to load SELinux policy".
extern "C" int __openat(int dirfd, const char* pathname, int flags, mode_t mode) {
    return a10_open_common(dirfd, pathname, flags, mode);
}

extern "C" int __open_2(const char* pathname, int flags) {
    return a10_open_common(AT_FDCWD, pathname, flags, 0);
}

extern "C" int __openat_2(int dirfd, const char* pathname, int flags) {
    return a10_open_common(dirfd, pathname, flags, 0);
}

// arm64-алиасы (LFS): гость вправе звать open64/openat64 — иначе он открывает
// /dev/kmsg мимо нашего перехвата (лог 14:36: kmsg так и не открылся).
int open64(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return a10_open_common(AT_FDCWD, pathname, flags, mode);
}

int openat64(int dirfd, const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return a10_open_common(dirfd, pathname, flags, mode);
}
// ---------------------------------------------------------------- ФС: stat/access
// Путь гостя переводится ТОЛЬКО по таблице. Вне таблицы — ENOENT: в ФС телефона
// гость не попадает (общих ресурсов у хоста и гостя нет).
int stat(const char* pathname, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("stat", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_newfstatat, AT_FDCWD, host, st, 0);
    if (r < 0) A10_FAIL("stat", pathname);
    return r;
}

int lstat(const char* pathname, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("lstat", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_newfstatat, AT_FDCWD, host, st, AT_SYMLINK_NOFOLLOW);
    if (r < 0) A10_FAIL("lstat", pathname);
    return r;
}

int fstat(int fd, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    return (int)syscall(__NR_fstat, fd, st);
}

int fstatat(int dirfd, const char* pathname, struct stat* st, int flags) {
    if (!st) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("fstatat", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_newfstatat, dirfd, host, st, flags);
    if (r < 0) A10_FAIL("fstatat", pathname);
    return r;
}

// LFS-алиасы статистики — на LP64 struct stat64 совпадает с struct stat.
int stat64(const char* pathname, struct stat64* st) {
    REAL_FN(real, "stat64", int, (const char*, struct stat64*));
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("stat64", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(host, st);
}

int lstat64(const char* pathname, struct stat64* st) {
    REAL_FN(real, "lstat64", int, (const char*, struct stat64*));
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("lstat64", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(host, st);
}

int fstat64(int fd, struct stat64* st) {
    REAL_FN(real, "fstat64", int, (int, struct stat64*));
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, st);
}

int fstatat64(int dirfd, const char* pathname, struct stat64* st, int flags) {
    REAL_FN(real, "fstatat64", int, (int, const char*, struct stat64*, int));
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("fstatat64", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(dirfd, host, st, flags);
}

int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* stx) {
    if (!stx) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("statx", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_statx, dirfd, host, flags, mask, stx);
    if (r < 0) A10_FAIL("statx", pathname);
    return r;
}

// Трассировка: печатаем только для mount'ов, помеченных в таблице (trace/selinux).
static bool traced_mount(const char* path) {
    const Entry* e = lookup_mount(path ? path : "");
    return e && (has_flag(e, "trace") || has_flag(e, "selinux"));
}

int access(const char* pathname, int mode) {
    if (!pathname) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("access", pathname);
        return -1;
    }
    bool trace = traced_mount(pathname);
    if (trace) {
        plog("A10_Preload: access(%s, %d) (переведён)", pathname, mode);
    }
    int r = (int)syscall(__NR_faccessat, AT_FDCWD, host, mode);
    if (r < 0) {
        A10_FAIL("access", pathname);
    } else if (trace || trace_slot()) {
        plog("A10_Preload: access(%s) -> 0", pathname);
    }
    return r;
}

// fopen/fopen64/freopen: путь гостя переводится по таблице (иначе гость прочёл бы
// ФС ХОСТА вместо своей).
FILE* fopen(const char* pathname, const char* mode) {
    REAL_FN(real, "fopen", FILE*, (const char*, const char*));
    if (!real) { errno = ENOSYS; return nullptr; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("fopen", pathname);
        return nullptr;
    }
    bool trace = traced_mount(pathname);
    if (trace) plog("A10_Preload: fopen(%s, %s)", pathname ? pathname : "?", mode ? mode : "?");
    FILE* f = real(host, mode);
    if (!f) {
        A10_FAIL("fopen", pathname);
    } else if (trace || trace_slot()) {
        plog("A10_Preload: fopen(%s) -> ok", pathname ? pathname : "?");
    }
    return f;
}

FILE* fopen64(const char* pathname, const char* mode) {
    REAL_FN(real, "fopen64", FILE*, (const char*, const char*));
    if (!real) { errno = ENOSYS; return nullptr; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("fopen64", pathname);
        return nullptr;
    }
    return real(host, mode);
}

FILE* freopen(const char* pathname, const char* mode, FILE* stream) {
    REAL_FN(real, "freopen", FILE*, (const char*, const char*, FILE*));
    if (!real) { errno = ENOSYS; return nullptr; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("freopen", pathname);
        return nullptr;
    }
    return real(host, mode, stream);
}

// Признак сокета — чтобы поймать трафик гостя в logd (write/sendto/sendmsg).
static bool is_socket_fd(int fd) {
    struct stat st {};
    if (syscall(__NR_fstat, fd, &st) != 0) return false;
    return S_ISSOCK(st.st_mode);
}

// ---------------------------------------------------------------- dup2
// init делает SetStdioToDevNull() ДО InitKernelLogging(): его stdout/stderr уходят в
// /dev/null, и ранний LOG(FATAL) ("Init encountered errors...", "Unable to load SELinux
// policy") теряется. Оставляем stdout/stderr гостя на консоли — так видно ВСЕ сообщения.
int dup2(int oldfd, int newfd) {
    REAL_FN(real, "dup2", int, (int, int));
    if (!real) { errno = ENOSYS; return -1; }
    if (g_console_fd >= 0 && (newfd == STDOUT_FILENO || newfd == STDERR_FILENO)) {
        int r = real(g_console_fd, newfd);
        plog("A10_Preload: dup2(fd=%d) -> stdout/stderr остаются на консоли гостя", oldfd);
        return r;
    }
    return real(oldfd, newfd);
}

// ---------------------------------------------------------------- ФС: изменения
// Запись разрешена только в mount'ы, помеченные в таблице флагом "rw"
// (или "chmod_ok"). Путей вне таблицы гость не касается — ФС телефона защищена.
static bool writable_target(const char* pathname, char* host, size_t hostsz) {
    if (!pathname) return false;
    // Уже переведённый (host) путь гостя: пускаем как есть (внутри гостевой ФС).
    if (g_rootfs[0] && strncmp(pathname, g_rootfs, strlen(g_rootfs)) == 0) {
        snprintf(host, hostsz, "%s", pathname);
        return true;
    }
    const Entry* e = lookup_mount(pathname);
    if (!e) return false;
    if (!has_flag(e, "rw") && !has_flag(e, "chmod_ok")) return false;
    snprintf(host, hostsz, "%s%s", e->host, pathname + strlen(e->guest));
    return true;
}

int mkdir(const char* pathname, mode_t mode) {
    REAL_FN(real, "mkdir", int, (const char*, mode_t));
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) {
        plog("A10_Preload: mkdir %s denied (вне гостевой ФС)", pathname ? pathname : "?");
        errno = EACCES;
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(host, mode);
    if (r < 0 && errno == EEXIST) {
        r = 0;   // mkdir -p семантика
        plog("A10_Preload: mkdir %s ok (уже существует)", pathname ? pathname : "?");
    } else if (r < 0) {
        plog("A10_Preload: mkdir %s FAILED errno=%d (%s)", pathname ? pathname : "?", errno,
             strerror(errno));
    } else {
        plog("A10_Preload: mkdir %s ok", pathname ? pathname : "?");
    }
    return r;
}

int mkdirat(int dirfd, const char* pathname, mode_t mode) {
    REAL_FN(real, "mkdirat", int, (int, const char*, mode_t));
    char host[900];
    if (!writable_target(pathname, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("mkdirat", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, host, mode);
    if (r < 0 && errno == EEXIST) return 0;
    if (r < 0) A10_FAIL("mkdirat", pathname);
    return r;
}

int rmdir(const char* pathname) {
    REAL_FN(real, "rmdir", int, (const char*));
    char host[900];
    if (!writable_target(pathname, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("rmdir", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(host);
    if (r < 0) A10_FAIL("rmdir", pathname);
    return r;
}

int unlink(const char* pathname) {
    REAL_FN(real, "unlink", int, (const char*));
    char host[900];
    if (!writable_target(pathname, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("unlink", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(host);
    if (r < 0) A10_FAIL("unlink", pathname);
    return r;
}

int unlinkat(int dirfd, const char* pathname, int flags) {
    REAL_FN(real, "unlinkat", int, (int, const char*, int));
    char host[900];
    if (!writable_target(pathname, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("unlinkat", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, host, flags);
    if (r < 0) A10_FAIL("unlinkat", pathname);
    return r;
}

int rename(const char* oldpath, const char* newpath) {
    REAL_FN(real, "rename", int, (const char*, const char*));
    char ho[900], hn[900];
    if (!writable_target(oldpath, ho, sizeof(ho)) || !writable_target(newpath, hn, sizeof(hn))) {
        errno = EACCES;
        A10_FAIL("rename", oldpath);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ho, hn);
    if (r < 0) A10_FAIL("rename", oldpath);
    return r;
}

int symlink(const char* target, const char* linkpath) {
    REAL_FN(real, "symlink", int, (const char*, const char*));
    char host[900];
    if (!writable_target(linkpath, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("symlink", linkpath);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(target, host);
    if (r < 0) A10_FAIL("symlink", linkpath);
    return r;
}

int link(const char* oldpath, const char* newpath) {
    REAL_FN(real, "link", int, (const char*, const char*));
    char ho[900], hn[900];
    if (!writable_target(oldpath, ho, sizeof(ho)) || !writable_target(newpath, hn, sizeof(hn))) {
        errno = EACCES;
        A10_FAIL("link", oldpath);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(ho, hn);
    if (r < 0) A10_FAIL("link", oldpath);
    return r;
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz) {
    REAL_FN(real, "readlink", ssize_t, (const char*, char*, size_t));
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("readlink", pathname);
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    ssize_t r = real(host, buf, bufsiz);
    if (r < 0) A10_FAIL("readlink", pathname);
    return r;
}

int chmod(const char* pathname, mode_t mode) {
    const Entry* e = lookup_mount(pathname ? pathname : "");
    if (!e) {
        errno = ENOENT;
        A10_FAIL("chmod", pathname);
        return -1;
    }
    // chmod в mount'е с флагом "chmod_ok" ядро хоста не даёт — эмулируем успех.
    if (has_flag(e, "chmod_ok")) {
        plog("A10_Preload: chmod %s emulated (ядро хоста не даёт)", pathname ? pathname : "?");
        return 0;
    }
    char host[900];
    snprintf(host, sizeof(host), "%s%s", e->host, pathname + strlen(e->guest));
    int r = (int)syscall(__NR_fchmodat, AT_FDCWD, host, mode);
    if (r < 0) A10_FAIL("chmod", pathname);
    return r;
}

int fchmodat(int dirfd, const char* pathname, mode_t mode, int flags) {
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("fchmodat", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_fchmodat, dirfd, host, mode, flags);
    if (r < 0) A10_FAIL("fchmodat", pathname);
    return r;
}

int chown(const char* pathname, uid_t owner, gid_t group) {
    const Entry* e = lookup_mount(pathname ? pathname : "");
    if (!e) {
        errno = ENOENT;
        A10_FAIL("chown", pathname);
        return -1;
    }
    if (has_flag(e, "chmod_ok")) {
        plog("A10_Preload: chown %s emulated", pathname ? pathname : "?");
        return 0;
    }
    char host[900];
    snprintf(host, sizeof(host), "%s%s", e->host, pathname + strlen(e->guest));
    int r = (int)syscall(__NR_fchownat, AT_FDCWD, host, owner, group, 0);
    if (r < 0) A10_FAIL("chown", pathname);
    return r;
}

int lchown(const char* pathname, uid_t owner, gid_t group) {
    const Entry* e = lookup_mount(pathname ? pathname : "");
    if (!e) {
        errno = ENOENT;
        A10_FAIL("lchown", pathname);
        return -1;
    }
    if (has_flag(e, "chmod_ok")) return 0;
    char host[900];
    snprintf(host, sizeof(host), "%s%s", e->host, pathname + strlen(e->guest));
    int r = (int)syscall(__NR_fchownat, AT_FDCWD, host, owner, group, AT_SYMLINK_NOFOLLOW);
    if (r < 0) A10_FAIL("lchown", pathname);
    return r;
}

int fchown(int fd, uid_t owner, gid_t group) {
    return (int)syscall(__NR_fchown, fd, owner, group);
}

int truncate(const char* pathname, off_t length) {
    char host[900];
    if (!writable_target(pathname, host, sizeof(host))) {
        errno = EACCES;
        A10_FAIL("truncate", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_truncate, host, length);
    if (r < 0) A10_FAIL("truncate", pathname);
    return r;
}

DIR* opendir(const char* name) {
    static DIR* (*real)(const char*) = nullptr;
    if (!real) real = (DIR* (*)(const char*))dlsym(RTLD_NEXT, "opendir");
    if (!real) { errno = ENOSYS; return nullptr; }
    char host[900];
    if (!host_path_of(name, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("opendir", name);
        return nullptr;
    }
    DIR* d = real(host);
    if (!d) A10_FAIL("opendir", name);
    return d;
}

// Временные файлы гостя (например /dev/sepolicy.XXXXXX) создаём в гостевой ФС.
int mkostemp(char* tmpl, int flags) {
    static int (*real)(char*, int) = nullptr;
    if (!real) real = (int (*)(char*, int))dlsym(RTLD_NEXT, "mkostemp");
    if (!real) { errno = ENOSYS; return -1; }
    char host[900];
    if (!host_path_of(tmpl, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("mkostemp", tmpl);
        return -1;
    }
    char keep[300];
    snprintf(keep, sizeof(keep), "%s", tmpl);
    int fd = real(host, flags);
    // Подменяем tmpl на реальный путь, только если он помещается: иначе гость получил бы
    // ОБРЕЗАННЫЙ путь (и потом удалял бы несуществующий файл).
    if (fd >= 0 && strlen(host) < strlen(keep)) snprintf(tmpl, strlen(keep), "%s", host);
    return fd;
}

int mkstemp(char* tmpl) {
    static int (*real)(char*) = nullptr;
    if (!real) real = (int (*)(char*))dlsym(RTLD_NEXT, "mkstemp");
    if (!real) { errno = ENOSYS; return -1; }
    char host[900];
    if (!host_path_of(tmpl, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("mkstemp", tmpl);
        return -1;
    }
    char keep[300];
    snprintf(keep, sizeof(keep), "%s", tmpl);
    int fd = real(host);
    // Подменяем tmpl на реальный путь, только если он помещается: иначе гость получил бы
    // ОБРЕЗАННЫЙ путь (и потом удалял бы несуществующий файл).
    if (fd >= 0 && strlen(host) < strlen(keep)) snprintf(tmpl, strlen(keep), "%s", host);
    return fd;
}

// ---------------------------------------------------------------- exec: гость не должен
// запустить ХОСТОВЫЙ /system/bin/init — переводим путь в rootfs.
int execve(const char* path, char* const argv[], char* const envp[]) {
    char host[800];
    const char* use = path;
    if (path && host_path_of(path, host, sizeof(host))) {
        plog("A10_Preload: execve %s -> %s", path, host);
        use = host;
    }
    return (int)syscall(__NR_execve, use, argv, envp);
}

int execv(const char* path, char* const argv[]) {
    char host[800];
    const char* use = path;
    if (path && host_path_of(path, host, sizeof(host))) {
        plog("A10_Preload: execv %s -> %s", path, host);
        use = host;
    }
    return (int)syscall(__NR_execve, use, argv, environ);
}

int chdir(const char* path) {
    char host[900];
    const Entry* e = lookup_mount(path ? path : "");
    if (e && strcmp(e->guest, "/") == 0) {
        plog("A10_Preload: chdir(/) -> %s (корень гостя)", e->host);
        return (int)syscall(__NR_chdir, e->host);
    }
    if (e) {
        snprintf(host, sizeof(host), "%s%s", e->host, path + strlen(e->guest));
        return (int)syscall(__NR_chdir, host);
    }
    return (int)syscall(__NR_chdir, path ? path : "");
}

// init делает clearenv() перед exec'ом второй стадии (selinux_setup) — восстанавливаем
// окружение гостя. БЕЗ восстановления LD_PRELOAD вторая стадия стартует БЕЗ нашей
// эмуляции и падает на SELinux (лог 14:55). Восстанавливаем ровно то, что было:
// никаких путей «по умолчанию» — только сохранённые значения.
int clearenv(void) {
    static int (*real)(void) = nullptr;
    if (!real) real = (int (*)(void))dlsym(RTLD_NEXT, "clearenv");
    int r = real ? real() : 0;
    if (g_preload[0]) setenv("LD_PRELOAD", g_preload, 1);
    if (g_console_env[0]) setenv("A10_CONSOLE_FD", g_console_env, 1);
    if (g_rootfs[0]) setenv("A10_ROOTFS", g_rootfs, 1);
    if (g_mounts_file[0]) setenv("A10_MOUNTS_FILE", g_mounts_file, 1);
    if (g_android_root[0]) setenv("ANDROID_ROOT", g_android_root, 1);
    if (g_ld_library_path[0]) setenv("LD_LIBRARY_PATH", g_ld_library_path, 1);
    if (g_path[0]) setenv("PATH", g_path, 1);
    return r;
}

// ---------------------------------------------------------------- SELinux: запись в ядро
// Сокет гостя, которого нет в гостевой ФС (logd гостя и прочие): подключение
// эмулируем успехом, а сообщения гостя печатаем сами. Сокетов ХОСТА не трогаем —
// ничего общего у хоста и гостя.
static bool guest_socket_exists(const char* sun_path) {
    if (!sun_path || sun_path[0] == '\0') return false;   // абстрактное имя: у нас таких нет
    char host[900];
    if (!host_path_of(sun_path, host, sizeof(host))) return false;
    struct stat st {};
    if (stat(host, &st) != 0) return false;
    return S_ISSOCK(st.st_mode);
}

int connect(int fd, const struct sockaddr* addr, socklen_t len) {
    REAL_FN(real, "connect", int, (int, const struct sockaddr*, socklen_t));
    // liblog гостя стучится в сокет logd, которого в гостевой ФС нет: протокол
    // несовместим с хостовым, сообщения терялись бы. Эмулируем подключение и печатаем
    // сообщения гостя сами.
    if (fd >= 0 && addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un* un = (const struct sockaddr_un*)addr;
        if (!guest_socket_exists(un->sun_path)) {
            mark_logfd(fd);
            plog("A10_Preload: connect %s -> эмулирован (сокета гостя нет)", un->sun_path);
            return 0;
        }
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, addr, len);
}

// Печать пакета гостя (в logd уходит бинарный формат — покажем читаемые байты).
static void dump_guest_log(const char* buf, size_t n) {
    char tmp[512];
    size_t len = n < sizeof(tmp) - 1 ? n : sizeof(tmp) - 1;
    size_t t = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        tmp[t++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    tmp[t] = '\0';
    char out[640];
    int m = snprintf(out, sizeof(out), "[guest-log] %s", tmp);
    if (m > 0) console_raw(out, (size_t)m);
}

ssize_t write(int fd, const void* buf, size_t count) {
    int kind = dev_kind_of_fd(fd);
    // Журнал ядра гостя (kmsg) -> консоль гостя.
    if (kind == DEVK_KMSG) {
        if (buf) guest_out("[guest kmsg]", 2, (const char*)buf, count);
        return (ssize_t)count;
    }
    // null/zero/full: данные не храним, запись успешна.
    if (kind == DEVK_NULL || kind == DEVK_FULL || kind == DEVK_ZERO) {
        return (ssize_t)count;
    }
    if (is_selinux_fd(fd)) {
        plog("A10_Preload: write to emulated selinuxfs fd=%d accepted (%zu bytes)", fd, count);
        return (ssize_t)count;
    }
    if ((is_logfd(fd) || (fd != g_console_fd && is_socket_fd(fd))) && buf) {
        dump_guest_log((const char*)buf, count);
    }
    if (fd <= 2) guest_out("[guest write]", fd, (const char*)buf, count);
    return (ssize_t)syscall(__NR_write, fd, buf, count);
}

// Устройства гостя: null/zero/full/random/urandom — эмуляция по номерам major/minor.
// К устройствам ХОСТА не обращаемся (ничего общего у хоста и гостя).
ssize_t read(int fd, void* buf, size_t count) {
    // Виртуальные файлы procfs гостя: содержимое эмулируем.
    int pk = proc_kind_of_fd(fd);
    if (pk != PROC_NONE) {
        char content[4096];
        ssize_t n = 0;
        if (pk == PROC_FILESYSTEMS) n = build_guest_filesystems(content, sizeof(content));
        else if (pk == PROC_MOUNTS) n = build_guest_mounts(content, sizeof(content));
        if (n <= 0) return 0;
        size_t cp = (size_t)n < count ? (size_t)n : count;
        memcpy(buf, content, cp);
        return (ssize_t)cp;
    }
    int kind = dev_kind_of_fd(fd);
    if (kind == DEVK_NULL || kind == DEVK_FULL || kind == DEVK_KMSG) {
        return 0;   // EOF
    }
    if (kind == DEVK_ZERO) {
        if (buf && count) memset(buf, 0, count);
        return (ssize_t)count;
    }
    if (kind == DEVK_RANDOM || kind == DEVK_URANDOM) {
        ssize_t r = (ssize_t)syscall(__NR_getrandom, buf, count, 0);
        if (r < 0) {
            if (buf && count) memset(buf, 0, count);
            r = (ssize_t)count;
        }
        return r;
    }
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    if (fd <= 2) {
        for (int i = 0; i < iovcnt; i++) {
            guest_out("[guest writev]", fd, (const char*)iov[i].iov_base, iov[i].iov_len);
        }
    }
    if (is_logfd(fd) || (fd != g_console_fd && is_socket_fd(fd))) {
        for (int i = 0; i < iovcnt; i++) dump_guest_log((const char*)iov[i].iov_base, iov[i].iov_len);
    }
    REAL_FN(real, "writev", ssize_t, (int, const struct iovec*, int));
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, iov, iovcnt);
}

// sendto/sendmsg — liblog может слать пакеты ими (а не write).
ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* addr,
               socklen_t addrlen) {
    REAL_FN(real, "sendto", ssize_t, (int, const void*, size_t, int, const struct sockaddr*, socklen_t));
    if ((is_logfd(fd) || (fd != g_console_fd && is_socket_fd(fd))) && buf) {
        dump_guest_log((const char*)buf, len);
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, buf, len, flags, addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr* msg, int flags) {
    REAL_FN(real, "sendmsg", ssize_t, (int, const struct msghdr*, int));
    if (is_logfd(fd) || (fd != g_console_fd && is_socket_fd(fd))) {
        if (msg && msg->msg_iov) {
            for (size_t i = 0; i < msg->msg_iovlen; i++) {
                dump_guest_log((const char*)msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
            }
        }
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, msg, flags);
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void* arg = va_arg(ap, void*);
    va_end(ap);
    if (is_selinux_fd(fd)) {
        plog("A10_Preload: ioctl on emulated selinuxfs fd=%d accepted", fd);
        return 0;
    }
    return (int)syscall(__NR_ioctl, fd, request, arg);
}

// restorecon не может выставить контекст на файлы гостя — эмулируем успех.
int lsetxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    plog("A10_Preload: lsetxattr %s (%s) emulated", path ? path : "?", name ? name : "?");
    return 0;
}
int setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    return lsetxattr(path, name, value, size, flags);
}
int fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    plog("A10_Preload: fsetxattr fd=%d (%s) emulated", fd, name ? name : "?");
    return 0;
}
int removexattr(const char* path, const char* name) { return 0; }

// ---------------------------------------------------------------- привилегированные вызовы
// На хосте их выполнить нельзя (нет CAP_SYS_ADMIN) — эмулируем успех с логом.
static int emulated_ok(const char* name, const char* detail) {
    plog("A10_Preload: %s%s%s emulated (нет прав на хосте) -> 0", name, detail ? " " : "",
         detail ? detail : "");
    return 0;
}

// Регистрация точки монтирования гостя в mount-таблице. Отсюда берётся и host-путь
// (корень гостя — запись "/" таблицы), и тип ФС (fs=<тип>). Изменения сохраняются
// в файл таблицы — их увидит и вторая стадия init'а.
static void register_guest_mount(const char* target, const char* fstype) {
    if (!target || target[0] != '/') return;
    const Entry* e = table_find_exact(target);
    char host[900];
    if (e) {
        snprintf(host, sizeof(host), "%s", e->host);
    } else {
        char root[700];
        if (!guest_root(root, sizeof(root))) return;
        snprintf(host, sizeof(host), "%s%s", root, target);
    }
    mkdir_p(host);

    char flags[256];
    snprintf(flags, sizeof(flags), "rw");
    if (fstype && *fstype) {
        char add[160];
        snprintf(add, sizeof(add), " fs=%s", fstype);
        strncat(flags, add, sizeof(flags) - strlen(flags) - 1);
        if (strcmp(fstype, "selinuxfs") == 0) {
            // Эмулированный selinuxfs: запись принимается, fstatfs отдаёт magic.
            snprintf(add, sizeof(add), " selinux magic=0x%lx", (unsigned long)SELINUX_MAGIC);
            strncat(flags, add, sizeof(flags) - strlen(flags) - 1);
        }
        if (strcmp(fstype, "proc") == 0) {
            // procfs гостя: файлы виртуальные (содержимое эмулируем).
            snprintf(add, sizeof(add), " procfs");
            strncat(flags, add, sizeof(flags) - strlen(flags) - 1);
        }
    }
    table_set(target, host, flags);
    table_save();

    // procfs гостя: создаём виртуальные файлы (init читает их и делает chmod /proc/cmdline).
    if (fstype && strcmp(fstype, "proc") == 0) {
        static const char* proc_files[] = {"cmdline", "filesystems", "mounts"};
        for (size_t i = 0; i < sizeof(proc_files) / sizeof(proc_files[0]); i++) {
            char fp[900];
            snprintf(fp, sizeof(fp), "%s/%s", host, proc_files[i]);
            int pfd = (int)syscall(__NR_openat, AT_FDCWD, fp,
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (pfd >= 0) syscall(__NR_close, pfd);
        }
        char selfdir[900];
        snprintf(selfdir, sizeof(selfdir), "%s/self", host);
        mkdir_p(selfdir);
    }

    plog("A10_Preload: mount %s -> точка гостя зарегистрирована (%s, %s)", target, host,
         fstype ? fstype : "?");
}

int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data) {
    (void)mountflags;
    (void)data;
    register_guest_mount(target, filesystemtype);
    char d[256];
    snprintf(d, sizeof(d), "%s->%s (%s)", source ? source : "?", target ? target : "?",
             filesystemtype ? filesystemtype : "?");
    return emulated_ok("mount", d);
}

int umount2(const char* target, int flags) { return emulated_ok("umount2", target); }

// Устройство гостя: регистрируем в таблице по номерам major/minor и создаём узел
// в гостевой ФС. Устройств ХОСТА не создаём и не используем.
int mknod(const char* path, mode_t mode, dev_t dev) {
    if (!path) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(path, host, sizeof(host))) {
        errno = EACCES;
        return -1;
    }
    int maj = (int)major(dev);
    int min = (int)minor(dev);
    char flags[128];
    flags[0] = 0;
    if (S_ISCHR(mode)) {
        snprintf(flags, sizeof(flags), "chr=%d:%d", maj, min);
    } else if (S_ISBLK(mode)) {
        snprintf(flags, sizeof(flags), "blk=%d:%d", maj, min);
    }
    table_set(path, host, flags);
    table_save();
    // Узел гостя — обычный файл в гостевой ФС (устройство эмулируется по номерам).
    // Старый симлинк на устройство ХОСТА (от прошлых прогонов) убираем — иначе
    // запись ушла бы в хостовое устройство (SELinux хоста это блокирует: EACCES).
    // Права 0666: гость пишет в него (kmsg, null).
    unlink(host);
    int fd = (int)syscall(__NR_openat, AT_FDCWD, host, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        syscall(__NR_fchmodat, AT_FDCWD, host, 0666, 0);
        syscall(__NR_close, fd);
    } else {
        plog("A10_Preload: mknod %s: узел не создан errno=%d (%s)", path, errno, strerror(errno));
    }
    plog("A10_Preload: mknod %s -> устройство гостя %d:%d (эмуляция)", path, maj, min);
    return 0;
}
int setgroups(size_t size, const gid_t* list) { return emulated_ok("setgroups", NULL); }
int setgid(gid_t gid) { return emulated_ok("setgid", NULL); }
int setuid(uid_t uid) { return emulated_ok("setuid", NULL); }
int setreuid(uid_t r, uid_t e) { return emulated_ok("setreuid", NULL); }
int setregid(gid_t r, gid_t e) { return emulated_ok("setregid", NULL); }
int setresuid(uid_t r, uid_t e, uid_t s) { return emulated_ok("setresuid", NULL); }
int setresgid(gid_t r, gid_t e, gid_t s) { return emulated_ok("setresgid", NULL); }
int setfsuid(uid_t u) { return emulated_ok("setfsuid", NULL); }
int setfsgid(gid_t g) { return emulated_ok("setfsgid", NULL); }
int capset(void* hdr, void* data) { return emulated_ok("capset", NULL); }
int reboot(int magic1, int magic2, int cmd, void* arg) { return emulated_ok("reboot", NULL); }
int swapon(const char* path, int flags) { return emulated_ok("swapon", path); }
int swapoff(const char* path) { return emulated_ok("swapoff", path); }
int settimeofday(const struct timeval* tv, const struct timezone* tz) { return emulated_ok("settimeofday", NULL); }
int clock_settime(clockid_t clk, const struct timespec* tp) { return emulated_ok("clock_settime", NULL); }
int sched_setscheduler(pid_t pid, int policy, const struct sched_param* param) { return emulated_ok("sched_setscheduler", NULL); }
int init_module(void* img, unsigned long len, const char* args) { return emulated_ok("init_module", NULL); }
int delete_module(const char* name, int flags) { return emulated_ok("delete_module", NULL); }
long kexec_load(unsigned long entry, unsigned long nr, void* seg, unsigned long flags) { return emulated_ok("kexec_load", NULL); }
int adjtimex(struct timex* txc) { return emulated_ok("adjtimex", NULL); }
int setpriority(int which, int who, int prio) { return emulated_ok("setpriority", NULL); }
int setpgid(pid_t pid, pid_t pgid) { return emulated_ok("setpgid", NULL); }
pid_t setsid(void) { return emulated_ok("setsid", NULL); }
int nice(int inc) { return emulated_ok("nice", NULL); }
int acct(const char* filename) { return emulated_ok("acct", NULL); }
int syslog(int type, char* buf, int len) { return emulated_ok("syslog", NULL); }
int chroot(const char* path) { return emulated_ok("chroot", path); }
long pivot_root(const char* nr, const char* po) { return emulated_ok("pivot_root", NULL); }
int sethostname(const char* name, size_t len) { return emulated_ok("sethostname", NULL); }
int setdomainname(const char* name, size_t len) { return emulated_ok("setdomainname", NULL); }

// statfs: честный ответ по переведённому пути; f_type — из флага "magic" записи
// таблицы (если он задан), иначе реальный тип ФС хоста.
int statfs(const char* path, struct statfs* buf) {
    if (!buf) { errno = EFAULT; return -1; }
    char host[900];
    const char* use = path;
    const Entry* e = lookup_mount(path ? path : "");
    if (e) {
        snprintf(host, sizeof(host), "%s%s", e->host, path + strlen(e->guest));
        use = host;
    }
    int r = (int)syscall(__NR_statfs, use ? use : "", buf);
    if (r == 0) {
        unsigned long mg = e ? magic_of(e) : 0;
        if (mg) {
            buf->f_type = (long)mg;
            plog("A10_Preload: statfs(%s) -> type=0x%lx (magic из mount-таблицы)",
                 path ? path : "?", mg);
        } else {
            plog("A10_Preload: statfs(%s) -> type=0x%lx", path ? path : "?",
                 (unsigned long)buf->f_type);
        }
    }
    return r;
}

// fstatfs: f_type — из флага "magic" mount'а, из которого получен fd (таблица).
// Раньше magic был зашит в коде (SELINUX_MAGIC) — теперь его задаёт таблица.
int fstatfs(int fd, struct statfs* buf) {
    REAL_FN(real, "fstatfs", int, (int, struct statfs*));
    if (!buf) { errno = EFAULT; return -1; }
    const Entry* e = mount_of_fd(fd);
    unsigned long mg = e ? magic_of(e) : 0;
    int r = real ? real(fd, buf) : (errno = ENOSYS, -1);
    if (r == 0 && mg) {
        buf->f_type = (long)mg;
        plog("A10_Preload: fstatfs(fd=%d) -> type=0x%lx (magic из mount-таблицы)", fd, mg);
    }
    return r;
}

// uname: гость ожидает Android.
int uname(struct utsname* buf) {
    if (!buf) { errno = EFAULT; return -1; }
    memset(buf, 0, sizeof(*buf));
    strncpy(buf->sysname, "Linux", sizeof(buf->sysname) - 1);
    strncpy(buf->nodename, "android", sizeof(buf->nodename) - 1);
    strncpy(buf->release, "3.18", sizeof(buf->release) - 1);
    strncpy(buf->version, "#1", sizeof(buf->version) - 1);
    strncpy(buf->machine, "aarch64", sizeof(buf->machine) - 1);
    return 0;
}

// ---------------------------------------------------------------- свойства
// Гость спрашивает свойства через bionic. Часть свойств эмулируем (гость без
// vendor-раздела: split-политики нет, SELinux целиком не перезагружается).
extern "C" int __system_property_get(const char* name, char* value) {
    static int (*real)(const char*, char*) = nullptr;
    if (!real) real = (int (*)(const char*, char*))dlsym(RTLD_NEXT, "__system_property_get");
    if (name && strcmp(name, "ro.boot.selinux") == 0) {
        if (value) { strcpy(value, "0"); return 0; }   // 1 = SELinux включен
        return 0;
    }
    if (!real) {
        if (value) value[0] = '\0';
        return 0;
    }
    return real(name, value);
}
