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
//   * пути гостя переводятся в пути хоста: /system,/vendor,/product,/dev,/data,/mnt,...
//     -> <rootfs>/... (A10_ROOTFS). /proc и /sys остаются реальными (настоящее ядро);
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

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
static char g_policy[600];   // эмулированная SELinux-политика гостя (<rootfs>/sepolicy)
// Сохраняем окружение гостя: init первой стадии делает clearenv() — без восстановления
// LD_PRELOAD вторая стадия (selinux_setup) стартовала БЕЗ нашей эмуляции (лог 14:55).
static char g_preload[1024];
static char g_console_env[64];
static char g_android_root[512];
static char g_ld_library_path[1024];

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

// ---------------------------------------------------------------- перевод путей
// Корни гостевой ФС: всё, что принадлежит гостю, живёт в <rootfs>.
// /proc и /sys НЕ переводятся — это настоящее ядро хоста (те же pid/устройства).
static const char* kGuestRoots[] = {
    "/system", "/vendor", "/product", "/apex", "/odm", "/oem", "/system_root",
    "/dev", "/data", "/mnt", "/cache", "/metadata", "/sdcard", "/storage",
    "/first_stage_ramdisk", "/debug_ramdisk", "/sepolicy",
};

static bool is_guest_root(const char* p) {
    for (size_t i = 0; i < sizeof(kGuestRoots) / sizeof(kGuestRoots[0]); i++) {
        const char* pre = kGuestRoots[i];
        size_t n = strlen(pre);
        if (strncmp(p, pre, n) == 0 && (p[n] == '\0' || p[n] == '/')) return true;
    }
    return false;
}

// guest path -> host path. Возвращает true, если путь был переведён.
static bool translate(const char* p, char* out, size_t outsz) {
    if (!p || p[0] != '/' || g_rootfs[0] == '\0') return false;
    if (!is_guest_root(p)) return false;
    snprintf(out, outsz, "%s%s", g_rootfs, p);
    return true;
}

// ---------------------------------------------------------------- конструктор
static void __attribute__((constructor)) a10preload_init(void) {
    const char* cf = getenv("A10_CONSOLE_FD");
    if (cf && *cf) g_console_fd = atoi(cf);
    const char* rf = getenv("A10_ROOTFS");
    if (rf && *rf) snprintf(g_rootfs, sizeof(g_rootfs), "%s", rf);
    snprintf(g_policy, sizeof(g_policy), "%s/sepolicy", g_rootfs);

    // Запоминаем переменные, которые init сотрёт через clearenv().
    const char* pv = getenv("LD_PRELOAD");
    if (pv) snprintf(g_preload, sizeof(g_preload), "%s", pv);
    if (cf && *cf) snprintf(g_console_env, sizeof(g_console_env), "%s", cf);
    const char* ar = getenv("ANDROID_ROOT");
    if (ar) snprintf(g_android_root, sizeof(g_android_root), "%s", ar);
    const char* llp = getenv("LD_LIBRARY_PATH");
    if (llp) snprintf(g_ld_library_path, sizeof(g_ld_library_path), "%s", llp);

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

// Отслеживаемые fd: 1 = selinuxfs (запись в ядро эмулируется).
#define A10_TRACK_MAX 64
static int g_track_fd[A10_TRACK_MAX];
static int g_track_kind[A10_TRACK_MAX];

static void track_add(int fd, int kind) {
    if (fd < 0) return;
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == 0) {
            g_track_fd[i] = fd;
            g_track_kind[i] = kind;
            return;
        }
    }
}

static bool is_selinux_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd && g_track_kind[i] == 1) return true;
    }
    return false;
}

// ---------------------------------------------------------------- эмуляция SELinux
static bool is_selinux_path(const char* p) {
    return p && strncmp(p, "/sys/fs/selinux", 14) == 0;
}

// Путь с политикой: монолитный /sepolicy гостя (его собрал стаб из его же CIL).
// Прекомпилированная политика гостя (/system/etc/selinux/precompiled_sepolicy) читается
// как обычный файл — перехватывать её не нужно.
static bool is_policy_path(const char* p) {
    return p && strcmp(p, "/sepolicy") == 0;
}

// ---------------------------------------------------------------- ФС: открытие
// /dev/kmsg и /dev/console -> консольный pipe (логи init в A10_Guest).
static int open_console_redirect(const char* pathname) {
    if (g_console_fd < 0 || !pathname) return -1;
    if (strcmp(pathname, "/dev/kmsg") == 0 || strcmp(pathname, "/dev/console") == 0) {
        int fd = fcntl(g_console_fd, F_DUPFD, 3);
        if (fd >= 0) {
            plog("A10_Preload: %s -> console pipe fd=%d (init klog captured)", pathname, fd);
            return fd;
        }
        return -1;
    }
    return -1;
}

static int a10_open_common(int dirfd, const char* path, int flags, mode_t mode) {
    if (!path) { errno = EFAULT; return -1; }
    int r = open_console_redirect(path);
    if (r >= 0) return r;

    // Эмулированная политика SELinux: отдаём гостю файл, который заготовил стаб.
    if (is_policy_path(path) && g_policy[0]) {
        int fd = (int)syscall(__NR_openat, AT_FDCWD, g_policy, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) return fd;
    }

    // selinuxfs на хосте закрыт для записи, но ЧИТАТЬ его можно. Открываем настоящий
    // /sys/fs/selinux/<name> (тогда fstatfs даст SELINUX_MAGIC и libselinux согласится
    // грузить политику), а запись в него считаем успешной (write() по отмеченным fd).
    if (is_selinux_path(path)) {
        int fd = (int)syscall(__NR_openat, AT_FDCWD, path, flags & ~O_CREAT, mode);
        if (fd < 0) {
            fd = (int)syscall(__NR_openat, AT_FDCWD, "/dev/null", O_RDWR, 0);
        }
        if (fd >= 0) {
            track_add(fd, 1);
            plog("A10_Preload: %s -> emulated selinuxfs (fd=%d, запись принимается)", path, fd);
        }
        return fd;
    }

    char host[800];
    const char* use = path;
    if (translate(path, host, sizeof(host))) use = host;
    return (int)syscall(__NR_openat, dirfd, use, flags, mode);
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
int stat(const char* pathname, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_newfstatat, AT_FDCWD, use ? use : "", st, 0);
}

int lstat(const char* pathname, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_newfstatat, AT_FDCWD, use ? use : "", st, AT_SYMLINK_NOFOLLOW);
}

int fstat(int fd, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    return (int)syscall(__NR_fstat, fd, st);
}

int fstatat(int dirfd, const char* pathname, struct stat* st, int flags) {
    if (!st) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_newfstatat, dirfd, use ? use : "", st, flags);
}

// LFS-алиасы статистики — на LP64 struct stat64 совпадает с struct stat.
int stat64(const char* pathname, struct stat64* st) {
    REAL_FN(real, "stat64", int, (const char*, struct stat64*));
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    if (!real) { errno = ENOSYS; return -1; }
    return real(use ? use : "", st);
}

int lstat64(const char* pathname, struct stat64* st) {
    REAL_FN(real, "lstat64", int, (const char*, struct stat64*));
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    if (!real) { errno = ENOSYS; return -1; }
    return real(use ? use : "", st);
}

int fstat64(int fd, struct stat64* st) {
    REAL_FN(real, "fstat64", int, (int, struct stat64*));
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, st);
}

int fstatat64(int dirfd, const char* pathname, struct stat64* st, int flags) {
    REAL_FN(real, "fstatat64", int, (int, const char*, struct stat64*, int));
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    if (!real) { errno = ENOSYS; return -1; }
    return real(dirfd, use ? use : "", st, flags);
}

int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* stx) {
    if (!stx) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_statx, dirfd, use ? use : "", flags, mask, stx);
}

int access(const char* pathname, int mode) {
    if (!pathname) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = pathname;
    if (translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_faccessat, AT_FDCWD, use, mode);
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
// Запись разрешена только внутрь гостевого rootfs и в /proc,/sys (виртуальные ФС ядра).
static bool writable_target(const char* pathname, char* host, size_t hostsz) {
    if (!pathname) return false;
    if (translate(pathname, host, hostsz)) return true;
    if (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0) return true;
    return false;
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
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) { errno = EACCES; return -1; }
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(dirfd, host, mode);
    if (r < 0 && errno == EEXIST) return 0;
    return r;
}

int rmdir(const char* pathname) {
    REAL_FN(real, "rmdir", int, (const char*));
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) { errno = EACCES; return -1; }
    if (!real) { errno = ENOSYS; return -1; }
    return real(host);
}

int unlink(const char* pathname) {
    REAL_FN(real, "unlink", int, (const char*));
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) { errno = EACCES; return -1; }
    if (!real) { errno = ENOSYS; return -1; }
    return real(host);
}

int unlinkat(int dirfd, const char* pathname, int flags) {
    REAL_FN(real, "unlinkat", int, (int, const char*, int));
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) { errno = EACCES; return -1; }
    if (!real) { errno = ENOSYS; return -1; }
    return real(dirfd, host, flags);
}

int rename(const char* oldpath, const char* newpath) {
    REAL_FN(real, "rename", int, (const char*, const char*));
    char ho[800], hn[800];
    if (!writable_target(oldpath, ho, sizeof(ho)) || !writable_target(newpath, hn, sizeof(hn))) {
        errno = EACCES;
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(ho, hn);
}

int symlink(const char* target, const char* linkpath) {
    REAL_FN(real, "symlink", int, (const char*, const char*));
    char host[800];
    if (!writable_target(linkpath, host, sizeof(host))) { errno = EACCES; return -1; }
    if (!real) { errno = ENOSYS; return -1; }
    return real(target, host);
}

int link(const char* oldpath, const char* newpath) {
    REAL_FN(real, "link", int, (const char*, const char*));
    char ho[800], hn[800];
    if (!writable_target(oldpath, ho, sizeof(ho)) || !writable_target(newpath, hn, sizeof(hn))) {
        errno = EACCES;
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(ho, hn);
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz) {
    REAL_FN(real, "readlink", ssize_t, (const char*, char*, size_t));
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    if (!real) { errno = ENOSYS; return -1; }
    return real(use ? use : "", buf, bufsiz);
}

int chmod(const char* pathname, mode_t mode) {
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) {
        use = host;
    } else if (pathname && (strncmp(pathname, "/proc/", 6) == 0 || strncmp(pathname, "/sys/", 5) == 0)) {
        plog("A10_Preload: chmod %s emulated (ядро не даёт chmod)", pathname);
        return 0;
    }
    return (int)syscall(__NR_fchmodat, AT_FDCWD, use ? use : "", mode);
}

int fchmodat(int dirfd, const char* pathname, mode_t mode, int flags) {
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) use = host;
    return (int)syscall(__NR_fchmodat, dirfd, use ? use : "", mode, flags);
}

int chown(const char* pathname, uid_t owner, gid_t group) {
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) {
        use = host;
    } else {
        plog("A10_Preload: chown %s emulated", pathname ? pathname : "?");
        return 0;
    }
    return (int)syscall(__NR_fchownat, AT_FDCWD, use, owner, group, 0);
}

int lchown(const char* pathname, uid_t owner, gid_t group) {
    char host[800];
    const char* use = pathname;
    if (pathname && translate(pathname, host, sizeof(host))) {
        use = host;
    } else {
        return 0;
    }
    return (int)syscall(__NR_fchownat, AT_FDCWD, use, owner, group, AT_SYMLINK_NOFOLLOW);
}

int fchown(int fd, uid_t owner, gid_t group) {
    return (int)syscall(__NR_fchown, fd, owner, group);
}

int truncate(const char* pathname, off_t length) {
    char host[800];
    if (!writable_target(pathname, host, sizeof(host))) { errno = EACCES; return -1; }
    return (int)syscall(__NR_truncate, host, length);
}

DIR* opendir(const char* name) {
    static DIR* (*real)(const char*) = nullptr;
    if (!real) real = (DIR* (*)(const char*))dlsym(RTLD_NEXT, "opendir");
    if (!real) { errno = ENOSYS; return nullptr; }
    char host[800];
    const char* use = name;
    if (name && translate(name, host, sizeof(host))) use = host;
    return real(use);
}

// Временные файлы гостя (например /dev/sepolicy.XXXXXX) создаём в гостевой ФС.
int mkostemp(char* tmpl, int flags) {
    static int (*real)(char*, int) = nullptr;
    if (!real) real = (int (*)(char*, int))dlsym(RTLD_NEXT, "mkostemp");
    if (!real) { errno = ENOSYS; return -1; }
    char host[800];
    char keep[300];
    snprintf(keep, sizeof(keep), "%s", tmpl);
    if (translate(tmpl, host, sizeof(host))) {
        int fd = real(host, flags);
        if (fd >= 0) snprintf(tmpl, strlen(keep) + 1, "%s", host);
        return fd;
    }
    return real(tmpl, flags);
}

int mkstemp(char* tmpl) {
    static int (*real)(char*) = nullptr;
    if (!real) real = (int (*)(char*))dlsym(RTLD_NEXT, "mkstemp");
    if (!real) { errno = ENOSYS; return -1; }
    char host[800];
    char keep[300];
    snprintf(keep, sizeof(keep), "%s", tmpl);
    if (translate(tmpl, host, sizeof(host))) {
        int fd = real(host);
        if (fd >= 0) snprintf(tmpl, strlen(keep) + 1, "%s", host);
        return fd;
    }
    return real(tmpl);
}

// ---------------------------------------------------------------- exec: гость не должен
// запустить ХОСТОВЫЙ /system/bin/init — переводим путь в rootfs.
int execve(const char* path, char* const argv[], char* const envp[]) {
    char host[800];
    const char* use = path;
    if (path && translate(path, host, sizeof(host))) {
        plog("A10_Preload: execve %s -> %s", path, host);
        use = host;
    }
    return (int)syscall(__NR_execve, use, argv, envp);
}

int execv(const char* path, char* const argv[]) {
    char host[800];
    const char* use = path;
    if (path && translate(path, host, sizeof(host))) {
        plog("A10_Preload: execv %s -> %s", path, host);
        use = host;
    }
    return (int)syscall(__NR_execve, use, argv, environ);
}

int chdir(const char* path) {
    if (path && strcmp(path, "/") == 0 && g_rootfs[0]) {
        plog("A10_Preload: chdir(/) -> %s (корень гостя)", g_rootfs);
        return (int)syscall(__NR_chdir, g_rootfs);
    }
    char host[800];
    const char* use = path;
    if (path && translate(path, host, sizeof(host))) use = host;
    return (int)syscall(__NR_chdir, use ? use : "");
}

// init делает clearenv() перед exec'ом второй стадии (selinux_setup) — восстанавливаем
// окружение гостя. БЕЗ восстановления LD_PRELOAD вторая стадия стартует БЕЗ нашей
// эмуляции и падает на SELinux (лог 14:55).
int clearenv(void) {
    static int (*real)(void) = nullptr;
    if (!real) real = (int (*)(void))dlsym(RTLD_NEXT, "clearenv");
    int r = real ? real() : 0;
    if (g_preload[0]) setenv("LD_PRELOAD", g_preload, 1);
    if (g_console_env[0]) setenv("A10_CONSOLE_FD", g_console_env, 1);
    if (g_rootfs[0]) setenv("A10_ROOTFS", g_rootfs, 1);
    if (g_android_root[0]) setenv("ANDROID_ROOT", g_android_root, 1);
    if (g_rootfs[0]) {
        char libs[900];
        snprintf(libs, sizeof(libs),
                 "LD_LIBRARY_PATH=%s/system/lib64:%s/system/lib:%s/lib64:%s/lib:%s/vendor/lib64:%s/vendor/lib",
                 g_rootfs, g_rootfs, g_rootfs, g_rootfs, g_rootfs, g_rootfs);
        setenv("LD_LIBRARY_PATH", libs + strlen("LD_LIBRARY_PATH="), 1);
    } else if (g_ld_library_path[0]) {
        setenv("LD_LIBRARY_PATH", g_ld_library_path, 1);
    }
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin", 1);
    return r;
}

// ---------------------------------------------------------------- SELinux: запись в ядро
ssize_t write(int fd, const void* buf, size_t count) {
    if (is_selinux_fd(fd)) {
        plog("A10_Preload: write to emulated selinuxfs fd=%d accepted (%zu bytes)", fd, count);
        return (ssize_t)count;
    }
    if (fd <= 2) guest_out("[guest write]", fd, (const char*)buf, count);
    return (ssize_t)syscall(__NR_write, fd, buf, count);
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    if (fd <= 2) {
        for (int i = 0; i < iovcnt; i++) {
            guest_out("[guest writev]", fd, (const char*)iov[i].iov_base, iov[i].iov_len);
        }
    }
    REAL_FN(real, "writev", ssize_t, (int, const struct iovec*, int));
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, iov, iovcnt);
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

int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data) {
    char host[800];
    if (target && translate(target, host, sizeof(host))) mkdir_p(host);
    char d[256];
    snprintf(d, sizeof(d), "%s->%s (%s)", source ? source : "?", target ? target : "?",
             filesystemtype ? filesystemtype : "?");
    return emulated_ok("mount", d);
}

int umount2(const char* target, int flags) { return emulated_ok("umount2", target); }
int mknod(const char* path, mode_t mode, dev_t dev) {
    char host[800];
    const char* use = path;
    if (path && translate(path, host, sizeof(host))) use = host;
    // Узел хоста уже есть (/dev/null, /dev/kmsg...) — эмулируем успех.
    if (use && syscall(__NR_faccessat, AT_FDCWD, use, F_OK, 0) == 0) {
        plog("A10_Preload: mknod %s ok (узел есть)", path ? path : "?");
        return 0;
    }
    plog("A10_Preload: mknod %s emulated (узла нет)", path ? path : "?");
    return 0;
}int setgroups(size_t size, const gid_t* list) { return emulated_ok("setgroups", NULL); }
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

// statfs: честный ответ по переведённому пути (без выдуманных типов ФС).
int statfs(const char* path, struct statfs* buf) {
    if (!buf) { errno = EFAULT; return -1; }
    char host[800];
    const char* use = path;
    if (path && translate(path, host, sizeof(host))) use = host;
    int r = (int)syscall(__NR_statfs, use ? use : "", buf);
    if (r == 0) plog("A10_Preload: statfs(%s) -> type=0x%lx", path ? path : "?",
                     (unsigned long)buf->f_type);
    return r;
}

// fstatfs: для эмулированного selinuxfs отдаём SELINUX_MAGIC. Иначе libselinux
// (проверка is_selinuxfs(fd)) не признаёт наш /dev/null selinuxfs и отказывается
// грузить политику -> "Unable to load SELinux policy" (лог 15:34).
int fstatfs(int fd, struct statfs* buf) {
    REAL_FN(real, "fstatfs", int, (int, struct statfs*));
    if (is_selinux_fd(fd)) {
        if (!buf) { errno = EFAULT; return -1; }
        memset(buf, 0, sizeof(*buf));
        buf->f_type = 0xf97cff8c;   // SELINUX_MAGIC
        buf->f_bsize = 4096;
        buf->f_namelen = 255;
        return 0;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, buf);
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
        if (value) { strcpy(value, "1"); return 1; }   // 1 = SELinux отключён
        return 0;
    }
    if (!real) {
        if (value) value[0] = '\0';
        return 0;
    }
    return real(name, value);
}
