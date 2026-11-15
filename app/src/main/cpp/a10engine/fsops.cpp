#include "a10engine.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

// Префикс "/proc/self/fd/" = 14 символов. Гость (libselinux) узнаёт путь своего
// файла через readlink("/proc/self/fd/N") — без этого restorecon падал с ENOENT.
#define A10_PROC_FD_PREFIX "/proc/self/fd/"
#define A10_PROC_FD_PREFIX_LEN 14

// Гостевой путь файла, открываемого через open/openat: абсолютный — как есть,
// относительный — склеивается с путём каталога dirfd (путь каталога знаем из трекера).
static void a10_guest_path(int dirfd, const char* path, char* out, size_t outsz) {
    if (!path || !out || outsz == 0) return;
    out[0] = '\0';
    if (path[0] == '/') {
        snprintf(out, outsz, "%s", path);
        return;
    }
    const char* dp = (dirfd == AT_FDCWD) ? nullptr : track_path_of(dirfd);
    if (dp && *dp) {
        snprintf(out, outsz, "%s/%s", dp, path);
    } else {
        snprintf(out, outsz, "%s", path);
    }
}

// Подготовка виртуального содержимого виртуальных файлов procfs/selinuxfs гостя:
// помечаем fd и ГОТОВИМ содержимое один раз — read() выдаёт его по позиции.
static void a10_prepare_virtual(int fd, const char* path, const Entry* e) {
    if (fd < 0 || !e) return;
    if (!flag_present(e, "procfs") && !flag_present(e, "selinux")) return;
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    int pk = proc_kind_of_name(base);
    if (pk == PROC_NONE) return;
    track_set_proc(fd, pk);
    size_t cap = 262144;
    char* data = (char*)malloc(cap);
    size_t len = 0;
    if (data) {
        ssize_t n = 0;
        if (pk == PROC_FILESYSTEMS) n = build_guest_filesystems(data, cap);
        else if (pk == PROC_MOUNTS) n = build_guest_mounts(data, cap);
        else if (pk == PROC_CMDLINE) n = 0;
        else if (pk == SEL_ENFORCE) n = snprintf(data, cap, "0\n");
        else if (pk == SEL_STATUS) n = snprintf(data, cap, "permissive\n");
        else if (pk == SEL_CONTEXTS) n = build_guest_contexts(data, cap);
        len = n > 0 ? (size_t)n : 0;
    }
    track_set_virt(fd, data, len);
}

static int a10_open_common(int dirfd, const char* path, int flags, mode_t mode) {
    if (!path) { errno = EFAULT; return -1; }

    // /proc/self/fd/N гостя -> путь гостя по трекеру fd (у хоста это его путь).
    if (strncmp(path, A10_PROC_FD_PREFIX, A10_PROC_FD_PREFIX_LEN) == 0) {
        int n = atoi(path + A10_PROC_FD_PREFIX_LEN);
        const char* gp = track_path_of(n);
        if (!gp || !*gp) {
            errno = ENOENT;
            A10_FAIL("open", path);
            return -1;
        }
        path = gp;
    }
    const Entry* e = lookup_guest(path);
    const int idx = e ? (int)(e - g_mounts) : -1;

    // Гостевой путь (для /proc/self/fd/N и относительных openat).
    // ВНИМАНИЕ: наш собственный код (свойства гостя, файлы procfs) открывает файлы по
    // HOST-путям. Такие пути в трекер гостя попадать не должны: иначе относительный
    // open() гостя склеивается с host-путём каталога, и путь гостя «заражается».
    char gpath[A10_PATH_MAX];
    bool guest_path = !(g_rootfs[0] && strncmp(path, g_rootfs, strlen(g_rootfs)) == 0);
    if (guest_path) {
        a10_guest_path(dirfd, path, gpath, sizeof(gpath));
    } else {
        gpath[0] = '\0';
    }

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
        if (fd >= 0) {
            track_add(fd, idx, kind);
            if (guest_path) track_set_path(fd, gpath);
        }
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
            if (guest_path) track_set_path(fd, gpath);
            plog("A10_Preload: %s -> эмулированный selinuxfs (fd=%d, запись принимается)", path, fd);
        }
        return fd;
    }

    // Гость root: если файл уже есть, но прав на запись нет (создан с 0444/0000) —
    // расширяем права, иначе его open(O_RDWR) падает с EACCES.
    // ИСХОДНЫЙ режим запоминаем в реестре прав (modes.cpp): гостю в stat() показываем
    // именно его (propertyinfoparser требует, чтобы property_info НЕ был доступен на
    // запись группе/остальным), а реальный файл остаётся записываемым.
    if ((flags & (O_WRONLY | O_RDWR)) != 0) {
        struct stat st {};
        if (syscall(__NR_newfstatat, AT_FDCWD, use, &st, 0) == 0) {
            if ((st.st_mode & 0222) != 0222) {
                modes_record(gpath, st.st_mode);
                syscall(__NR_fchmodat, AT_FDCWD, use, 0664, 0);
                plog("A10_Preload: права на %s расширены до 0664 (гость root; исходные %o "
                     "запомнены)", use, st.st_mode & 07777);
            }
        }
    }

    int fd = (int)syscall(__NR_openat, dirfd, use, flags, mode);
    if (fd >= 0) {
        track_add(fd, idx, DEVK_PLAIN);
        if (guest_path) track_set_path(fd, gpath);
        a10_prepare_virtual(fd, path, e);
    }
    if (fd < 0) {
        // Диагностика: файл есть по faccessat, но openat даёт ENOENT — значит, путь
        // указывает не туда (симлинк/исчезновение). Показываем, что видим.
        struct stat sb {};
        int sres = (int)syscall(__NR_newfstatat, AT_FDCWD, use, &sb, 0);
        A10_FAIL("open", path);
        plog("A10_Preload:   open(%s) -> %s errno=%d; fstatat(%s)=%d size=%ld", path, use, errno,
             use, sres, sres == 0 ? (long)sb.st_size : -1L);
        return fd;
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
// ---------------------------------------------------------------- «владелец» файлов гостя
// Гость работает как root: его файлы принадлежат root (uid 0, gid 0) и не должны быть
// доступны на запись группе/остальным. Именно это проверяет гость при загрузке
// property_info (propertyinfoparser: PropertyInfoAreaFile::LoadPath):
//     st_uid == 0 && st_gid == 0 && !(st_mode & (S_IWGRP|S_IWOTH))
// Мы — обычное приложение (uid приложения), chown в 0:0 невозможен (нет CAP_CHOWN),
// поэтому подменяем значения в структуре, которую видит гость: его файлы выглядят
// как root-овые с правами 0644/0444.
// Права, которые гость должен видеть: исходные (из реестра) + root-владение.
static void a10_guest_mode(const char* guest_path, unsigned* mode) {
    unsigned orig = 0;
    if (guest_path && modes_lookup(guest_path, &orig)) {
        *mode = orig & 07777;
        return;
    }
    // Режима в реестре нет (файл расширили в прошлом прогоне) — убираем запись для
    // группы/остальных: настоящий root-гость таких прав не имеет.
    *mode &= ~(S_IWGRP | S_IWOTH);
}

static void a10_root_owned(struct stat* st) {
    st->st_uid = 0;
    st->st_gid = 0;
    unsigned m = st->st_mode;
    a10_guest_mode(nullptr, &m);
    st->st_mode = m;
}

static void a10_root_owned_path(struct stat* st, const char* guest_path) {
    st->st_uid = 0;
    st->st_gid = 0;
    unsigned m = st->st_mode;
    a10_guest_mode(guest_path, &m);
    st->st_mode = m;
}

static void a10_root_owned64(struct stat64* st) {
    st->st_uid = 0;
    st->st_gid = 0;
    unsigned m = st->st_mode;
    a10_guest_mode(nullptr, &m);
    st->st_mode = m;
}

static void a10_root_owned64_path(struct stat64* st, const char* guest_path) {
    st->st_uid = 0;
    st->st_gid = 0;
    unsigned m = st->st_mode;
    a10_guest_mode(guest_path, &m);
    st->st_mode = m;
}

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
    else a10_root_owned_path(st, pathname);
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
    else a10_root_owned_path(st, pathname);
    return r;
}

int fstat(int fd, struct stat* st) {
    if (!st) { errno = EFAULT; return -1; }
    int r = (int)syscall(__NR_fstat, fd, st);
    // Диагностика: размер файла, который гость собирается читать.
    static int n = 0;
    if (r == 0 && n < 30) {
        n++;
        plog("A10_Preload: fstat(fd=%d, %s) -> размер %lld", fd,
             track_path_of(fd) ? track_path_of(fd) : "?", (long long)st->st_size);
    }
    if (r == 0) a10_root_owned_path(st, track_path_of(fd));
    return r;
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
    else a10_root_owned_path(st, pathname);
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
    int r = real(host, st);
    if (r == 0) a10_root_owned64_path(st, pathname);
    return r;
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
    int r = real(host, st);
    if (r == 0) a10_root_owned64_path(st, pathname);
    return r;
}

int fstat64(int fd, struct stat64* st) {
    REAL_FN(real, "fstat64", int, (int, struct stat64*));
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(fd, st);
    static int n = 0;
    if (r == 0 && n < 30) {
        n++;
        plog("A10_Preload: fstat64(fd=%d, %s) -> размер %lld", fd,
             track_path_of(fd) ? track_path_of(fd) : "?", (long long)st->st_size);
    }
    if (r == 0) a10_root_owned64_path(st, track_path_of(fd));
    return r;
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
    int r = real(dirfd, host, st, flags);
    if (r == 0) a10_root_owned64_path(st, pathname);
    return r;
}

extern "C" int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* stx) {
    if (!stx) { errno = EFAULT; return -1; }
    char host[900];
    if (!host_path_of(pathname, host, sizeof(host))) {
        errno = ENOENT;
        A10_FAIL("statx", pathname);
        return -1;
    }
    int r = (int)syscall(__NR_statx, dirfd, host, flags, mask, stx);
    if (r < 0) {
        A10_FAIL("statx", pathname);
    } else {
        stx->stx_uid = 0;
        stx->stx_gid = 0;
        stx->stx_mode &= ~(S_IWGRP | S_IWOTH);
    }
    return r;
}

// Трассировка: печатаем только для mount'ов, помеченных в таблице (trace/selinux).
static bool traced_mount(const char* path) {
    const Entry* e = lookup_guest(path ? path : "");
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
    } else {
        // Файл гостя открыт через fopen: его fd надо знать (путь гостя) — иначе он
        // не отслеживается, и содержимое виртуальных файлов не подставляется.
        int fd = fileno(f);
        if (fd >= 0) {
            track_set_path(fd, pathname);
            const Entry* e = lookup_guest(pathname);
            a10_prepare_virtual(fd, pathname, e);
        }
        if (trace || trace_slot()) {
            plog("A10_Preload: fopen(%s) -> ok (fd=%d)", pathname ? pathname : "?", fd);
        }
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
    if (r < 0) {
        A10_FAIL("unlink", pathname);
    } else {
        plog("A10_Preload: unlink(%s) ok", pathname ? pathname : "?");
    }
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
    if (r < 0) {
        A10_FAIL("unlinkat", pathname);
    } else {
        plog("A10_Preload: unlinkat(%s) ok", pathname ? pathname : "?");
    }
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

    // /proc/self/fd/N гостя: отдаём ПУТЬ ГОСТЯ (не хостовый). Гость узнаёт так свой
    // путь (libselinux -> restorecon). Хостовый /proc/self/fd/N показывал бы путь
    // телефона — это shared и не совпало бы с контекстами гостя.
    if (pathname && strncmp(pathname, A10_PROC_FD_PREFIX, A10_PROC_FD_PREFIX_LEN) == 0) {
        int n = atoi(pathname + A10_PROC_FD_PREFIX_LEN);
        const char* gp = track_path_of(n);
        if (gp && *gp) {
            size_t len = strlen(gp);
            if (len > bufsiz) len = bufsiz;
            memcpy(buf, gp, len);
            plog("A10_Preload: readlink(%s) -> %s", pathname, gp);
            return (ssize_t)len;
        }
        // fd не отслежен — берём реальный путь и переводим его в гостевой (корень гостя).
        char hfd[64];
        snprintf(hfd, sizeof(hfd), "/proc/self/fd/%d", n);
        char hbuf[A10_PATH_MAX];
        if (real) {
            ssize_t hr = real(hfd, hbuf, sizeof(hbuf) - 1);
            if (hr > 0) {
                hbuf[hr] = '\0';
                size_t rl = strlen(g_rootfs);
                if (g_rootfs[0] && strncmp(hbuf, g_rootfs, rl) == 0) {
                    const char* g = hbuf + rl;
                    if (*g == '\0') g = "/";
                    size_t len = strlen(g);
                    if (len > bufsiz) len = bufsiz;
                    memcpy(buf, g, len);
                    plog("A10_Preload: readlink(%s) -> %s (переведён из хоста)", pathname, g);
                    return (ssize_t)len;
                }
            }
        }
        errno = ENOENT;
        A10_FAIL("readlink", pathname);
        return -1;
    }

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
    // Уже переведённый (host) путь внутри гостевой ФС — chmod прямо по нему.
    if (g_rootfs[0] && pathname && strncmp(pathname, g_rootfs, strlen(g_rootfs)) == 0) {
        int r = (int)syscall(__NR_fchmodat, AT_FDCWD, pathname, mode);
        if (r < 0) A10_FAIL("chmod", pathname);
        return r;
    }
    const Entry* e = lookup_guest(pathname ? pathname : "");
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
    // Гость root: chown для него всегда успешен (у нас нет CAP_CHOWN).
    plog("A10_Preload: chown(%s, %u, %u) -> ok (эмуляция: гость root)", pathname ? pathname : "?",
         (unsigned)owner, (unsigned)group);
    return 0;
}

int lchown(const char* pathname, uid_t owner, gid_t group) {
    // Гость root: chown для него всегда успешен.
    plog("A10_Preload: lchown(%s, %u, %u) -> ok (эмуляция: гость root)", pathname ? pathname : "?",
         (unsigned)owner, (unsigned)group);
    return 0;
}

int fchown(int fd, uid_t owner, gid_t group) {
    // Гость root: смена владельца для него успешна.
    plog("A10_Preload: fchown(fd=%d, %u, %u) -> ok (эмуляция: гость root)", fd, (unsigned)owner,
         (unsigned)group);
    return 0;
}

extern "C" int fchownat(int dirfd, const char* pathname, uid_t owner, gid_t group, int flags) {
    plog("A10_Preload: fchownat(%s, %u, %u) -> ok (эмуляция: гость root)",
         pathname ? pathname : "?", (unsigned)owner, (unsigned)group);
    return 0;
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
