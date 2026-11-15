#include "a10engine.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

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

void install_sigsys_handler() {
    struct sigaction sa {};
    sa.sa_sigaction = a10_preload_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) == 0) {
        plog("a10preload.so: SIGSYS-handler установлен (внутри init'а)");
    }
}

// Виртуальные файлы procfs/selinuxfs ГОСТЯ: содержимое эмулируется (procfs/selinuxfs
// хоста — это shared, гостю он не принадлежит). Перечень видов (enum ProcKind) — в a10engine.h.

// Список SELinux-контекстов гостя: собирается из ГОСТЕВЫХ файлов "*_contexts"
//// (file/service/property/hwservice/seapp) в гостевой ФС. Данные хоста не используются.
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
    const Entry* e = lookup_guest(path ? path : "");
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
ssize_t write(int fd, const void* buf, size_t count) {
    int kind = dev_kind_of_fd(fd);
    // Журнал ядра гостя (kmsg) -> консоль гостя.
    if (kind == DEVK_KMSG) {
        guest_kmsg_out(fd, (const char*)buf, count);
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
    // Трассировка обычных записей гостя (первые N): видно, что он пишет в property_info
    // и в persistent properties. Пишем СНАЧАЛА, потом логируем результат.
    if (fd > 2) {
        ssize_t wr = (ssize_t)syscall(__NR_write, fd, buf, count);
        if (wr < 0) {
            A10_FAIL("write", track_path_of(fd));
        } else if (trace_slot()) {
            plog("A10_Preload: write(fd=%d, %zu байт) -> %zd", fd, count, wr);
        }
        // Диагностика: итоговый размер файла после записи (отдельный счётчик).
        static int writes = 0;
        if (writes < 25) {
            writes++;
            struct stat wst {};
            long fsz = (syscall(__NR_fstat, fd, &wst) == 0) ? (long)wst.st_size : -1L;
            plog("A10_Preload: write #%d: fd=%d (%s) %zd байт, размер файла = %ld", writes, fd,
                 track_path_of(fd) ? track_path_of(fd) : "?", wr, fsz);
        }
        return wr;
    }
    return (ssize_t)syscall(__NR_write, fd, buf, count);
}

// pread: гость читает файлы и через него (в обход read — мимо трассировки).
ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    REAL_FN(real, "pread", ssize_t, (int, void*, size_t, off_t));
    static int n = 0;
    ssize_t r = real ? real(fd, buf, count, offset) : -1;
    if (n < 15) {
        n++;
        plog("A10_Preload: pread(fd=%d, %s, %zu) -> %zd", fd,
             track_path_of(fd) ? track_path_of(fd) : "?", count, r);
    }
    return r;
}

// ftruncate/mmap: property_info готовится через них (AOSP).
int ftruncate(int fd, off_t length) {
    static int (*real)(int, off_t) = nullptr;
    if (!real) real = (int (*)(int, off_t))dlsym(RTLD_NEXT, "ftruncate");
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(fd, length);
    plog("A10_Preload: ftruncate(fd=%d, %ld) -> %d (errno=%d)", fd, (long)length, r,
         r < 0 ? errno : 0);
    return r;
}

void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset) {
    static void* (*real)(void*, size_t, int, int, int, off_t) = nullptr;
    if (!real) real = (void* (*)(void*, size_t, int, int, int, off_t))dlsym(RTLD_NEXT, "mmap");
    if (!real) { errno = ENOSYS; return MAP_FAILED; }
    void* p = real(addr, len, prot, flags, fd, offset);
    // Диагностика: отображение ФАЙЛА (гость читает файлы через mmap — обойти read()).
    static int maps = 0;
    if (fd >= 0 && maps < 25) {
        maps++;
        plog("A10_Preload: mmap(len=%zu, fd=%d, %s) -> %s", len, fd,
             track_path_of(fd) ? track_path_of(fd) : "?", p == MAP_FAILED ? "ОШИБКА" : "ok");
    }
    if (p == MAP_FAILED) {
        A10_FAIL("mmap", track_path_of(fd));
    } else if (trace_slot()) {
        plog("A10_Preload: mmap(len=%zu, fd=%d) -> ok", len, fd);
    }
    return p;
}

// Устройства гостя: null/zero/full/random/urandom — эмуляция по номерам major/minor.
// К устройствам ХОСТА не обращаемся (ничего общего у хоста и гостя).
// ВАЖНО: прототип как в bionic — int request (иначе конфликт с <sys/ioctl.h>).
// Код ioctl в ядре 32-битный, поэтому знаковое расширение безвредно.
extern "C" int ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void* arg = va_arg(ap, void*);
    va_end(ap);
    unsigned int req = (unsigned int)request;
    if (is_selinux_fd(fd)) {
        // Эмулированный selinuxfs гостя (политика в ядро ХОСТА не грузится — это было бы
        // shared с телефоном; гостю отдаём собственные ответы).
        //   SECURITY_CTX_TO_SID = 1: гость просит SID контекста -> отдаём свой SID;
        //   SECURITY_SID_TO_CTX = 2: обратное преобразование.
        if (req == 1 && arg) {
            // SECURITY_CTX_TO_SID: arg = указатель на строку-контекст, результат ioctl = SID.
            const char* ctx = *(const char* const*)arg;
            long sid = (long)guest_sid_for(ctx);
            plog("A10_Preload: ioctl(selinuxfs, CTX_TO_SID) -> sid=%ld", sid);
            return (int)sid;
        }
        if (req == 2 && arg) {
            struct SelinuxSidToCtx {
                char* ctx;
                uint32_t len;
            };
            SelinuxSidToCtx* p = (SelinuxSidToCtx*)arg;
            if (p && p->ctx && p->len) {
                const char* c = guest_ctx_for_sid((int)(uintptr_t)p->len);
                size_t n = strlen(c) + 1;
                if (n > p->len) n = p->len;
                memcpy(p->ctx, c, n);
            }
            return 0;
        }
        plog("A10_Preload: ioctl on emulated selinuxfs fd=%d request=%u accepted", fd, req);
        return 0;
    }
    return (int)syscall(__NR_ioctl, fd, req, arg);
}

// restorecon не может выставить контекст на файлы гостя — эмулируем успех.
extern "C" int lsetxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    plog("A10_Preload: lsetxattr %s (%s) emulated", path ? path : "?", name ? name : "?");
    return 0;
}
extern "C" int setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    return lsetxattr(path, name, value, size, flags);
}
extern "C" int fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    plog("A10_Preload: fsetxattr fd=%d (%s) emulated", fd, name ? name : "?");
    return 0;
}
extern "C" int removexattr(const char* path, const char* name) { return 0; }

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

extern "C" int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data) {
    (void)mountflags;
    (void)data;
    register_guest_mount(target, filesystemtype);
    char d[256];
    snprintf(d, sizeof(d), "%s->%s (%s)", source ? source : "?", target ? target : "?",
             filesystemtype ? filesystemtype : "?");
    return emulated_ok("mount", d);
}

extern "C" int umount2(const char* target, int flags) { return emulated_ok("umount2", target); }

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
extern "C" int setfsuid(uid_t u) { return emulated_ok("setfsuid", NULL); }
extern "C" int setfsgid(gid_t g) { return emulated_ok("setfsgid", NULL); }
extern "C" int capset(void* hdr, void* data) { return emulated_ok("capset", NULL); }
extern "C" int reboot(int magic1, int magic2, int cmd, void* arg) { return emulated_ok("reboot", NULL); }
extern "C" int swapon(const char* path, int flags) { return emulated_ok("swapon", path); }
extern "C" int swapoff(const char* path) { return emulated_ok("swapoff", path); }
extern "C" int settimeofday(const struct timeval* tv, const struct timezone* tz) { return emulated_ok("settimeofday", NULL); }
extern "C" int clock_settime(clockid_t clk, const struct timespec* tp) { return emulated_ok("clock_settime", NULL); }
extern "C" int sched_setscheduler(pid_t pid, int policy, const struct sched_param* param) { return emulated_ok("sched_setscheduler", NULL); }
extern "C" int init_module(void* img, unsigned long len, const char* args) { return emulated_ok("init_module", NULL); }
extern "C" int delete_module(const char* name, int flags) { return emulated_ok("delete_module", NULL); }
extern "C" long kexec_load(unsigned long entry, unsigned long nr, void* seg, unsigned long flags) { return emulated_ok("kexec_load", NULL); }
extern "C" int adjtimex(struct timex* txc) { return emulated_ok("adjtimex", NULL); }
extern "C" int setpriority(int which, int who, int prio) { return emulated_ok("setpriority", NULL); }
int setpgid(pid_t pid, pid_t pgid) { return emulated_ok("setpgid", NULL); }
pid_t setsid(void) { return emulated_ok("setsid", NULL); }
int nice(int inc) { return emulated_ok("nice", NULL); }
int acct(const char* filename) { return emulated_ok("acct", NULL); }
extern "C" int syslog(int type, char* buf, int len) { return emulated_ok("syslog", NULL); }
int chroot(const char* path) { return emulated_ok("chroot", path); }
extern "C" long pivot_root(const char* nr, const char* po) { return emulated_ok("pivot_root", NULL); }
int sethostname(const char* name, size_t len) { return emulated_ok("sethostname", NULL); }
extern "C" int setdomainname(const char* name, size_t len) { return emulated_ok("setdomainname", NULL); }

// statfs: честный ответ по переведённому пути; f_type — из флага "magic" записи
// таблицы (если он задан), иначе реальный тип ФС хоста.
int statfs(const char* path, struct statfs* buf) {
    if (!buf) { errno = EFAULT; return -1; }
    char host[900];
    const char* use = path;
    const Entry* e = lookup_guest(path ? path : "");
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
// Свойства гостя целиком живут в гостевой ФС (/dev/__properties__/guest_properties),
// перехваты — в props.cpp. Общая область свойств ТЕЛЕФОНА не используется.

