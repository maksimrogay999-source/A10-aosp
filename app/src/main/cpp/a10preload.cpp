// a10preload.so — LD_PRELOAD библиотека для перехвата syscalls, которые блокирует хост-seccomp.
// Перехватывает mount(), statfs(), openat(), stat(), statx(), mkdir(), access(), uname()
// и другие, возвращая fake-success. Вывод — ТОЛЬКО в консоль (A10_CONSOLE_FD -> A10_Guest).
// ЗАВИСИМОСТЕЙ НЕТ (liblog/libc++ убраны): при exec LD_PRELOAD линкер подтягивал их заново —
// в этом окне зависли обе exec-пробы 13:40, не дав ни одного байта до конструктора.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

// Консольный fd (pipe в loader -> logcat A10_Guest), задаётся env A10_CONSOLE_FD.
static int g_console_fd = -1;

// Единственный вывод библиотеки: raw write в консоль. НЕТ liblog и НЕТ logd-сокета:
// первым действием старого конструктора был __android_log_print (logd-сокет в свежем
// exec-процессе) — главный подозреваемый зависания проб 13:40.
static void plog(const char *fmt, ...) {
    if (g_console_fd < 0) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf) - 2) n = (int)sizeof(buf) - 2;
    buf[n] = '\n';
    ssize_t wn = write(g_console_fd, buf, (size_t)n + 1);
    (void)wn;
}

// Конструктор: exec-безопасный порядок — (1) ok-файл raw-сисколлами, (2) маркер в
// консоль raw write. Никаких logd/fcntl/стримов в начале.
static void __attribute__((constructor)) a10preload_init(void) {
    const char *cf = getenv("A10_CONSOLE_FD");
    if (cf && *cf) g_console_fd = atoi(cf);

    // 1) ok-файл exec-пробы: ДОКАЗАТЕЛЬСТВО, что линкер загрузил preload именно при exec.
    //    Родитель-стаб поллит его каждые 20мс — результат не зависит от exit-кода потомка.
    const char *okf = getenv("A10_PROBE_OK_FILE");
    if (okf && *okf) {
        long fd = syscall(__NR_openat, AT_FDCWD, okf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *msg = "ok";
            syscall(__NR_write, fd, msg, 2);
            syscall(__NR_close, fd);
        }
    }

    // 2) маркер в консоль: виден и в пробе (A10_PROBE_LABEL), и в init после exec.
    if (g_console_fd >= 0) {
        const char *lbl = getenv("A10_PROBE_LABEL");
        char buf[176];
        int n = (lbl && *lbl)
            ? snprintf(buf, sizeof(buf), "=== a10preload.so LOADED at exec (probe %s), console_fd=%d ===\n", lbl, g_console_fd)
            : snprintf(buf, sizeof(buf), "=== a10preload.so LOADED (constructor), console_fd=%d ===\n", g_console_fd);
        if (n > 0) {
            ssize_t wn = write(g_console_fd, buf, (size_t)n);
            (void)wn;
        }
        plog("a10preload.so loaded, intercepts active: mount/umount/statfs/openat/...");
    }
}

static void log_blocked(const char *name, long nr) {
    plog("A10_Preload: BLOCKED %s (nr=%ld) -> 0", name, nr);
}

// /dev/kmsg и /dev/console гостевого init -> наш console pipe: first-stage логи init
// попадут в logcat через reader-поток loader'а.
static int open_console_redirect(const char *pathname) {
    if (g_console_fd < 0 || !pathname) return -1;
    if (strcmp(pathname, "/dev/kmsg") == 0 || strcmp(pathname, "/dev/console") == 0) {
        int fd = fcntl(g_console_fd, F_DUPFD, 3);
        if (fd >= 0) {
            plog("A10_Preload: %s -> console pipe fd=%d (init klog captured)", pathname, fd);
            char buf[160];
            int n = snprintf(buf, sizeof(buf), "=== a10preload: %s redirected to console pipe (fd=%d) ===\n", pathname, fd);
            if (n > 0) {
                ssize_t wn = write(g_console_fd, buf, (size_t)n);
                (void)wn;
            }
            return fd;
        }
        return -1;
    }
    return -1;
}

// --- mount: fake success ---
int mount(const char *source, const char *target,
          const char *filesystemtype, unsigned long mountflags,
          const void *data) {
    log_blocked("mount", __NR_mount);
    return 0;
}

// --- umount2: fake success ---
int umount2(const char *target, int flags) {
    log_blocked("umount2", __NR_umount2);
    return 0;
}

// --- setgroups: fake success ---
int setgroups(size_t size, const gid_t *list) {
    log_blocked("setgroups", __NR_setgroups);
    return 0;
}

// --- statfs: вернуть тип ФС, ожидаемый init ---
int statfs(const char *path, struct statfs *buf) {
    if (!buf) { errno = EFAULT; return -1; }
    memset(buf, 0, sizeof(*buf));
    buf->f_bsize = 4096;
    buf->f_blocks = 0;
    buf->f_bfree = 0;
    buf->f_bavail = 0;
    buf->f_files = 0;
    buf->f_ffree = 0;
    buf->f_namelen = 255;
    buf->f_fsid.__val[0] = 0;
    buf->f_fsid.__val[1] = 0;

    if (path) {
        if (strcmp(path, "/sys/fs/selinux") == 0) {
            buf->f_type = 0xf97cff8c; // SELINUX_MAGIC
            log_blocked("statfs(selinuxfs)", __NR_statfs);
        } else if (strcmp(path, "/dev") == 0 || strcmp(path, "/dev/pts") == 0) {
            buf->f_type = 0x01021994; // TMPFS_MAGIC
            log_blocked("statfs(tmpfs)", __NR_statfs);
        } else if (strcmp(path, "/proc") == 0) {
            buf->f_type = 0x9fa0; // PROC_SUPER_MAGIC
            log_blocked("statfs(proc)", __NR_statfs);
        } else if (strcmp(path, "/sys") == 0 || strncmp(path, "/sys/", 5) == 0) {
            buf->f_type = 0x62656572; // SYSFS_MAGIC
            log_blocked("statfs(sysfs)", __NR_statfs);
        } else {
            buf->f_type = 0x01021994; // default tmpfs
            log_blocked("statfs(default tmpfs)", __NR_statfs);
        }
    } else {
        buf->f_type = 0x01021994;
        log_blocked("statfs(NULL)", __NR_statfs);
    }
    return 0;
}

// --- open: /dev/kmsg|/dev/console -> console pipe; остальное -> реальный open (raw syscall) ---
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int r = open_console_redirect(pathname);
    if (r >= 0) return r;
    return (int)syscall(__NR_openat, AT_FDCWD, pathname, flags, mode);
}

// --- openat: /dev/kmsg|/dev/console -> console pipe; остальное -> реальный openat (raw syscall) ---
int openat(int dfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int r = open_console_redirect(pathname);
    if (r >= 0) return r;
    return (int)syscall(__NR_openat, dfd, pathname, flags, mode);
}

// --- stat: вернуть существует ли файл ---
int stat(const char *pathname, struct stat *statbuf) {
    if (!statbuf) { errno = EFAULT; return -1; }
    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_mode = S_IFREG | 0644;
    statbuf->st_size = 0;
    statbuf->st_uid = 0;
    statbuf->st_gid = 0;
    log_blocked("stat", 0);
    return 0;
}

// --- statx: ---
int statx(int dfd, const char *pathname, int flags, unsigned int mask,
          struct statx *statxbuf) {
    if (!statxbuf) { errno = EFAULT; return -1; }
    memset(statxbuf, 0, sizeof(*statxbuf));
    statxbuf->stx_mode = S_IFREG | 0644;
    statxbuf->stx_uid = 0;
    statxbuf->stx_gid = 0;
    log_blocked("statx", __NR_statx);
    return 0;
}

// --- fstat: ---
int fstat(int fd, struct stat *statbuf) {
    if (!statbuf) { errno = EFAULT; return -1; }
    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_mode = S_IFREG | 0644;
    statbuf->st_size = 0;
    statbuf->st_uid = 0;
    statbuf->st_gid = 0;
    log_blocked("fstat", __NR_fstat);
    return 0;
}

// --- mkdir: fake success ---
int mkdir(const char *pathname, mode_t mode) {
    log_blocked("mkdir", 0);
    return 0;
}

// --- access: вернуть доступен ---
int access(const char *pathname, int mode) {
    log_blocked("access", 0);
    return 0;
}

// --- uname: вернуть Android ---
int uname(struct utsname *buf) {
    if (!buf) { errno = EFAULT; return -1; }
    memset(buf, 0, sizeof(*buf));
    strncpy(buf->sysname, "Linux", sizeof(buf->sysname) - 1);
    strncpy(buf->nodename, "android", sizeof(buf->nodename) - 1);
    strncpy(buf->release, "3.18", sizeof(buf->release) - 1);
    strncpy(buf->version, "#1", sizeof(buf->version) - 1);
    strncpy(buf->machine, "aarch64", sizeof(buf->machine) - 1);
    log_blocked("uname", __NR_uname);
    return 0;
}

// --- chroot: fake success ---
int chroot(const char *path) {
    log_blocked("chroot", __NR_chroot);
    return 0;
}

// --- pivot_root: fake success ---
long pivot_root(const char *new_root, const char *put_old) {
    log_blocked("pivot_root", __NR_pivot_root);
    return 0;
}

// --- sethostname: fake success ---
int sethostname(const char *name, size_t len) {
    log_blocked("sethostname", __NR_sethostname);
    return 0;
}

// --- setdomainname: fake success ---
int setdomainname(const char *name, size_t len) {
    log_blocked("setdomainname", __NR_setdomainname);
    return 0;
}

// --- capset: fake success ---
int capset(void *hdr_e, void *data) {
    log_blocked("capset", __NR_capset);
    return 0;
}

// --- setgid/setuid family: fake success ---
int setgid(gid_t gid) { log_blocked("setgid", __NR_setgid); return 0; }
int setuid(uid_t uid) { log_blocked("setuid", __NR_setuid); return 0; }
int setreuid(uid_t ruid, uid_t euid) { log_blocked("setreuid", __NR_setreuid); return 0; }
int setregid(gid_t rgid, gid_t egid) { log_blocked("setregid", __NR_setregid); return 0; }
int setresuid(uid_t ruid, uid_t euid, uid_t suid) { log_blocked("setresuid", __NR_setresuid); return 0; }
int setresgid(gid_t rgid, gid_t egid, gid_t sgid) { log_blocked("setresgid", __NR_setresgid); return 0; }
int setfsuid(uid_t fsuid) { log_blocked("setfsuid", __NR_setfsuid); return 0; }
int setfsgid(gid_t fsgid) { log_blocked("setfsgid", __NR_setfsgid); return 0; }

// --- reboot: fake success ---
int reboot(int magic1, int magic2, int cmd, void *arg) {
    log_blocked("reboot", __NR_reboot);
    return 0;
}

// --- swapon/swapoff: fake success ---
int swapon(const char *path, int swapflags) { log_blocked("swapon", __NR_swapon); return 0; }
int swapoff(const char *path) { log_blocked("swapoff", __NR_swapoff); return 0; }

// --- settimeofday/clock_settime: fake success ---
int settimeofday(const struct timeval *tv, const struct timezone *tz) {
    log_blocked("settimeofday", __NR_settimeofday);
    return 0;
}
int clock_settime(clockid_t clk_id, const struct timespec *tp) {
    log_blocked("clock_settime", __NR_clock_settime);
    return 0;
}

// --- sched_setscheduler: fake success ---
int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param) {
    log_blocked("sched_setscheduler", __NR_sched_setscheduler);
    return 0;
}

// --- init_module/delete_module/kexec_load: fake success ---
int init_module(void *module_image, unsigned long len, const char *uargs) {
    log_blocked("init_module", __NR_init_module);
    return 0;
}
int delete_module(const char *name, int flags) {
    log_blocked("delete_module", __NR_delete_module);
    return 0;
}
long kexec_load(unsigned long entry, unsigned long nr_segments,
                struct kexec_segment *segments, unsigned long flags) {
    log_blocked("kexec_load", __NR_kexec_load);
    return 0;
}

// --- adjtimex/setpriority/setpgid/setsid/nice: fake success ---
long adjtimex(struct timex *txc) { log_blocked("adjtimex", __NR_adjtimex); return 0; }
int setpriority(int which, int who, int prio) { log_blocked("setpriority", __NR_setpriority); return 0; }
int setpgid(pid_t pid, pid_t pgid) { log_blocked("setpgid", __NR_setpgid); return 0; }
pid_t setsid(void) { log_blocked("setsid", __NR_setsid); return 0; }
int nice(int inc) { log_blocked("nice", 0); return 0; }

// --- acct/syslog: fake success ---
int acct(const char *filename) { log_blocked("acct", __NR_acct); return 0; }
int syslog(int type, char *buf, int len) { log_blocked("syslog", __NR_syslog); return 0; }