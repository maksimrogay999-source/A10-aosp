#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cstdlib>
#include <string>

#include "a10mounts.h"

#define TAG "A10_Stub"

// f_type эмулированного selinuxfs гостя (константа uapi ядра, linux/selinux.h).

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
// struct seccomp_notif_resp/req layout may vary; these are typical values on Linux
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW(SECCOMP_IOC_MAGIC, 2, __u64)
#endif

// Минимальные определения на случай отсутствия в NDK headers.
struct a10_seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
struct a10_seccomp_notif_sizes {
    __u16 seccomp_notif;
    __u16 seccomp_notif_resp;
    __u16 seccomp_data;
};
struct a10_seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct a10_seccomp_data data;
};
struct a10_seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

// Устанавливает seccomp USER_NOTIF фильтр, возвращает notify_fd (>=0) или -1.
// Вызывается ТОЛЬКО в fork-потомке ("seccomp worker"): хостовый seccomp (untrusted_app_27)
// может убить процесс прямо на syscall seccomp (SECCOMP_RET_KILL — SIG_IGN не спасает).
// Если worker погибнет — родитель увидит закрытие ack-пайпа и уйдёт в fallback
// (LD_PRELOAD + SIGSYS). Запуск не ломается, а seccomp-этап обязателен и выполняется каждый раз.
static int install_user_notif_filter(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "seccomp: installing USER_NOTIF filter (mandatory stage, worker pid=%d)", getpid());

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "PR_SET_NO_NEW_PRIVS failed: errno=%d (%s)", errno, strerror(errno));
        // продолжим попытку установки фильтра
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "PR_SET_NO_NEW_PRIVS ok");
    }

    // Фильтр: перехватываем только syscalls, которые init вызывает и которые хост seccomp блокирует.
    // nr в seccomp_data находится по offsetof(struct seccomp_data, nr).
    // BPF_JUMP: если nr совпадает с одним из нужных -> USER_NOTIF, иначе ALLOW.
    // ARM64 syscall numbers: mount=40, umount2=39, setgroups=159, statfs=43, stat=4, statx=163,
    // openat=56, mkdir=34, access=48, uname=160, chroot=51, pivot_root=41, sethostname=170,
    // setdomainname=171, capset=125, setgid=144, setuid=146, setreuid=145, setregid=143,
    // setresuid=147, setresgid=149, setfsuid=140, setfsgid=141, reboot=142, swapon=143,
    // swapoff=144, mknod=33, settimeofday=164, clock_settime=113, sched_setscheduler=144? no,
    // init_module=175, delete_module=176, kexec_load=174, adjtimex=305, setpriority=140? no,
    // setpgid=157, setsid=157? no, nice=34? no, acct=163, syslog=116, capset=125.
    // Для краткости перехватываем основные: mount, umount2, setgroups, statfs, stat, statx,
    // openat, mkdir, access, uname, chroot, pivot_root, sethostname, setdomainname, capset,
    // setgid, setuid, setreuid, setregid, setresuid, setresgid, setfsuid, setfsgid,
    // reboot, swapon, swapoff, mknod, settimeofday, clock_settime, adjtimex,
    // setpriority, setpgid, setsid, init_module, delete_module, kexec_load, acct, syslog, capset.
    // syscall numbers for arm64 (from asm/unistd.h):
    // #define __NR_mount 40
    // #define __NR_umount2 39
    // #define __NR_setgroups 159
    // #define __NR_statfs 43
    // #define __NR_newstat 4
    // #define __NR_statx 163
    // #define __NR_openat 56
    // #define __NR_mkdir 34
    // #define __NR_access 48
    // #define __NR_uname 160
    // #define __NR_chroot 51
    // #define __NR_pivot_root 41
    // #define __NR_sethostname 170
    // #define __NR_setdomainname 171
    // #define __NR_capset 125
    // #define __NR_setgid 144
    // #define __NR_setuid 146
    // #define __NR_setreuid 145
    // #define __NR_setregid 143
    // #define __NR_setresuid 147
    // #define __NR_setresgid 149
    // #define __NR_setfsuid 140
    // #define __NR_setfsgid 141
    // #define __NR_reboot 142
    // #define __NR_swapon 143
    // #define __NR_swapoff 144
    // #define __NR_mknod 33
    // #define __NR_settimeofday 164
    // #define __NR_clock_settime 113
    // #define __NR_adjtimex 305
    // #define __NR_setpriority 140
    // #define __NR_setpgid 157
    // #define __NR_setsid 157
    // #define __NR_init_module 175
    // #define __NR_delete_module 176
    // #define __NR_kexec_load 174
    // #define __NR_acct 163
    // #define __NR_syslog 116
    // #define __NR_capset 125

    // BPF program: load nr, jump to USER_NOTIF if matches any of our syscalls, else ALLOW.
    // We'll use a jump table approach: compare nr against each syscall we want to intercept.
    // For brevity, we'll list the most critical ones first.
    // Structure: LD nr, then series of JEQ to USER_NOTIF, finally ALLOW.
    
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        
        // Critical syscalls that init uses and host blocks:
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 40, 0, 1),  // mount
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 1),  // umount2
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 159, 0, 1), // setgroups
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 43, 0, 1),  // statfs
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 1),   // stat (newstat)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 163, 0, 1), // statx
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 56, 0, 1),  // openat
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 34, 0, 1),  // mkdir
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 48, 0, 1),  // access
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 160, 0, 1), // uname
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 51, 0, 1),  // chroot
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 41, 0, 1),  // pivot_root
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 170, 0, 1), // sethostname
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 171, 0, 1), // setdomainname
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 125, 0, 1), // capset
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 144, 0, 1), // setgid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 146, 0, 1), // setuid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 145, 0, 1), // setreuid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 143, 0, 1), // setregid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 147, 0, 1), // setresuid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 149, 0, 1), // setresgid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 140, 0, 1), // setfsuid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 141, 0, 1), // setfsgid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 142, 0, 1), // reboot
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 143, 0, 1), // swapon
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 144, 0, 1), // swapoff
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 33, 0, 1),  // mknod
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 164, 0, 1), // settimeofday
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 113, 0, 1), // clock_settime
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 305, 0, 1), // adjtimex
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 140, 0, 1), // setpriority
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 157, 0, 1), // setpgid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 157, 0, 1), // setsid (same nr as setpgid on some arches, but arm64 is 112? need to check)
        // Actually on arm64 setsid is 112, setpgid is 157. Let me add setsid separately.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 112, 0, 1), // setsid
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 175, 0, 1), // init_module
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 176, 0, 1), // delete_module
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 174, 0, 1), // kexec_load
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 163, 0, 1), // acct
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 116, 0, 1), // syslog
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 125, 0, 1), // capset (already listed but duplicate ok)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    __android_log_print(ANDROID_LOG_INFO, TAG, "seccomp: calling seccomp(SET_MODE_FILTER, NEW_LISTENER) nr=%d (if this is the last log, the syscall blocks or kills)", __NR_seccomp);
    int notify_fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notify_fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "seccomp NEW_LISTENER failed: errno=%d (%s)", errno, strerror(errno));
        __android_log_print(ANDROID_LOG_INFO, TAG, "seccomp user-notif likely unsupported or blocked on this device/kernel/policy");
        return -1;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "seccomp NEW_LISTENER ok: notify_fd=%d", notify_fd);

    struct a10_seccomp_notif_sizes sizes {};
    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "SECCOMP_GET_NOTIF_SIZES: notif=%u resp=%u data=%u", sizes.seccomp_notif, sizes.seccomp_notif_resp, sizes.seccomp_data);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "SECCOMP_GET_NOTIF_SIZES failed: errno=%d (%s)", errno, strerror(errno));
    }

    return notify_fd;
}

// stdout/stderr гостевого init -> консольный pipe loader'а (тот читает и пишет в logcat A10_Guest).
static void setup_guest_console(int console_fd, const char* mode_label) {
    if (console_fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "no console fd (A10_CONSOLE_FD unset) - guest stdio NOT redirected");
        return;
    }
    char hdr[128];
    int hn = snprintf(hdr, sizeof(hdr), "\n=== a10stub: exec guest init (%s) ===\n", mode_label);
    if (hn > 0) {
        ssize_t wn = write(console_fd, hdr, (size_t)hn);
        (void)wn;
    }
    dup2(console_fd, STDOUT_FILENO);
    dup2(console_fd, STDERR_FILENO);
    __android_log_print(ANDROID_LOG_INFO, TAG, "guest stdio -> console pipe fd=%d (%s)", console_fd, mode_label);
}

// ---------------------------------------------------------------- раскладка гостя
// ЕДИНЫЙ ИСТОЧНИК ПРАВДЫ. Эта таблица:
//   * описывает, где лежит каждый путь гостя (host-путь);
//   * из неё создаются каталоги и симлинки в rootfs;
//   * из неё строится LD_LIBRARY_PATH и PATH гостя;
//   * она записывается в <rootfs>/a10_mounts и передаётся гостю (A10_MOUNTS_FILE) —
//     preload переводит пути по ней, без единого хардкода.
//
// host == nullptr  -> "<rootfs><guest>" (внутри гостевой ФС)
// host == ""      -> путь хоста как есть ("/proc", "/sys", ...)
// Флаги: rw, chmod_ok, console, selinux, magic=0xHEX, fallback=путь, logd,
//        lib64, lib, bin, trace, dir (создать каталог), link=цель (симлинк).
// Mount-таблица гостя. Списков путей в коде НЕТ: базовые записи — из СКАНА корня
// гостевой ФС, точки монтирования и устройства — из mount()/mknod() гостя (preload
// дописывает их в таблицу). Таблица живёт в <rootfs>/a10_mounts и передаётся гостю.
struct LayoutEntry {
    char guest[192];
    char host[512];
    char flags[256];
};
static LayoutEntry g_layout[256];
static int g_layout_count = 0;

// Добавить/обновить запись таблицы. Флаги ДОПОЛНЯЮТСЯ (ранее выставленные, напр. "trace",
// не теряются при повторной регистрации каталога).
static void layout_add(const char* guest, const char* host, const char* flags) {
    for (int i = 0; i < g_layout_count; i++) {
        if (strcmp(g_layout[i].guest, guest) == 0) {
            snprintf(g_layout[i].host, sizeof(g_layout[i].host), "%s", host);
            if (!flags || !flags[0]) return;
            char add[256];
            snprintf(add, sizeof(add), "%s", flags);
            char* save = nullptr;
            for (char* t = strtok_r(add, " \t", &save); t; t = strtok_r(nullptr, " \t", &save)) {
                a10mount::Entry e {};
                snprintf(e.flags, sizeof(e.flags), "%s", g_layout[i].flags);
                if (a10mount::flag_present(&e, t)) continue;
                size_t n = strlen(g_layout[i].flags);
                snprintf(g_layout[i].flags + n, sizeof(g_layout[i].flags) - n, " %s", t);
            }
            return;
        }
    }
    if (g_layout_count >= (int)(sizeof(g_layout) / sizeof(g_layout[0]))) return;
    LayoutEntry& e = g_layout[g_layout_count++];
    snprintf(e.guest, sizeof(e.guest), "%s", guest);
    snprintf(e.host, sizeof(e.host), "%s", host);
    snprintf(e.flags, sizeof(e.flags), "%s", flags ? flags : "");
}

// Самая длинная подходящая запись (префикс по границе компонента пути).
static const LayoutEntry* layout_lookup(const char* guest_path) {
    if (!guest_path) return nullptr;
    const LayoutEntry* best = nullptr;
    size_t bestlen = 0;
    for (int i = 0; i < g_layout_count; i++) {
        if (!a10mount::path_prefix(guest_path, g_layout[i].guest)) continue;
        size_t gl = strlen(g_layout[i].guest);
        if (gl > bestlen) {
            bestlen = gl;
            best = &g_layout[i];
        }
    }
    return best;
}

// Перевод гостевого пути в host-путь по таблице.
static bool guest_to_host(const char* guest_path, char* out, size_t outsz) {
    const LayoutEntry* e = layout_lookup(guest_path);
    if (!e) return false;
    snprintf(out, outsz, "%s%s", e->host, guest_path + strlen(e->guest));
    return true;
}

// Скан корня гостевой ФС -> базовые записи таблицы.
//
// Симлинк гостя (напр. "/product" -> "/system/product") НЕ должен уводить в корень
// ХОСТА: иначе линкер гостя подхватит хостовые библиотеки (libbase AOSP-16 вместо
// гостевого) — это и есть «shared с хостом». Поэтому цель симлинка переводится внутрь
// гостевой ФС, а host-путь записи остаётся путём внутри rootfs.
static void scan_guest_root(const char* rootfs) {
    layout_add("/", rootfs, "rw");
    DIR* d = opendir(rootfs);
    if (!d) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "раскладка: не читается корень %s", rootfs);
        return;
    }
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        char guest[192], host[900];
        snprintf(guest, sizeof(guest), "/%s", e->d_name);
        snprintf(host, sizeof(host), "%s/%s", rootfs, e->d_name);
        struct stat st {};
        if (lstat(host, &st) == 0 && S_ISLNK(st.st_mode)) {
            char target[512];
            ssize_t n = readlink(host, target, sizeof(target) - 1);
            if (n > 0) {
                target[n] = 0;
                if (target[0] == '/') {
                    // Цель могла накопить префиксы rootfs за прошлые прогоны (перевод не
                    // был идемпотентным) — отбрасываем их, получая исходный путь гостя.
                    char clean[512];
                    snprintf(clean, sizeof(clean), "%s", target);
                    size_t rl = strlen(rootfs);
                    while (rl && strncmp(clean, rootfs, rl) == 0) {
                        memmove(clean, clean + rl, strlen(clean + rl) + 1);
                    }
                    char inside[900];
                    snprintf(inside, sizeof(inside), "%s%s", rootfs, clean);
                    unlink(host);
                    if (strcmp(inside, host) == 0) {
                        // Симлинк указывал сам на себя (остаток прошлых прогонов) — убираем.
                        __android_log_print(ANDROID_LOG_INFO, TAG,
                                            "раскладка: симлинк гостя %s (на себя) удалён", guest);
                    } else if (symlink(inside, host) != 0) {
                        __android_log_print(ANDROID_LOG_WARN, TAG, "symlink %s -> %s failed: %s",
                                            host, inside, strerror(errno));
                    } else {
                        __android_log_print(ANDROID_LOG_INFO, TAG,
                                            "раскладка: симлинк гостя %s -> %s (переведён внутрь гостя)",
                                            guest, clean);
                    }
                }
            }
        }
        layout_add(guest, host, "rw");
    }
    closedir(d);
    __android_log_print(ANDROID_LOG_INFO, TAG, "раскладка: просканирован корень гостя (%d записей)",
                        g_layout_count);
}

// Таблица гостя -> файл <rootfs>/a10_mounts (его читает preload через A10_MOUNTS_FILE).
static void write_mount_table(const char* rootfs, char* table_path, size_t sz) {
    snprintf(table_path, sz, "%s/a10_mounts", rootfs);
    FILE* f = fopen(table_path, "w");
    if (!f) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "раскладка: не смог записать %s", table_path);
        return;
    }
    fprintf(f, "# a10 mount table: <guest> <host> [flags]\n");
    for (int i = 0; i < g_layout_count; i++) {
        fprintf(f, "%s %s %s\n", g_layout[i].guest, g_layout[i].host, g_layout[i].flags);
    }
    fclose(f);
    __android_log_print(ANDROID_LOG_INFO, TAG, "раскладка гостя: %d записей -> %s", g_layout_count,
                        table_path);
    // Дамп таблицы: видно, что реально видит preload (диагностика путей гостя).
    for (int i = 0; i < g_layout_count; i++) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "раскладка: %s -> %s [%s]", g_layout[i].guest,
                            g_layout[i].host, g_layout[i].flags);
    }
}

static void mkdir_p_host(const char* path);
static void ensure_guest_dir(const char* guest_dir, const char* rootfs);
static void ensure_guest_parent(const char* guest_file, const char* rootfs);
static void layout_mark_trace(const char* guest);
static void prepare_guest_product(const char* rootfs);

// Пометить запись таблицы как трассируемую: обращения гостя к ней видны в логе.
static void layout_mark_trace(const char* guest) {
    for (int i = 0; i < g_layout_count; i++) {
        if (strcmp(g_layout[i].guest, guest) != 0) continue;
        a10mount::Entry e {};
        snprintf(e.flags, sizeof(e.flags), "%s", g_layout[i].flags);
        if (a10mount::flag_present(&e, "trace")) return;
        size_t n = strlen(g_layout[i].flags);
        snprintf(g_layout[i].flags + n, sizeof(g_layout[i].flags) - n, " trace");
        return;
    }
}

// product-раздела в GSI нет, но гостевая AOSP 10 сверяет product-пару sha
// (FindPrecompiledSplitPolicy): без неё гость молча уходит из split-ветки ->
// "Unable to load SELinux policy". Делаем гостевой /product (свой каталог) и
// кладём СОГЛАСОВАННУЮ product-sha (копия plat-sha) — сравнение проходит.
static void prepare_guest_product(const char* rootfs) {
    char prod[700];
    snprintf(prod, sizeof(prod), "%s/product", rootfs);
    struct stat st {};
    if (lstat(prod, &st) == 0 && S_ISLNK(st.st_mode)) {
        // Симлинк гостя на отсутствующий product-раздел — заменяем своим каталогом.
        unlink(prod);
    }
    ensure_guest_dir("/product", rootfs);
    ensure_guest_dir("/product/etc/selinux", rootfs);
    layout_mark_trace("/product/etc/selinux");

    char plat_sha[700], prod_sha[700];
    if (!guest_to_host("/system/etc/selinux/plat_sepolicy_and_mapping.sha256", plat_sha,
                       sizeof(plat_sha)) ||
        !guest_to_host("/product/etc/selinux/product_sepolicy_and_mapping.sha256", prod_sha,
                       sizeof(prod_sha))) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: product-sha: пути не найдены в раскладке");
        return;
    }
    struct stat pst {};
    if (stat(prod_sha, &pst) == 0 && pst.st_size > 0) return;
    int in = open(plat_sha, O_RDONLY);
    if (in < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет %s — product-sha не создана", plat_sha);
        return;
    }
    char buf[512];
    ssize_t n = read(in, buf, sizeof(buf));
    close(in);
    if (n <= 0) return;
    int out = open(prod_sha, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) {
        ssize_t w = write(out, buf, (size_t)n);
        (void)w;
        close(out);
        __android_log_print(ANDROID_LOG_INFO, TAG,
                            "policy: гостевая product-sha создана (копия plat) -> %s", prod_sha);
    }
}

// Эмулированный selinuxfs ГОСТЯ. Нужен ДО монтирования гостем: init первой стадии
// делает statfs("/sys/fs/selinux") и по f_type решает, включён ли SELinux (на
// устройстве selinuxfs поднят ядром с рождения, гость его только проверяет).
// Позже гость сам монтирует selinuxfs — его mount() перезапишет эту запись (fs=selinuxfs).
// Файловая система — ГОСТЕВАЯ (в rootfs), к selinuxfs хоста не обращаемся.
static void register_guest_selinuxfs(const char* rootfs) {
    const char* guest = "/sys/fs/selinux";
    ensure_guest_dir("/sys/fs", rootfs);
    char host[900];
    snprintf(host, sizeof(host), "%s%s", rootfs, guest);
    mkdir_p_host(host);
    char flags[192];
    snprintf(flags, sizeof(flags), "rw fs=selinuxfs selinux magic=0x%lx",
             (unsigned long)0xf97cff8cUL);
    layout_add(guest, host, flags);
    __android_log_print(ANDROID_LOG_INFO, TAG, "раскладка: эмулированный selinuxfs гостя -> %s", host);
}

// Каталог гостя: создаём в гостевой ФС и регистрируем в таблице (вместе с родителями).
static void ensure_guest_dir(const char* guest_dir, const char* rootfs) {
    char host[900];
    snprintf(host, sizeof(host), "%s%s", rootfs, guest_dir);
    mkdir_p_host(host);
    char acc[256] = {0};
    const char* p = guest_dir;
    while (*p == '/') p++;
    while (*p) {
        const char* slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (acc[0]) {
            snprintf(acc + strlen(acc), sizeof(acc) - strlen(acc), "/%.*s", (int)n, p);
        } else {
            snprintf(acc, sizeof(acc), "/%.*s", (int)n, p);
        }
        char h[900];
        snprintf(h, sizeof(h), "%s%s", rootfs, acc);
        layout_add(acc, h, "rw");
        if (!slash) break;
        p = slash + 1;
    }
}

// Каталог гостя, в котором лежит файл: регистрируем и создаём.
static void ensure_guest_parent(const char* guest_file, const char* rootfs) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", guest_file);
    char* slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    ensure_guest_dir(tmp, rootfs);
}

// LD_LIBRARY_PATH гостя: каталоги lib/lib64, найденные в гостевой ФС (по таблице).
// ТОЛЬКО внутри rootfs: хостовские библиотеки гостю не подсовываем.
static void build_guest_ld_library_path(const char* rootfs, char* out, size_t outsz) {
    size_t used = 0;
    size_t rlen = rootfs ? strlen(rootfs) : 0;
    out[0] = 0;
    for (int i = 0; i < g_layout_count; i++) {
        const LayoutEntry* e = &g_layout[i];
        if (rlen && strncmp(e->host, rootfs, rlen) != 0) continue;
        const char* subs[2] = {"/lib64", "/lib"};
        for (int s = 0; s < 2; s++) {
            char full[900];
            snprintf(full, sizeof(full), "%s%s", e->host, subs[s]);
            struct stat st {};
            if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
            size_t need = strlen(full) + (used ? 1 : 0) + 1;
            if (used + need >= outsz) continue;
            if (used) out[used++] = ':';
            memcpy(out + used, full, strlen(full));
            used += strlen(full);
            out[used] = 0;
        }
    }
}

// PATH гостя: каталоги bin/sbin, найденные в гостевой ФС (по таблице).
static void build_guest_path(char* out, size_t outsz) {
    size_t used = 0;
    out[0] = 0;
    for (int i = 0; i < g_layout_count; i++) {
        const LayoutEntry* e = &g_layout[i];
        const char* subs[2] = {"/bin", "/sbin"};
        for (int s = 0; s < 2; s++) {
            char full[900];
            snprintf(full, sizeof(full), "%s%s", e->host, subs[s]);
            struct stat st {};
            if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
            char gp[256];
            size_t gl = strlen(e->guest);
            if (gl > 0 && e->guest[gl - 1] == '/') {
                snprintf(gp, sizeof(gp), "%s%s", e->guest, subs[s] + 1);
            } else {
                snprintf(gp, sizeof(gp), "%s%s", e->guest, subs[s]);
            }
            size_t need = strlen(gp) + (used ? 1 : 0) + 1;
            if (used + need >= outsz) continue;
            if (used) out[used++] = ':';
            memcpy(out + used, gp, strlen(gp));
            used += strlen(gp);
            out[used] = 0;
        }
    }
}

static void mkdir_p_host(const char* path);

// Диагностика гостевой SELinux-ФС: какие политики/CIL/mapping есть в rootfs.
// Политика должна быть ГОСТЕВОЙ (AOSP-10 GSI) — хостовую (AOSP-16) гостевой
// libselinux распарсит неправильно.
static void report_guest_selinux(const char* rootfs) {
    const char* dirs[] = {
        "/system/etc/selinux",
        "/system/etc/selinux/mapping",
        "/vendor/etc/selinux",
        "/odm/etc/selinux",
        "/product/etc/selinux",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[700];
        if (!guest_to_host(dirs[i], p, sizeof(p))) continue;
        DIR* d = opendir(p);
        if (!d) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "selinux-diag: %s — каталога НЕТ", dirs[i]);
            continue;
        }
        __android_log_print(ANDROID_LOG_INFO, TAG, "selinux-diag: %s — содержимое:", dirs[i]);
        struct dirent* e;
        int count = 0;
        while ((e = readdir(d)) != nullptr && count < 80) {
            if (e->d_name[0] == '.') continue;
            char fp[800];
            snprintf(fp, sizeof(fp), "%s/%s", p, e->d_name);
            struct stat st {};
            long sz = (stat(fp, &st) == 0) ? (long)st.st_size : -1L;
            __android_log_print(ANDROID_LOG_INFO, TAG, "selinux-diag:    %s (%ld байт)", e->d_name, sz);
            count++;
        }
        closedir(d);
    }

    const char* probe[] = {
        "/system/etc/selinux/precompiled_sepolicy",
        "/system/etc/selinux/plat_sepolicy.cil",
        "/system/etc/selinux/file_contexts",
        "/system/bin/secilc",
        "/sepolicy",
        "/vendor/etc/selinux/precompiled_sepolicy",
        "/vendor/etc/selinux/plat_sepolicy_vers.txt",
        "/vendor/etc/selinux/vendor_sepolicy.cil",
    };
    for (size_t i = 0; i < sizeof(probe) / sizeof(probe[0]); i++) {
        char fp[800];
        if (!guest_to_host(probe[i], fp, sizeof(fp))) continue;
        struct stat st {};
        if (stat(fp, &st) == 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "selinux-probe: ЕСТЬ %s (%ld байт)", probe[i],
                                (long)st.st_size);
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "selinux-probe: НЕТ  %s", probe[i]);
        }
    }
}

// Бинарная SELinux-политика начинается с magic 0xf97cff8c (он же у selinuxfs).
// Если plat_sepolicy.cil уже бинарная — её можно отдать гостю как есть, без secilc.
static bool is_binary_policy(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    unsigned char b[4] = {0, 0, 0, 0};
    ssize_t n = read(fd, b, 4);
    close(fd);
    return n == 4 && b[0] == 0xf9 && b[1] == 0x7c && b[2] == 0xff && b[3] == 0x8c;
}

// Лог первых байт файла: отличить CIL-текст от бинарной политики.
static void log_file_head(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    unsigned char b[16];
    ssize_t n = read(fd, b, sizeof(b));
    close(fd);
    if (n <= 0) return;
    char hex[64], txt[24];
    int hn = 0, tn = 0;
    for (ssize_t i = 0; i < n && hn < 48; i++) {
        hn += snprintf(hex + hn, sizeof(hex) - hn, "%02x", b[i]);
        if (hn < (int)sizeof(hex) - 1) txt[tn++] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.';
    }
    txt[tn] = 0;
    __android_log_print(ANDROID_LOG_INFO, TAG, "policy-head %s: [%s] '%s'%s", path, hex, txt,
                        is_binary_policy(path) ? "  <-- БИНАРНАЯ политика" : "");
}

// Гостевой secilc с перехватом stderr (в лог) — собираем политику гостя.
// ВАЖНО: -c это ЧИСЛОВАЯ версия политики (у гостевого secilc дефолт 31), а не версия
// mapping'а ("29.0"). mapping-файл передаётся отдельным аргументом.
static bool run_secilc(const char* rootfs, const char* vers, const char* polvers,
                       const char* out_path, char* err, size_t errsz) {
    err[0] = '\0';
    char cil[700], map[700], secilc[700], libs[900];
    char cil_g[220], map_g[220], secilc_g[220];
    snprintf(cil_g, sizeof(cil_g), "/system/etc/selinux/plat_sepolicy.cil");
    snprintf(map_g, sizeof(map_g), "/system/etc/selinux/mapping/%s.cil", vers);
    snprintf(secilc_g, sizeof(secilc_g), "/system/bin/secilc");
    if (!guest_to_host(cil_g, cil, sizeof(cil)) ||
        !guest_to_host(map_g, map, sizeof(map)) ||
        !guest_to_host(secilc_g, secilc, sizeof(secilc))) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: гостевые пути не найдены в раскладке");
        return false;
    }
    char llp[800];
    build_guest_ld_library_path(rootfs, llp, sizeof(llp));
    snprintf(libs, sizeof(libs), "LD_LIBRARY_PATH=%s", llp);

    int pfd[2];
    if (pipe(pfd) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDERR_FILENO);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        setenv("LD_LIBRARY_PATH", libs + strlen("LD_LIBRARY_PATH="), 1);
        // Аргументы — как в AOSP init (LoadSplitPolicy): plat, флаги, -c версия, mapping, -o, -f
        if (polvers && polvers[0]) {
            execl(secilc, secilc, cil, "-m", "-M", "true", "-G", "-N", "-c", polvers, map,
                  "-o", out_path, "-f", "/dev/null", (char*)nullptr);
        } else {
            execl(secilc, secilc, cil, "-m", "-M", "true", "-G", "-N", map,
                  "-o", out_path, "-f", "/dev/null", (char*)nullptr);
        }
        _exit(127);
    }
    close(pfd[1]);
    size_t got = 0;
    ssize_t n;
    while (got < errsz - 1 && (n = read(pfd[0], err + got, errsz - 1 - got)) > 0) got += (size_t)n;
    err[got] = '\0';
    close(pfd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    for (size_t i = 0; i < got; i++) {
        if (err[i] == '\n' || err[i] == '\r') err[i] = '|';
    }
    __android_log_print(code == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_WARN, TAG,
                        "policy: secilc -c %s mapping=%s exit=%d, вывод: %s",
                        (polvers && polvers[0]) ? polvers : "(дефолт)", vers, code, err);
    return code == 0;
}

// Собираем гостевую политику: перебираем версии mapping (свежие -> старые) и числовые
// версии политики (-c). Первая удачная сборка и есть результат.
static bool compile_guest_policy(const char* rootfs) {
    char cil[700], secilc[700], out[700], libs[900];
    char cil_g[220], secilc_g[220];
    snprintf(cil_g, sizeof(cil_g), "/system/etc/selinux/plat_sepolicy.cil");
    snprintf(secilc_g, sizeof(secilc_g), "/system/bin/secilc");
    if (!guest_to_host(cil_g, cil, sizeof(cil)) ||
        !guest_to_host(secilc_g, secilc, sizeof(secilc))) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: гостевые пути не найдены в раскладке");
        return false;
    }
    snprintf(out, sizeof(out), "%s/sepolicy.new", rootfs);
    char llp[800];
    build_guest_ld_library_path(rootfs, llp, sizeof(llp));
    snprintf(libs, sizeof(libs), "LD_LIBRARY_PATH=%s", llp);
    (void)libs;

    if (access(cil, R_OK) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет %s — компилировать нечего", cil);
        return false;
    }
    if (access(secilc, X_OK) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет %s — компилировать нечем", secilc);
        return false;
    }

    // Кандидаты mapping: читаем каталог и сортируем по убыванию.
    char mapdir[700];
    if (!guest_to_host("/system/etc/selinux/mapping", mapdir, sizeof(mapdir))) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: путь mapping не найден в раскладке");
        return false;
    }
    char vers[16][32];
    int nvers = 0;
    DIR* md = opendir(mapdir);
    if (md) {
        struct dirent* e;
        while ((e = readdir(md)) != nullptr && nvers < 16) {
            const char* dot = strrchr(e->d_name, '.');
            if (!dot || strcmp(dot, ".cil") != 0) continue;
            char v[32];
            snprintf(v, sizeof(v), "%.*s", (int)(dot - e->d_name), e->d_name);
            bool dup = false;
            for (int i = 0; i < nvers; i++) if (strcmp(vers[i], v) == 0) dup = true;
            if (!dup) snprintf(vers[nvers++], 32, "%s", v);
        }
        closedir(md);
    }
    for (int i = 0; i < nvers; i++) {
        for (int j = i + 1; j < nvers; j++) {
            if (strcmp(vers[j], vers[i]) > 0) {
                char t[32];
                snprintf(t, sizeof(t), "%s", vers[i]);
                snprintf(vers[i], 32, "%s", vers[j]);
                snprintf(vers[j], 32, "%s", t);
            }
        }
    }
    if (nvers == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет mapping/*.cil — собрать нечего");
        return false;
    }

    // Числовые версии политики: дефолт гостевого secilc (31) и соседние.
    const char* polvers[] = {"31", "30", "29", "28", ""};
    char err[1024];
    for (int i = 0; i < nvers; i++) {
        for (size_t p = 0; p < sizeof(polvers) / sizeof(polvers[0]); p++) {
            unlink(out);
            if (run_secilc(rootfs, vers[i], polvers[p], out, err, sizeof(err))) {
                struct stat sst {};
                long sz = (stat(out, &sst) == 0) ? (long)sst.st_size : -1L;
                if (sz > 0) {
                    char final[700];
                    if (!guest_to_host("/sepolicy", final, sizeof(final))) {
                        snprintf(final, sizeof(final), "%s/sepolicy", rootfs);
                    }
                    unlink(final);
                    rename(out, final);
                    __android_log_print(ANDROID_LOG_INFO, TAG,
                                        "policy: собрана ГОСТЕВАЯ политика (mapping=%s, -c %s, %ld байт) -> %s",
                                        vers[i], polvers[p][0] ? polvers[p] : "(дефолт)", sz, final);
                    return true;
                }
            }
        }
    }
    unlink(out);
    __android_log_print(ANDROID_LOG_WARN, TAG, "policy: собрать НЕ удалось (ни одна пара mapping/-c не подошла)");
    return false;
}

static void mkdir_p_host(const char* path);

// Ставит гостевую политику по всем путям, которые читает libselinux:
//  * /sepolicy — монолитный путь (LoadMonolithicPolicy);
//  * /system/etc/selinux/precompiled_sepolicy — стандартное место GSI;
//  * /vendor/etc/selinux/precompiled_sepolicy (+ sha) — чтобы гость (split-путь)
//    нашёл готовую политику через FindPrecompiledSplitPolicy и НЕ звал secilc сам.
static bool install_guest_policy(const char* rootfs, const char* src) {
    // Каталоги гостя под политику: создаём и регистрируем в таблице.
    ensure_guest_dir("/vendor/etc/selinux", rootfs);
    layout_mark_trace("/vendor/etc/selinux");
    ensure_guest_dir("/system/etc/selinux", rootfs);
    layout_mark_trace("/system/etc/selinux");

    // Куда кладём готовую политику (ГОСТЕВЫЕ пути -> host по раскладке).
    // /vendor и /odm — стандартные места AOSP для precompiled-политики; в GSI их нет,
    // поэтому делаем гостевые (иначе FindPrecompiledSplitPolicy гостя не находит).
    const char* dsts_g[4] = {
        "/sepolicy",
        "/system/etc/selinux/precompiled_sepolicy",
        "/vendor/etc/selinux/precompiled_sepolicy",
        "/odm/etc/selinux/precompiled_sepolicy",
    };
    char dsts[4][700];
    for (int i = 0; i < 4; i++) {
        ensure_guest_parent(dsts_g[i], rootfs);
        if (!guest_to_host(dsts_g[i], dsts[i], sizeof(dsts[i]))) {
            snprintf(dsts[i], sizeof(dsts[i]), "%s", dsts_g[i]);
        }
    }

    int in = open(src, O_RDONLY);
    if (in < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет источника %s", src);
        return false;
    }
    // Читаем источник ЦЕЛИКОМ в память: иначе первый же dst (тот же файл) с O_TRUNC
    // обрезает то, что мы читаем (лог 15:32: «гостевая политика 0 байт»).
    size_t cap = 1 << 20;
    char* buf = (char*)malloc(cap);
    if (!buf) {
        close(in);
        return false;
    }
    size_t got = 0;
    ssize_t n;
    while (got + 1 < cap && (n = read(in, buf + got, cap - got - 1)) > 0) got += (size_t)n;
    close(in);
    if (got == 0) {
        free(buf);
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: источник %s пустой", src);
        return false;
    }

    bool ok = false;
    for (int i = 0; i < 4; i++) {
        int out = open(dsts[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out < 0) continue;
        ssize_t w = write(out, buf, got);
        close(out);
        __android_log_print(ANDROID_LOG_INFO, TAG, "policy: гостевая политика %zu байт -> %s", got,
                            dsts[i]);
        if (w == (ssize_t)got && i == 0) ok = true;
    }
    free(buf);

    // sha-файлы для FindPrecompiledSplitPolicy: гостю нужны пары plat и product.
    // Если какой-то файл отсутствует, гость молча уходит из split-ветки -> "Unable to load
    // SELinux policy" (лог 19:29). Значения копируем 1:1 из гостевой системы.
    //
    // product-раздела у GSI нет — готовим гостевой /product с согласованной product-sha
    // (иначе FindPrecompiledSplitPolicy гостя не пройдёт: лог 00:00 "Unable to load
    // SELinux policy").
    prepare_guest_product(rootfs);
    const char* sha_src_g[2] = {
        "/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
        "/product/etc/selinux/product_sepolicy_and_mapping.sha256",
    };
    // Куда кладём пары: и в vendor, и в odm (гость ищет precompiled там, где есть раздел).
    const char* sha_dst_g[4] = {
        "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
        "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256",
        "/odm/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
        "/odm/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256",
    };
    for (int i = 0; i < 4; i++) {
        int src_idx = i % 2;
        ensure_guest_parent(sha_dst_g[i], rootfs);
        char srcsha[700], dstsha[700];
        if (!guest_to_host(sha_src_g[src_idx], srcsha, sizeof(srcsha)) ||
            !guest_to_host(sha_dst_g[i], dstsha, sizeof(dstsha))) {
            continue;
        }
        int si = open(srcsha, O_RDONLY);
        if (si < 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "policy: нет %s — sha-пара неполная", srcsha);
            continue;
        }
        int so = open(dstsha, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (so >= 0) {
            char buf[512];
            ssize_t n;
            while ((n = read(si, buf, sizeof(buf))) > 0) {
                if (write(so, buf, (size_t)n) <= 0) break;
            }
            close(so);
            __android_log_print(ANDROID_LOG_INFO, TAG, "policy: sha-файл -> %s", dstsha);
        }
        close(si);
    }

    // Проверка: vendor-пара должна совпадать с гостевой (иначе FindPrecompiledSplitPolicy
    // гостя тихо вернёт false -> "Unable to load SELinux policy").
    {
        struct { const char* guest_actual; const char* guest_vendor; } pairs[2] = {
            {"/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
             "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256"},
            {"/product/etc/selinux/product_sepolicy_and_mapping.sha256",
             "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256"},
        };
        for (int i = 0; i < 2; i++) {
            char pa[700], pv[700];
            if (!guest_to_host(pairs[i].guest_actual, pa, sizeof(pa)) ||
                !guest_to_host(pairs[i].guest_vendor, pv, sizeof(pv))) {
                continue;
            }
            char ba[256] = {0}, bv[256] = {0};
            int fa = open(pa, O_RDONLY);
            int fv = open(pv, O_RDONLY);
            if (fa >= 0) { ssize_t n = read(fa, ba, sizeof(ba) - 1); if (n < 0) n = 0; ba[n] = 0; close(fa); }
            if (fv >= 0) { ssize_t n = read(fv, bv, sizeof(bv) - 1); if (n < 0) n = 0; bv[n] = 0; close(fv); }
            if (ba[0] && bv[0] && strcmp(ba, bv) == 0) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "policy: sha-пара %d совпадает (%s)", i, ba);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "policy: sha-пара %d НЕ совпадает: actual='%s' vendor='%s'", i,
                                    ba, bv);
            }
        }
    }

    // Версия mapping'а: на случай, если гость сам пойдёт в compile-ветку
    // (GetVendorMappingVersion читает /vendor/etc/selinux/plat_sepolicy_vers.txt).
    char vtxt[700];
    if (guest_to_host("/vendor/etc/selinux/plat_sepolicy_vers.txt", vtxt, sizeof(vtxt))) {
        int vf = open(vtxt, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (vf >= 0) {
            const char* line = "29.0\n";
            ssize_t w = write(vf, line, strlen(line));
            (void)w;
            close(vf);
            __android_log_print(ANDROID_LOG_INFO, TAG, "policy: версия mapping -> %s", vtxt);
        }
    }

    // System-версия mapping'а: гость сверяет её с vendor-версией — если не совпали,
    // он компилирует политику сам (ему нужен полный набор CIL).
    char svers[700];
    if (guest_to_host("/system/etc/selinux/plat_sepolicy_vers.txt", svers, sizeof(svers))) {
        int sf = open(svers, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (sf >= 0) {
            const char* line = "29.0\n";
            ssize_t w = write(sf, line, strlen(line));
            (void)w;
            close(sf);
            __android_log_print(ANDROID_LOG_INFO, TAG, "policy: system-версия mapping -> %s", svers);
        }
    }

    // Набор CIL для самостоятельной компиляции гостем: product/vendor/odm-разделов в GSI
    // нет — делаем пустые секции + product-mapping (копия system-mapping) и
    // versioned-public-политику (её гость тоже проверяет).
    {
        struct { const char* guest; const char* from; } cils[4] = {
            {"/product/etc/selinux/product_sepolicy.cil", nullptr},
            {"/vendor/etc/selinux/vendor_sepolicy.cil", nullptr},
            {"/odm/etc/selinux/odm_sepolicy.cil", nullptr},
            {"/vendor/etc/selinux/plat_pub_versioned.cil", nullptr},
        };
        for (int i = 0; i < 4; i++) {
            ensure_guest_parent(cils[i].guest, rootfs);
            char dst[700];
            if (!guest_to_host(cils[i].guest, dst, sizeof(dst))) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "policy: путь %s не найден в раскладке",
                                    cils[i].guest);
                continue;
            }
            struct stat st {};
            if (stat(dst, &st) == 0 && st.st_size > 0) continue;
            int df = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (df >= 0) {
                close(df);
                __android_log_print(ANDROID_LOG_INFO, TAG, "policy: пустая CIL-секция гостя -> %s", dst);
            }
        }
        // product-mapping: копия system-mapping той же версии.
        ensure_guest_dir("/product/etc/selinux/mapping", rootfs);
        char pm[700], sm[700];
        if (guest_to_host("/product/etc/selinux/mapping/29.0.cil", pm, sizeof(pm)) &&
            guest_to_host("/system/etc/selinux/mapping/29.0.cil", sm, sizeof(sm))) {
            struct stat st {};
            if (stat(pm, &st) != 0) {
                int in = open(sm, O_RDONLY);
                if (in >= 0) {
                    char buf[8192];
                    ssize_t n;
                    int out = open(pm, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    while (out >= 0 && (n = read(in, buf, sizeof(buf))) > 0) {
                        if (write(out, buf, (size_t)n) <= 0) break;
                    }
                    if (out >= 0) close(out);
                    close(in);
                    __android_log_print(ANDROID_LOG_INFO, TAG, "policy: product-mapping гостя -> %s", pm);
                }
            }
        }
    }

    // AOSP 10: FindPrecompiledSplitPolicy проверяет ДВЕ пары sha — plat и product.
    // system_ext-пара нужна только в AOSP 11+ — гостю (AOSP 10) она не требуется.
    return ok;
}

// Подготовка гостевой ФС внутри rootfs: каталоги, симлинки на реальные устройства
// хоста (абсолютные -> ядро откроет настоящий узел), монолитная SELinux-политика.
static void mkdir_p_host(const char* path) {
    char tmp[700];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t n = strlen(tmp);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void prepare_guest_fs(const char* rootfs) {
    if (!rootfs || !rootfs[0]) return;
    char p[700];

    // Каталоги и симлинки гостевой ФС создаёт build_guest_layout() по раскладке.
    report_guest_selinux(rootfs);
    char pol[700];
    char src[700];
    char vsrc[700];
    if (!guest_to_host("/sepolicy", pol, sizeof(pol))) {
        snprintf(pol, sizeof(pol), "%s/sepolicy", rootfs);
    }
    if (!guest_to_host("/system/etc/selinux/precompiled_sepolicy", src, sizeof(src))) {
        snprintf(src, sizeof(src), "%s/system/etc/selinux/precompiled_sepolicy", rootfs);
    }
    if (!guest_to_host("/vendor/etc/selinux/precompiled_sepolicy", vsrc, sizeof(vsrc))) {
        snprintf(vsrc, sizeof(vsrc), "%s/vendor/etc/selinux/precompiled_sepolicy", rootfs);
    }

    // Остатки прошлых прогонов (в т.ч. ПУСТЫЕ файлы) не должны считаться политикой —
    // иначе гость получит нулевую политику. Чистим и всегда собираем заново при нужде.
    struct stat st0 {};
    const char* leftovers[3] = {src, vsrc, pol};
    for (int i = 0; i < 3; i++) {
        if (stat(leftovers[i], &st0) == 0 && st0.st_size == 0) {
            unlink(leftovers[i]);
            __android_log_print(ANDROID_LOG_WARN, TAG, "policy: удалён пустой файл %s", leftovers[i]);
        }
    }

    char platcil[700];
    if (!guest_to_host("/system/etc/selinux/plat_sepolicy.cil", platcil, sizeof(platcil))) {
        snprintf(platcil, sizeof(platcil), "%s/system/etc/selinux/plat_sepolicy.cil", rootfs);
    }
    log_file_head(platcil);

    bool installed = false;
    if (access(src, R_OK) == 0) {
        installed = install_guest_policy(rootfs, src);
    }
    if (!installed && is_binary_policy(platcil)) {
        installed = install_guest_policy(rootfs, platcil);
    }
    if (!installed) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "policy: прекомпилированной нет — компилируем гостевым secilc");
        if (compile_guest_policy(rootfs)) {
            install_guest_policy(rootfs, pol);
        }
    }
}

// SIGSYS handler: force_sig (SECCOMP_RET_TRAP) доставляет его даже там, где SIG_IGN не
// работает (лог 13:40: init умер на mount при SIG_IGN). Syscall при TRAP НЕ выполняется;
// после возврата handler'а ядро возвращает -ENOSYS. Выживает через execve, наследуется init'ом.
static void a10_sigsys_handler(int sig, siginfo_t* info, void* uctx) {
    (void)sig;
    (void)uctx;
    const char* cf = getenv("A10_CONSOLE_FD");
    int fd = (cf && *cf) ? atoi(cf) : -1;
    long nr = info ? (long)info->si_syscall : -1;
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "=== SIGSYS caught: host blocked syscall %ld -> ENOSYS ===\n", nr);
    if (fd >= 0 && n > 0) {
        ssize_t w = write(fd, buf, (size_t)n);
        (void)w;
    }
}

// Результат exec-пробы LD_PRELOAD.
enum { PROBE_ERROR = -1, PROBE_NOT_LOADED = 0, PROBE_LOADED = 1, PROBE_HUNG = 2 };

// fork -> потомок exec'ает СЕБЯ ЖЕ (argc<2 -> мгновенный exit) с LD_PRELOAD в env.
// Лог 13:20: exec+LD_PRELOAD из nativeLibDir ВИСНЕТ в линкере (как seccomp() на этом
// устройстве), хотя dlopen того же файла в стабе проходит мгновенно. Пробы позволяют
// (1) проверить путь ДО запуска init и (2) выбрать рабочий путь для init.
//   PROBE_LOADED    — конструктор отработал при exec (написал ok-файл) — путь годится.
//   PROBE_NOT_LOADED — потомок дошёл до main, но preload линкер молча НЕ загрузил.
//   PROBE_HUNG      — нет ok-файла и нет exit за 1500мс: зависание ДО/В конструкторе; убит.
static int run_ld_preload_probe(const char* label, const char* preload_path, const char* ok_file,
                                int console_fd, int sup_sock,
                                char* env_android_root, char* env_path, char* env_ld_library_path,
                                const char* ld_debug_env, const char* rootfs_dir,
                                const char* mounts_file_env) {
    if (console_fd >= 0) {
        char m[640];
        int n = snprintf(m, sizeof(m), "=== LD_PRELOAD exec-probe %s: exec self with %s ===\n", label, preload_path);
        if (n > 0) { ssize_t w = write(console_fd, m, (size_t)n); (void)w; }
    }
    pid_t pp = fork();
    if (pp == 0) {
        if (sup_sock >= 0) close(sup_sock);
        char selfbuf[512];
        ssize_t sl = readlink("/proc/self/exe", selfbuf, sizeof(selfbuf) - 1);
        if (sl <= 0) _exit(126);
        selfbuf[sl] = 0;
        char env_ld[1024];
        snprintf(env_ld, sizeof(env_ld), "LD_PRELOAD=%s", preload_path);
        char env_label[64];
        snprintf(env_label, sizeof(env_label), "A10_PROBE_LABEL=%s", label);
        char env_okfile[600];
        snprintf(env_okfile, sizeof(env_okfile), "A10_PROBE_OK_FILE=%s", ok_file);
        // A10_CONSOLE_FD ОБЯЗАТЕЛЕН в потомке пробы: без него конструктор preload и маркер
        // "child reached main" слепы (лог 13:40 — ни одного байта от обеих проб).
        char env_console[64];
        env_console[0] = 0;
        if (console_fd >= 0) {
            snprintf(env_console, sizeof(env_console), "A10_CONSOLE_FD=%d", console_fd);
        }
        // A10_ROOTFS: preload переводит пути гостя в корень гостевой ФС.
        char env_rootfs[600];
        env_rootfs[0] = 0;
        if (rootfs_dir && rootfs_dir[0]) {
            snprintf(env_rootfs, sizeof(env_rootfs), "A10_ROOTFS=%s", rootfs_dir);
        }
        // A10_MOUNTS_FILE: mount-таблица гостя (превод путей).
        char env_mounts[800];
        env_mounts[0] = 0;
        if (mounts_file_env && mounts_file_env[0]) {
            snprintf(env_mounts, sizeof(env_mounts), "A10_MOUNTS_FILE=%s", mounts_file_env);
        }
        char* pe[14];
        int ei = 0;
        pe[ei++] = env_android_root;
        pe[ei++] = env_path;
        pe[ei++] = env_ld_library_path;
        pe[ei++] = env_ld;
        if (ld_debug_env && ld_debug_env[0]) pe[ei++] = (char*)ld_debug_env;
        pe[ei++] = env_label;
        pe[ei++] = env_okfile;
        if (env_console[0]) pe[ei++] = env_console;
        if (env_rootfs[0]) pe[ei++] = env_rootfs;
        if (env_mounts[0]) pe[ei++] = env_mounts;
        pe[ei] = nullptr;
        char* const pargv[] = { selfbuf, nullptr };
        execve(selfbuf, pargv, pe);
        _exit(127);
    }
    if (pp < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "probe %s: fork failed errno=%d (%s)", label, errno, strerror(errno));
        return PROBE_ERROR;
    }
    int pst = 0;
    pid_t wr = 0;
    int waited = 0;
    bool ok_seen = false;
    struct stat st {};
    while (waited < 1500) {
        // ok-файл пишется raw-сисколлом ПЕРВЫМ делом конструктора: появился — линкер
        // загрузил preload. Проверяем РАНЬШЕ exit: потомок пробы может зависнуть позже
        // (например в main на logd) — это уже не отказ линкера.
        if (stat(ok_file, &st) == 0) { ok_seen = true; break; }
        wr = waitpid(pp, &pst, WNOHANG);
        if (wr == pp) break;
        usleep(20000);
        waited += 20;
    }
    if (ok_seen) {
        kill(pp, SIGKILL); // грузить preload научились — потомок пробы больше не нужен
        waitpid(pp, &pst, 0);
        unlink(ok_file);
        __android_log_print(ANDROID_LOG_INFO, TAG, "probe %s: LOADED (constructor ran at exec, ok-file written) - path works!", label);
        if (console_fd >= 0) {
            const char* m = "=== LD_PRELOAD exec-probe: constructor LOADED at exec - path WORKS ===\n";
            ssize_t w = write(console_fd, m, strlen(m));
            (void)w;
        }
        return PROBE_LOADED;
    }
    if (wr == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "probe %s: child hung >1500ms WITHOUT ok-file (hang before/during preload constructor) - killing", label);
        kill(pp, SIGKILL);
        waitpid(pp, &pst, 0);
        if (console_fd >= 0) {
            const char* m = "=== LD_PRELOAD exec-probe: child HUNG before any constructor output (no ok-file) ===\n";
            ssize_t w = write(console_fd, m, strlen(m));
            (void)w;
        }
        return PROBE_HUNG;
    }
    if (wr != pp) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "probe %s: waitpid failed errno=%d (%s)", label, errno, strerror(errno));
        return PROBE_ERROR;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "probe %s: child exited (status=0x%x) but preload NOT loaded (no ok-file; linker skipped it)", label, pst);
    if (console_fd >= 0) {
        const char* m = "=== LD_PRELOAD exec-probe: child reached main, but preload NOT loaded (no 'LOADED' above) ===\n";
        ssize_t w = write(console_fd, m, strlen(m));
        (void)w;
    }
    return PROBE_NOT_LOADED;
}

// Минимальный bootstrap-stub "новой системы".
// Запускается как контролируемый host-процесс перед гостевым init.
// Аргументы:
//   argv[1] = путь к guest init
//   argv[2] = rootfs dir (для будущего окружения/перехвата)
//   argv[3...] = дополнительные аргументы guest init (опционально)

int main(int argc, char** argv) {
    // В exec-пробе (argc<2 + A10_PROBE_LABEL) logd-вызовы ЗАПРЕЩЕНЫ: проба должна
    // показывать поведение линкера, а не зависать на нашем первом логе.
    const char* probe_label_env = getenv("A10_PROBE_LABEL");
    bool in_probe = (probe_label_env && probe_label_env[0]);
    if (!in_probe) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "stub start pid=%d uid=%d gid=%d argc=%d", getpid(), (int)getuid(), (int)getgid(), argc);
    }
    if (argc < 2) {
        if (!in_probe) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "usage: a10stub <guest_init_path> [rootfs_dir] [guest args...]");
        }
        // Маркер для LD_PRELOAD exec-пробы: конструктор preload должен был отработать
        // ВЫШЕ этой строки, если линкер загрузил LD_PRELOAD при exec.
        const char* cf = getenv("A10_CONSOLE_FD");
        if (cf && *cf) {
            int cfd = atoi(cf);
            if (cfd >= 0) {
                const char* lbl = probe_label_env;
                char m[192];
                int n = snprintf(m, sizeof(m), "=== exec-probe %s: child reached main ===\n", lbl ? lbl : "?");
                if (n > 0) {
                    ssize_t w = write(cfd, m, (size_t)n);
                    (void)w;
                }
            }
        }
        return 64;
    }

    const char* init_path = argv[1];
    const char* rootfs_dir = (argc >= 3) ? argv[2] : "";
    __android_log_print(ANDROID_LOG_INFO, TAG, "target init=%s rootfs=%s", init_path, rootfs_dir);

    // init бывает симлинком гостя ("/init" -> "/system/bin/init"): execve через симлинк
    // упирается в ENOENT, поэтому резолвим путь в настоящий файл.
    char init_real[PATH_MAX];
    init_real[0] = 0;
    if (realpath(init_path, init_real) != nullptr && init_real[0]) {
        if (strcmp(init_real, init_path) != 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "init symlink resolved: %s -> %s", init_path,
                                init_real);
        }
        init_path = init_real;
    }

    struct stat st {};
    if (stat(init_path, &st) == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "init stat ok: mode=0%o size=%lld", (unsigned)st.st_mode, (long long)st.st_size);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "init stat failed: %s (%s)", init_path, strerror(errno));
    }

    // Место для in-process перехвата (seccomp user-notif / SIGSYS / preload/env setup).
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "PR_SET_DUMPABLE: %s", strerror(errno));
    }

    const char* mode = getenv("A10_STUB_MODE");
    const char* sup_fd_env = getenv("A10_SUPERVISOR_FD");
    int sup_sock = (sup_fd_env && *sup_fd_env) ? atoi(sup_fd_env) : -1;
    const char* con_fd_env = getenv("A10_CONSOLE_FD");
    int console_fd = (con_fd_env && *con_fd_env) ? atoi(con_fd_env) : -1;
    const char* nlib_dir_env = getenv("A10_NATIVE_LIB_DIR");
    __android_log_print(ANDROID_LOG_INFO, TAG, "stub mode=%s supervisor_fd=%s console_fd=%d native_lib_dir=%s",
                        mode ? mode : "(unset)", sup_fd_env ? sup_fd_env : "(unset)",
                        console_fd, nlib_dir_env ? nlib_dir_env : "(unset)");

    // SIGSYS: НАСТОЯЩИЙ handler вместо SIG_IGN. force_sig (SECCOMP_RET_TRAP) игнорирует
    // SIG_IGN — init умер на mount даже с SIG_IGN (лог 13:40, Fatal signal 31 syscall 40).
    // Установленный handler force_sig доставляет; после его возврата ядро вернёт -ENOSYS
    // из заблокированного syscall'а. Установка ДО seccomp-этапа (worker'а).
    struct sigaction sa {};
    sa.sa_sigaction = a10_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "SIGSYS handler installed (survives exec; host-blocked syscall returns ENOSYS)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "sigaction(SIGSYS) failed: %s", strerror(errno));
    }

    // seccomp user-notif: выполняется ниже, в fork-потомке (worker), чтобы смерть на
    // syscall seccomp (если хост её устроит) не убивала весь launch.


    // argv для guest: argv[0]="init", далее пользовательские аргументы если есть
    int guest_argc = 1;
    if (argc > 3) guest_argc += (argc - 3);
    char** gargv = (char**)malloc(sizeof(char*) * (guest_argc + 1));
    if (!gargv) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "malloc argv failed");
        return 70;
    }
    gargv[0] = (char*)"init";
    int gi = 1;
    for (int i = 3; i < argc; i++) gargv[gi++] = argv[i];
    gargv[gi] = nullptr;

    // ---- Раскладка гостя: скан корня гостевой ФС -> mount-таблица ----
    // Таблица — единственный источник правды по путям: preload по ней переводит любой
    // путь гостя, а гость сам дополняет её своими mount()/mknod().
    char table_path[700];
    table_path[0] = 0;
    if (rootfs_dir && rootfs_dir[0]) {
        // Путь к таблице известен заранее — гость должен получить его в env ДО старта.
        snprintf(table_path, sizeof(table_path), "%s/a10_mounts", rootfs_dir);
        scan_guest_root(rootfs_dir);
    }

    // Базовое окружение для guest init: пути к библиотекам rootfs, чтобы linker нашёл
    // зависимости. Всё строится по таблице (никаких путей «по умолчанию»).
    char env_android_root[512];
    char host_system[700];
    if (rootfs_dir && rootfs_dir[0] && guest_to_host("/system", host_system, sizeof(host_system))) {
        snprintf(env_android_root, sizeof(env_android_root), "ANDROID_ROOT=%s", host_system);
    } else {
        snprintf(env_android_root, sizeof(env_android_root), "ANDROID_ROOT=%s",
                 rootfs_dir && rootfs_dir[0] ? rootfs_dir : "/system");
    }
    char guest_path[512];
    build_guest_path(guest_path, sizeof(guest_path));
    char env_path[600];
    snprintf(env_path, sizeof(env_path), "PATH=%s", guest_path);

    // LD_LIBRARY_PATH: библиотеки rootfs (64/32-bit), чтобы linker не падал на libbacktrace.so и др.
    char guest_libpath[900];
    build_guest_ld_library_path(rootfs_dir, guest_libpath, sizeof(guest_libpath));
    char env_ld_library_path[1024];
    snprintf(env_ld_library_path, sizeof(env_ld_library_path), "LD_LIBRARY_PATH=%s", guest_libpath);

    // Таблица раскладки — гостю (preload читает её по A10_MOUNTS_FILE).
    char env_mounts_file[800];
    env_mounts_file[0] = 0;
    if (table_path[0]) {
        snprintf(env_mounts_file, sizeof(env_mounts_file), "A10_MOUNTS_FILE=%s", table_path);
    }

    // Подготовка гостевой ФС: политика гостя (/sepolicy и прекомпилированная).
    // Корнем гостя становится rootfs (cwd + A10_ROOTFS для preload'а).
    prepare_guest_fs(rootfs_dir);
    // Таблица гостя — итоговая (после подготовки ФС): её читает preload (A10_MOUNTS_FILE).
    if (rootfs_dir && rootfs_dir[0]) {
        write_mount_table(rootfs_dir, table_path, sizeof(table_path));
    }
    if (rootfs_dir && rootfs_dir[0]) {
        if (chdir(rootfs_dir) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "chdir(%s) failed: %s", rootfs_dir, strerror(errno));
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "guest root = %s (cwd)", rootfs_dir);
        }
    }
    char env_rootfs[600];
    env_rootfs[0] = 0;
    if (rootfs_dir && rootfs_dir[0]) {
        snprintf(env_rootfs, sizeof(env_rootfs), "A10_ROOTFS=%s", rootfs_dir);
    }

    // ---- Кандидаты LD_PRELOAD ----
    // A: nativeLibDir APK (/data/app/~~.../lib/arm64) — useLegacyPackaging распаковывает.
    // B: rootfs lib64 (/data/.../files/aosp/lib64) — путь внутри LD_LIBRARY_PATH гостя.
    // dlopen-тест A информативный, но ВЫБОР делает exec-проба: exec+LD_PRELOAD может
    // виснуть в линкере (как seccomp() на этом устройстве), а dlopen — нет.
    char cand_a[512];
    char cand_b[512];
    cand_a[0] = 0;
    cand_b[0] = 0;
    if (nlib_dir_env && *nlib_dir_env) {
        snprintf(cand_a, sizeof(cand_a), "%s/liba10preload.so", nlib_dir_env);
    }
    if (rootfs_dir && rootfs_dir[0]) {
        snprintf(cand_b, sizeof(cand_b), "%s/lib64/liba10preload.so", rootfs_dir);
    }
    if (cand_a[0]) {
        struct stat cst {};
        if (stat(cand_a, &cst) != 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "preload candidate A missing: %s (%s)", cand_a, strerror(errno));
            cand_a[0] = 0;
        } else {
            void* h = dlopen(cand_a, RTLD_NOW | RTLD_LOCAL);
            if (h) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "dlopen preload A OK: %s (constructor ran, dlclose)", cand_a);
                dlclose(h);
            } else {
                const char* dlerr = dlerror();
                __android_log_print(ANDROID_LOG_ERROR, TAG, "dlopen preload A FAILED: %s: %s", cand_a, dlerr ? dlerr : "(no dlerror text)");
                cand_a[0] = 0;
            }
        }
    }
    if (cand_b[0]) {
        struct stat cst {};
        if (stat(cand_b, &cst) != 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "preload candidate B missing: %s (%s)", cand_b, strerror(errno));
            cand_b[0] = 0;
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "preload candidate B present: %s", cand_b);
        }
    }

    // filesDir для ok-файлов проб: rootfs_dir = <filesDir>/aosp -> срезаем "aosp".
    char files_dir[512];
    snprintf(files_dir, sizeof(files_dir), "/data/user/0/com.android.emulA10/files");
    if (rootfs_dir && rootfs_dir[0]) {
        size_t rl = strlen(rootfs_dir);
        if (rl > 5 && strcmp(rootfs_dir + rl - 5, "/aosp") == 0) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%.*s", (int)(rl - 5), rootfs_dir);
            snprintf(files_dir, sizeof(files_dir), "%s", tmp);
        }
    }
    char ok_file_a[576];
    char ok_file_b[576];
    snprintf(ok_file_a, sizeof(ok_file_a), "%s/probe_A_ok", files_dir);
    snprintf(ok_file_b, sizeof(ok_file_b), "%s/probe_B_ok", files_dir);
    unlink(ok_file_a);
    unlink(ok_file_b);

    // LD_DEBUG=dynamic: ТОЛЬКО по маркер-файлу files/enable_ld_debug (диагностика).
    // ВАЖНО: невалидная категория (например "libs") убивает процесс usage'ом (лог 12:56);
    // на штатном прогоне трассировка выключена — в 13:40 она дала 4000+ строк шума,
    // дублирующихся в A10_Guest.
    bool want_ld_debug = false;
    {
        char marker[600];
        snprintf(marker, sizeof(marker), "%s/enable_ld_debug", files_dir);
        struct stat mst {};
        if (stat(marker, &mst) == 0) want_ld_debug = true;
    }
    char env_ld_debug[64];
    env_ld_debug[0] = 0;
    if (want_ld_debug) {
        snprintf(env_ld_debug, sizeof(env_ld_debug), "LD_DEBUG=dynamic");
        __android_log_print(ANDROID_LOG_INFO, TAG, "LD_DEBUG=dynamic ON (marker file files/enable_ld_debug present)");
    }

    // ---- Exec-пробы LD_PRELOAD: выбираем рабочий путь для init ----
    // Потомок exec'ает СЕБЯ ЖЕ. Если линкер при exec загрузил preload — конструктор
    // пишет в консоль "LOADED" и ok-файл. Молча пропустил — потомок в main без него.
    // Заблокирован хостом — висим >1500мс и убиваем (иначе init молчал бы 19-25 сек).
    char preload_path[512];
    preload_path[0] = 0;
    if (cand_a[0]) {
        int r = run_ld_preload_probe("A", cand_a, ok_file_a, console_fd, sup_sock,
                                     env_android_root, env_path, env_ld_library_path,
                                     want_ld_debug ? env_ld_debug : nullptr, rootfs_dir,
                                     env_mounts_file);
        if (r == PROBE_LOADED) snprintf(preload_path, sizeof(preload_path), "%s", cand_a);
    }
    if (!preload_path[0] && cand_b[0]) {
        int r = run_ld_preload_probe("B", cand_b, ok_file_b, console_fd, sup_sock,
                                     env_android_root, env_path, env_ld_library_path,
                                     want_ld_debug ? env_ld_debug : nullptr, rootfs_dir,
                                     env_mounts_file);
        if (r == PROBE_LOADED) snprintf(preload_path, sizeof(preload_path), "%s", cand_b);
    }
    if (preload_path[0]) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "exec-probe winner: LD_PRELOAD=%s (for init)", preload_path);
    } else {
        // Ни одна проба не загрузила preload при exec -> init запускаем БЕЗ LD_PRELOAD:
        // с preload его линкер виснет навсегда (так init молчал 19-25 сек 13:05/13:20).
        __android_log_print(ANDROID_LOG_WARN, TAG, "exec-probes FAILED (A and B) - init runs WITHOUT LD_PRELOAD (else linker hangs)");
        if (console_fd >= 0) {
            const char* m = "=== both exec-probes failed: init runs WITHOUT LD_PRELOAD ===\n";
            ssize_t w = write(console_fd, m, strlen(m));
            (void)w;
        }
    }

    // A10_CONSOLE_FD нужен и ВНУТРИ init: preload-конструктор читает его из env,
    // чтобы перехватить /dev/kmsg и писать в нашу консоль (иначе init слеп).
    char env_guest_console[64];
    env_guest_console[0] = 0;
    if (console_fd >= 0) {
        snprintf(env_guest_console, sizeof(env_guest_console), "A10_CONSOLE_FD=%d", console_fd);
    }

    char env_ld_preload[1024];
    env_ld_preload[0] = 0;
    if (preload_path[0]) {
        snprintf(env_ld_preload, sizeof(env_ld_preload), "LD_PRELOAD=%s", preload_path);
    }

    char* envp[14];
    int eic = 0;
    envp[eic++] = env_android_root;
    envp[eic++] = env_path;
    envp[eic++] = env_ld_library_path;
    if (env_ld_preload[0]) {
        envp[eic++] = env_ld_preload;
    }
    if (want_ld_debug) {
        envp[eic++] = env_ld_debug;
    }
    if (env_guest_console[0]) {
        envp[eic++] = env_guest_console;
    }
    if (env_rootfs[0]) {
        envp[eic++] = env_rootfs;
    }
    if (env_mounts_file[0]) {
        envp[eic++] = env_mounts_file;
    }
    envp[eic] = nullptr;

    // Дамп финального env в консоль (A10_Guest): точно видно, что реально получит init.
    if (console_fd >= 0) {
        char buf[1100];
        for (int i = 0; envp[i]; i++) {
            int n = snprintf(buf, sizeof(buf), "[env] %s\n", envp[i]);
            if (n > 0) {
                ssize_t w = write(console_fd, buf, (size_t)n);
                (void)w;
            }
        }
    }

    // ---- seccomp user-notif: ОБЯЗАТЕЛЬНЫЙ этап (в fork-потомке) ----
    if (sup_sock >= 0) {
        int ackfd[2] = {-1, -1};
        bool have_ack = pipe2(ackfd, O_CLOEXEC) == 0;
        if (!have_ack) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "pipe2(ack) failed errno=%d (%s) - seccomp stage без ack невозможен, fallback", errno, strerror(errno));
        }
        pid_t wp = have_ack ? fork() : -1;
        if (wp == 0) {
            // === потомок: seccomp worker — ставит фильтр, передаёт notify_fd супервизору, exec'ает init ===
            int nfd = install_user_notif_filter();
            if (nfd < 0) _exit(2);

            struct msghdr msg {};
            struct iovec iov {};
            char dummy = 'N';
            iov.iov_base = &dummy;
            iov.iov_len = 1;
            char cmsgbuf[CMSG_SPACE(sizeof(int))];
            memset(cmsgbuf, 0, sizeof(cmsgbuf));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsgbuf;
            msg.msg_controllen = sizeof(cmsgbuf);
            struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &nfd, sizeof(int));
            ssize_t sn = sendmsg(sup_sock, &msg, 0);
            if (sn < 0) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "[worker] send notify_fd failed errno=%d (%s)", errno, strerror(errno));
                _exit(3);
            }
            __android_log_print(ANDROID_LOG_INFO, TAG, "[worker] notify_fd=%d sent to supervisor (handoff ok), exec'ing guest", nfd);
            close(nfd);
            close(sup_sock);
            setup_guest_console(console_fd, "seccomp");
            char ok = 'O';
            ssize_t an = write(ackfd[1], &ok, 1);
            (void)an;
            execve(init_path, gargv, envp);
            __android_log_print(ANDROID_LOG_ERROR, TAG, "[worker] execve guest failed: %s errno=%d (%s)", init_path, errno, strerror(errno));
            _exit(126);
        }
        // === родитель: ждём ack С ТАЙМАУТОМ; 'O' = фильтр установлен, потомок стал guest init ===
        // Таймаут обязателен: если хостовый seccomp БЛОКИРУЕТ syscall seccomp (а не убивает),
        // worker зависнет на нём навсегда — без таймаута завис и весь launch (так и было 12:43).
        char ackc = 0;
        ssize_t rn = -1;
        if (have_ack) {
            close(ackfd[1]);
            struct pollfd pfd = { ackfd[0], POLLIN, 0 };
            int pr = poll(&pfd, 1, 1000);
            if (pr == 1 && (pfd.revents & POLLIN)) {
                do { rn = read(ackfd[0], &ackc, 1); } while (rn < 0 && errno == EINTR);
            } else if (pr == 0) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "seccomp worker did not ack in 1000ms (likely blocked on seccomp() syscall)");
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "poll(ack) failed errno=%d (%s)", errno, strerror(errno));
            }
            close(ackfd[0]);
        }
        close(sup_sock); // loader-супервизор корректно завершится, если notify_fd не пришёл
        int wst = 0;
        if (rn != 1) {
            kill(wp, SIGKILL); // worker мог зависнуть на seccomp(); если уже мёртв — не страшно
        }
        waitpid(wp, &wst, 0);
        if (rn == 1 && ackc == 'O') {
            if (WIFEXITED(wst)) {
                int code = WEXITSTATUS(wst);
                __android_log_print(ANDROID_LOG_INFO, TAG, "guest init exited code=%d", code);
                return code;
            }
            if (WIFSIGNALED(wst)) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "guest init killed by signal %d", WTERMSIG(wst));
                return 128 + WTERMSIG(wst);
            }
            return 0;
        }
        if (rn != 1 || ackc != 'O') {
            __android_log_print(ANDROID_LOG_WARN, TAG, "seccomp stage failed (ack %s, worker %s) - fallback: LD_PRELOAD + SIGSYS only",
                                rn == 0 ? "EOF (worker died)" : (rn < 0 ? "TIMEOUT (worker hung)" : "bad"),
                                WIFSIGNALED(wst) ? "killed" : "exited");
        }
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "no supervisor socket - seccomp stage skipped, direct exec");
    }

    setup_guest_console(console_fd, sup_sock >= 0 ? "fallback" : "direct");
    execve(init_path, gargv, envp);
    int e = errno;
    __android_log_print(ANDROID_LOG_ERROR, TAG, "execve guest failed: %s errno=%d (%s)", init_path, e, strerror(e));
    return 126;
}
