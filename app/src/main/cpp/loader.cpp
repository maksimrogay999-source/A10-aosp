#include "loader.h"
#include "ptrace_intercept.h"
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <atomic>
#include <mutex>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <cerrno>
#include <cstring>
#include <thread>
#include <vector>
#include <dirent.h>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef SYS_memfd_create
#ifdef __aarch64__
#define SYS_memfd_create 279
#else
#define SYS_memfd_create 385
#endif
#endif
#ifndef SYS_execveat
#ifdef __aarch64__
#define SYS_execveat 281
#else
#define SYS_execveat 387
#endif
#endif

#define TAG "A10_Loader"

static pid_t g_init_pid = -1;
// Console reader ставит true на EOF (гость закрыл stdio / умер) — для UI и loader_guest_alive().
static std::atomic<bool> g_guest_exited{false};
static bool g_initialized = false;
static std::string g_rootfs_dir;
static std::string g_native_lib_dir;
static std::string g_last_error;
static std::mutex g_mutex;
static std::atomic<bool> g_tracer_running{false};

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW(SECCOMP_IOC_MAGIC, 2, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

// Совместимые минимальные определения (размеры уточняем через SECCOMP_GET_NOTIF_SIZES).
struct A10SeccompData { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; };
struct A10SeccompNotifSizes { __u16 seccomp_notif; __u16 seccomp_notif_resp; __u16 seccomp_data; };
struct A10SeccompNotif { __u64 id; __u32 pid; __u32 flags; A10SeccompData data; };
struct A10SeccompNotifResp { __u64 id; __s64 val; __s32 error; __u32 flags; };

static int recv_fd_from_socket(int sock) {
    char dummy = 0;
    struct iovec iov { &dummy, 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    ssize_t n = recvmsg(sock, &msg, 0);
    if (n <= 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "recvmsg(supervisor fd) failed: n=%zd errno=%d (%s)", n, errno, strerror(errno));
        return -1;
    }
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "recvmsg: no SCM_RIGHTS");
        return -1;
    }
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static void seccomp_supervisor_loop(int notify_fd) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: loop start notify_fd=%d", notify_fd);
    A10SeccompNotifSizes sizes {};
    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: sizes notif=%u resp=%u data=%u", sizes.seccomp_notif, sizes.seccomp_notif_resp, sizes.seccomp_data);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "supervisor: GET_NOTIF_SIZES failed errno=%d (%s)", errno, strerror(errno));
    }
    size_t req_sz = std::max<size_t>(sizes.seccomp_notif ? sizes.seccomp_notif : 0, sizeof(A10SeccompNotif));
    size_t resp_sz = std::max<size_t>(sizes.seccomp_notif_resp ? sizes.seccomp_notif_resp : 0, sizeof(A10SeccompNotifResp));
    std::vector<unsigned char> reqbuf(req_sz, 0), respbuf(resp_sz, 0);
    auto* req = reinterpret_cast<A10SeccompNotif*>(reqbuf.data());
    auto* resp = reinterpret_cast<A10SeccompNotifResp*>(respbuf.data());
    int handled = 0;
    while (true) {
        memset(reqbuf.data(), 0, reqbuf.size());
        errno = 0;
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            int e = errno;
            if (e == EINTR) continue;
            if (e == ENOENT) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: target gone (ENOENT), handled=%d", handled);
            } else {
                __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: RECV failed errno=%d (%s), handled=%d", e, strerror(e), handled);
            }
            break;
        }
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "supervisor: notif id=%llu pid=%u nr=%d ip=0x%llx args=[%llu,%llu,%llu,%llu,%llu,%llu]",
            (unsigned long long)req->id, req->pid, req->data.nr,
            (unsigned long long)req->data.instruction_pointer,
            (unsigned long long)req->data.args[0], (unsigned long long)req->data.args[1],
            (unsigned long long)req->data.args[2], (unsigned long long)req->data.args[3],
            (unsigned long long)req->data.args[4], (unsigned long long)req->data.args[5]);

        // Валидация (TOCTOU): цель могла умереть
        errno = 0;
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) != 0) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "supervisor: id invalid for notif id=%llu errno=%d", (unsigned long long)req->id, errno);
            continue;
        }

        memset(respbuf.data(), 0, respbuf.size());
        resp->id = req->id;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // allow: выполнить syscall как обычно
        resp->error = 0;
        resp->val = 0;
        errno = 0;
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) != 0) {
            int e = errno;
            if (e == ENOENT) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: SEND ENOENT (target gone) id=%llu", (unsigned long long)req->id);
                break;
            }
            __android_log_print(ANDROID_LOG_WARN, TAG, "supervisor: SEND failed id=%llu errno=%d (%s)", (unsigned long long)req->id, e, strerror(e));
        } else {
            handled++;
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "supervisor: continued id=%llu nr=%d", (unsigned long long)req->id, req->data.nr);
        }
    }
    close(notify_fd);
    __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: loop end handled=%d", handled);
}

static void start_console_reader_thread(int fd) {
    std::thread([fd]() {
        __android_log_print(ANDROID_LOG_INFO, TAG, "console reader: start (fd=%d) -> logcat tag=A10_Guest", fd);
        std::string line;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n') {
                    if (!line.empty()) {
                        __android_log_print(ANDROID_LOG_INFO, "A10_Guest", "%s", line.c_str());
                        line.clear();
                    }
                } else if (c != '\r' && line.size() < 4000) {
                    line += c;
                }
            }
        }
        if (!line.empty()) __android_log_print(ANDROID_LOG_INFO, "A10_Guest", "%s", line.c_str());
        if (n < 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "console reader: read failed errno=%d (%s)", errno, strerror(errno));
        }
        __android_log_print(ANDROID_LOG_INFO, TAG, "console reader: EOF (guest stdio closed / init exited)");
        g_guest_exited.store(true); // для UI: авто-переключение Start/Stop
        close(fd);
    }).detach();
}

static void start_supervisor_receiver_thread(int sock) {
    std::thread([sock]() {
        __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: waiting for notify fd on socket=%d", sock);
        int nfd = recv_fd_from_socket(sock);
        close(sock);
        if (nfd < 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "supervisor: no notify fd received, supervisor not started");
            return;
        }
        __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor: received notify_fd=%d", nfd);
        seccomp_supervisor_loop(nfd);
    }).detach();
}

bool loader_init(const std::string& rootfsDir) {
    return loader_init(rootfsDir, "");
}

bool loader_init(const std::string& rootfsDir, const std::string& nativeLibDir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) return true;
    g_rootfs_dir = rootfsDir;
    g_native_lib_dir = nativeLibDir;
    g_last_error.clear();
    g_initialized = true;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Loader initialized with rootfs: %s nativeLibDir: %s", rootfsDir.c_str(), nativeLibDir.c_str());
    return true;
}

pid_t loader_start_init() {
    std::lock_guard<std::mutex> lock(g_mutex);
    __android_log_print(ANDROID_LOG_INFO, TAG, "loader_start_init: begin initialized=%d rootfs=%s tracer_running=%d", g_initialized ? 1 : 0, g_rootfs_dir.c_str(), g_tracer_running.load() ? 1 : 0);
    if (!g_initialized) { g_last_error = "loader not initialized"; __android_log_print(ANDROID_LOG_ERROR, TAG, "%s", g_last_error.c_str()); return -1; }
    if (g_init_pid > 0) { __android_log_print(ANDROID_LOG_INFO, TAG, "loader_start_init: already running pid=%d", g_init_pid); return g_init_pid; }
    if (g_tracer_running.load(std::memory_order_acquire)) {
        g_last_error = "previous tracer session still running; stop and retry";
        __android_log_print(ANDROID_LOG_WARN, TAG, "%s", g_last_error.c_str());
        return -1;
    }

    // По стандарту system-as-root (GSI): init может быть в /system/bin/init и т.д.
    // Ищем в типичных местах, затем рекурсивно.
    const char* candidates[] = {
        "/init",
        "/sbin/init",
        "/system/bin/init",
        "/system/bin/init_second_stage",
        "/bin/init",
        "/system/xbin/init",
    };
    std::string initPath;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Searching init in standard paths under %s", g_rootfs_dir.c_str());
    for (auto c : candidates) {
        std::string p = g_rootfs_dir + c;
        // lstat: симлинки пропускаем. Гостевой "/init" — симлинк на "/system/bin/init";
        // execve через него упирается в ENOENT, берём настоящий файл.
        struct stat lst{};
        int lrc = lstat(p.c_str(), &lst);
        if (lrc == 0 && S_ISLNK(lst.st_mode)) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "candidate: %s is a symlink - skipped", p.c_str());
            continue;
        }
        struct stat st{};
        int rc = stat(p.c_str(), &st);
        if (rc == 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "candidate: %s exists mode=0%o size=%lld", p.c_str(), (unsigned)st.st_mode, (long long)st.st_size);
            if (S_ISREG(st.st_mode) && st.st_size > 0) { initPath = p; break; }
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "candidate: %s stat failed: %s", p.c_str(), strerror(errno));
        }
    }
    if (initPath.empty()) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "init not found in standard paths, starting recursive search");
        // Рекурсивный поиск init
        std::vector<std::string> stack;
        stack.push_back(g_rootfs_dir);
        int checked = 0;
        while (!stack.empty() && initPath.empty() && checked < 20000) {
            std::string dir = stack.back(); stack.pop_back();
            DIR* d = opendir(dir.c_str());
            if (!d) { __android_log_print(ANDROID_LOG_DEBUG, TAG, "opendir failed: %s (%s)", dir.c_str(), strerror(errno)); continue; }
            struct dirent* e;
            while ((e = readdir(d)) != nullptr) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                std::string full = dir + "/" + e->d_name;
                struct stat st{};
                if (lstat(full.c_str(), &st) != 0) continue;
                checked++;
                if (S_ISDIR(st.st_mode)) {
                    // ограничим глубину/область
                    if (full.find("/proc") == std::string::npos && full.find("/dev") == std::string::npos)
                        stack.push_back(full);
                } else if (S_ISREG(st.st_mode) && strcmp(e->d_name, "init") == 0 && st.st_size > 0) {
                    __android_log_print(ANDROID_LOG_INFO, TAG, "recursive found init: %s size=%lld (checked=%d)", full.c_str(), (long long)st.st_size, checked);
                    initPath = full;
                    break;
                }
            }
            closedir(d);
        }
        __android_log_print(ANDROID_LOG_INFO, TAG, "recursive search done: checked=%d found=%d", checked, initPath.empty() ? 0 : 1);
    }
    if (initPath.empty()) {
        g_last_error = "init not found in rootfs (searched standard paths and recursive).";
        __android_log_print(ANDROID_LOG_ERROR, TAG, "%s rootfs=%s", g_last_error.c_str(), g_rootfs_dir.c_str());
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Using init: %s", initPath.c_str());
    struct stat pst{};
    if (stat(initPath.c_str(), &pst) == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "init stat: mode=0%o uid=%u gid=%u size=%lld", (unsigned)pst.st_mode, (unsigned)pst.st_uid, (unsigned)pst.st_gid, (long long)pst.st_size);
        if (access(initPath.c_str(), R_OK) == 0) __android_log_print(ANDROID_LOG_INFO, TAG, "access(R_OK) ok: %s", initPath.c_str());
        else __android_log_print(ANDROID_LOG_WARN, TAG, "access(R_OK) failed: %s (%s)", initPath.c_str(), strerror(errno));
        if (access(initPath.c_str(), X_OK) == 0) __android_log_print(ANDROID_LOG_INFO, TAG, "access(X_OK) ok: %s", initPath.c_str());
        else __android_log_print(ANDROID_LOG_WARN, TAG, "access(X_OK) failed: %s (%s)", initPath.c_str(), strerror(errno));
    }

    int fd = open(initPath.c_str(), O_RDONLY);
    if (fd < 0) {
        g_last_error = std::string("open init failed: ") + strerror(errno) + " (" + initPath + ")";
        __android_log_print(ANDROID_LOG_ERROR, TAG, "%s", g_last_error.c_str());
        return -1;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "opened init fd=%d", fd);
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        g_last_error = std::string("stat init failed: ") + strerror(errno);
        __android_log_print(ANDROID_LOG_ERROR, TAG, "%s (fd=%d)", g_last_error.c_str(), fd);
        close(fd);
        return -1;
    }
    std::vector<char> buf(st.st_size);
    ssize_t n = read(fd, buf.data(), buf.size());
    close(fd);
    __android_log_print(ANDROID_LOG_INFO, TAG, "read init bytes=%zd expected=%lld", n, (long long)st.st_size);
    if (n != (ssize_t)buf.size()) {
        g_last_error = std::string("read init failed: ") + strerror(errno);
        __android_log_print(ANDROID_LOG_ERROR, TAG, "%s", g_last_error.c_str());
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "forking to start init (ALL components: stub + supervisor + seccomp + SIGSYS + LD_PRELOAD)");

    // Подготовка bootstrap-stub: ищем executable a10stub в filesDir (copied from assets).
    std::string stubExecPath;
    {
        std::string filesDir = g_rootfs_dir;
        size_t slash = filesDir.rfind('/');
        if (slash != std::string::npos) filesDir = filesDir.substr(0, slash);
        stubExecPath = filesDir + "/a10stub";
        __android_log_print(ANDROID_LOG_INFO, TAG, "stub prepare: looking for executable a10stub at %s", stubExecPath.c_str());
        struct stat sst{};
        if (stat(stubExecPath.c_str(), &sst) == 0) {
            if (S_ISREG(sst.st_mode) && (sst.st_mode & S_IXUSR)) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "stub found: %s mode=0%o size=%lld", stubExecPath.c_str(), (unsigned)sst.st_mode, (long long)sst.st_size);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "stub found but not executable: %s mode=0%o", stubExecPath.c_str(), (unsigned)sst.st_mode);
                stubExecPath.clear();
            }
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "stub not found at %s (%s), using direct exec", stubExecPath.c_str(), strerror(errno));
            stubExecPath.clear();
        }
    }

    int sup_sv[2] = { -1, -1 };
    if (!stubExecPath.empty()) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sup_sv) == 0) {
            int fdflags = fcntl(sup_sv[1], F_GETFD);
            if (fdflags != -1) fcntl(sup_sv[1], F_SETFD, fdflags & ~FD_CLOEXEC);
            __android_log_print(ANDROID_LOG_INFO, TAG, "supervisor socketpair created: parent=%d child=%d", sup_sv[0], sup_sv[1]);
        } else {
            __android_log_print(ANDROID_LOG_WARN, TAG, "socketpair failed: errno=%d (%s)", errno, strerror(errno));
            sup_sv[0] = sup_sv[1] = -1;
        }
    }
    
    // Console pipe: guest init'у подменяем stdout/stderr, loader читает в отдельном потоке
    // и пересылает в logcat (TAG=A10_Guest). Без этого мы слепы: init пишет в kmsg/stderr.
    g_guest_exited.store(false); // новый запуск — старый флаг смерти сбрасываем
    int con_sv[2] = { -1, -1 };
    if (pipe2(con_sv, 0) == 0) {
        int fdflags = fcntl(con_sv[1], F_GETFD);
        if (fdflags != -1) fcntl(con_sv[1], F_SETFD, fdflags & ~FD_CLOEXEC);
        __android_log_print(ANDROID_LOG_INFO, TAG, "console pipe created: reader=%d writer=%d", con_sv[0], con_sv[1]);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "console pipe failed: errno=%d (%s)", errno, strerror(errno));
    }

    pid_t pid = fork();
    if (pid == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "[child] pid=%d ppid=%d uid=%d gid=%d", getpid(), getppid(), (int)getuid(), (int)getgid());
        if (con_sv[0] >= 0) close(con_sv[0]); // child пишет, читает родитель

        // Используем stub через supervisor socketpair
        if (!stubExecPath.empty()) {
            if (sup_sv[1] >= 0) {
                int fdflags = fcntl(sup_sv[1], F_GETFD);
                if (fdflags != -1) fcntl(sup_sv[1], F_SETFD, fdflags & ~FD_CLOEXEC);
                __android_log_print(ANDROID_LOG_INFO, TAG, "[child] supervisor socketpair created: parent=%d child=%d", sup_sv[0], sup_sv[1]);
                close(sup_sv[0]);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "socketpair failed: errno=%d (%s)", errno, strerror(errno));
                sup_sv[1] = -1;
            }

            // Окружение для stub: mode, supervisor fd, console fd, native lib dir (LD_PRELOAD).
            char* const sargv[] = { (char*)stubExecPath.c_str(), (char*)initPath.c_str(), (char*)g_rootfs_dir.c_str(), nullptr };
            char env_mode[] = "A10_STUB_MODE=probe";
            char env_sup[64];
            char env_con[64];
            char env_nlib[1024];
            char* senvp[8];
            int ei = 0;
            senvp[ei++] = env_mode;
            if (sup_sv[1] >= 0) {
                snprintf(env_sup, sizeof(env_sup), "A10_SUPERVISOR_FD=%d", sup_sv[1]);
                senvp[ei++] = env_sup;
            }
            if (con_sv[1] >= 0) {
                snprintf(env_con, sizeof(env_con), "A10_CONSOLE_FD=%d", con_sv[1]);
                senvp[ei++] = env_con;
            }
            if (!g_native_lib_dir.empty()) {
                snprintf(env_nlib, sizeof(env_nlib), "A10_NATIVE_LIB_DIR=%s", g_native_lib_dir.c_str());
                senvp[ei++] = env_nlib;
            }
            senvp[ei++] = (char*)"PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin";
            senvp[ei] = nullptr;
            __android_log_print(ANDROID_LOG_INFO, TAG, "[child] trying exec stub: %s -> %s (mode=probe, supervisor_fd=%d, console_fd=%d)", stubExecPath.c_str(), initPath.c_str(), sup_sv[1], con_sv[1]);
            execve(stubExecPath.c_str(), sargv, senvp);
            __android_log_print(ANDROID_LOG_ERROR, TAG, "[child] exec stub failed: %s errno=%d (%s), falling back to direct exec", stubExecPath.c_str(), errno, strerror(errno));
            if (sup_sv[1] >= 0) close(sup_sv[1]);
        }

        // Fallback: прямой exec init (console/env как у stub-пути)
        __android_log_print(ANDROID_LOG_INFO, TAG, "[child] fallback: direct exec init with LD_PRELOAD from system property");
        char* const argv[] = { (char*)"init", nullptr };
        char env_android_root[512];
        snprintf(env_android_root, sizeof(env_android_root), "ANDROID_ROOT=%s/system", g_rootfs_dir.c_str());
        char env_path[] = "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin";
        char env_ld_library_path[1024];
        snprintf(env_ld_library_path, sizeof(env_ld_library_path),
                 "LD_LIBRARY_PATH=%s/system/lib64:%s/system/lib:%s/lib64:%s/lib:%s/vendor/lib64:%s/vendor/lib",
                 g_rootfs_dir.c_str(), g_rootfs_dir.c_str(), g_rootfs_dir.c_str(),
                 g_rootfs_dir.c_str(), g_rootfs_dir.c_str(), g_rootfs_dir.c_str());
        
        // LD_PRELOAD: единственный источник — nativeLibDir APK (extractNativeLibs=true).
        // Дубль в filesDir убран вместе с assets-копией.
        char env_ld_preload[1024];
        env_ld_preload[0] = 0;
        if (!g_native_lib_dir.empty()) {
            snprintf(env_ld_preload, sizeof(env_ld_preload), "LD_PRELOAD=%s/liba10preload.so", g_native_lib_dir.c_str());
        }
        char env_con[64];
        char env_nlib[1024];
        char* envp[8];
        int ei = 0;
        envp[ei++] = env_android_root;
        envp[ei++] = env_path;
        envp[ei++] = env_ld_library_path;
        if (env_ld_preload[0]) {
            envp[ei++] = env_ld_preload;
        }
        if (con_sv[1] >= 0) {
            snprintf(env_con, sizeof(env_con), "A10_CONSOLE_FD=%d", con_sv[1]);
            envp[ei++] = env_con;
        }
        if (!g_native_lib_dir.empty()) {
            snprintf(env_nlib, sizeof(env_nlib), "A10_NATIVE_LIB_DIR=%s", g_native_lib_dir.c_str());
            envp[ei++] = env_nlib;
        }
        envp[ei] = nullptr;
        execve(initPath.c_str(), argv, envp);
        __android_log_print(ANDROID_LOG_ERROR, TAG, "[child] execve failed: %s", strerror(errno));
        _exit(126);
    } else if (pid > 0) {
        // Родитель: закрываем writer-end консоли (EOF придёт, когда умрёт init)
        if (con_sv[1] >= 0) close(con_sv[1]);
        // Родитель: запускаем поток-ридер консоли: stdout/stderr гостевого init -> logcat A10_Guest
        if (con_sv[0] >= 0) {
            start_console_reader_thread(con_sv[0]);
        }
        // Родитель: запускаем поток-супервизор (он ждёт notify_fd по сокету) ДО возврата pid.
        // Без этого потока notify_fd никто не принимает и перехваченные syscalls init зависают.
        if (sup_sv[0] >= 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "starting supervisor receiver thread (socket=%d)", sup_sv[0]);
            start_supervisor_receiver_thread(sup_sv[0]);
        }
        // Child exec'нулся, возвращаем pid
        __android_log_print(ANDROID_LOG_INFO, TAG, "Init process started (LD_PRELOAD + SIGSYS mode), child pid=%d", pid);
        g_init_pid = pid;
        g_last_error.clear();
        return pid;
    }
    g_last_error = std::string("fork failed: ") + strerror(errno);
    return -1;
}

// Жив ли гостевой init? EOF консоли ИЛИ waitpid(WNOHANG) говорят о смерти.
// Используется JNI-поллером UI для авто-переключения кнопок Start/Stop.
bool loader_guest_alive() {
    if (g_guest_exited.load()) return false;
    pid_t pid = g_init_pid;
    if (pid <= 0) return false;
    int st = 0;
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r == 0) return true;      // жив
    if (r == pid) {
        g_guest_exited.store(true); // сами реапнули — зафиксируем смерть
        return false;
    }
    return false;                 // r < 0 (ECHILD — уже реапнут/нет такого) = мёртв
}

std::string loader_status() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized) return "Loader not initialized";
    std::ostringstream oss;
    oss << "Loader | Rootfs: " << g_rootfs_dir << " | Init PID: " << g_init_pid;
    return oss.str();
}

std::string loader_last_error() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_last_error;
}

void loader_shutdown() {
    pid_t pid_to_kill = -1;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;
        pid_to_kill = g_init_pid;
        g_init_pid = -1;
        g_initialized = false;
        g_rootfs_dir.clear();
        g_last_error.clear();
    }
    if (pid_to_kill > 0) {
        kill(pid_to_kill, SIGKILL);
        // Не блокируемся: поток ptrace может уже ждать/реапить процесс.
        for (int i = 0; i < 20; i++) {
            int st = 0;
            pid_t w = waitpid(pid_to_kill, &st, WNOHANG);
            if (w == pid_to_kill || w == -1) break;
            usleep(10000);
        }
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "Loader shutdown");
}