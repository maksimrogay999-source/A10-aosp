#include "ptrace_intercept.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <android/log.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <cstdint>

#if defined(__aarch64__)
#include <sys/user.h>
#endif

#define TAG "A10_Ptrace"

// Обработчики syscalls
static std::string read_tracee_string(pid_t pid, unsigned long addr) {
    std::string out;
    if (addr == 0) return out;
    const size_t max_len = 512;
    for (size_t i = 0; i < max_len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(uintptr_t)(addr + i), nullptr);
        if (errno != 0) break;
        for (size_t b = 0; b < sizeof(long) && out.size() < max_len - 1; b++) {
            char c = (char)((word >> (b * 8)) & 0xff);
            if (c == '\0') return out;
            out.push_back(c);
        }
    }
    return out;
}

static void handle_openat(pid_t pid, long dfd, long path_ptr, long flags, long /*mode*/) {
    std::string path = read_tracee_string(pid, (unsigned long)path_ptr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "openat: pid=%d dfd=%ld flags=0x%lx path=%s", pid, dfd, (unsigned long)flags, path.c_str());
    // TODO: подмена путей на rootfs
}

static void handle_read(pid_t pid, long fd, long /*buf_ptr*/, long count) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "read: pid=%d fd=%ld count=%ld", pid, fd, count);
}

static void handle_write(pid_t pid, long fd, long /*buf_ptr*/, long count) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "write: pid=%d fd=%ld count=%ld", pid, fd, count);
}

static void handle_ioctl(pid_t pid, long fd, long request, long /*arg*/) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "ioctl: pid=%d fd=%ld request=0x%lx", pid, fd, (unsigned long)request);
    // Binder ioctl: BINDER_WRITE_READ = 0xc0306201
    if ((unsigned long)request == 0xc0306201UL) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Binder ioctl intercepted (BINDER_WRITE_READ) pid=%d", pid);
        // TODO: передать в Binder-эмулятор / виртуализировать fd
    }
}

struct TraceeState {
    bool in_syscall = false;
    long last_syscall_nr = -1;
};

// Возвращает true если tracee продолжен (или уже не существует обработано вызывающим), false при неустранимой ошибке.
// По умолчанию используем PTRACE_CONT для стабильности/диагностики (syscall-trace на части устройств даёт сбои).
static bool continue_tracee(pid_t tid, int sig_to_deliver) {
    errno = 0;
    if (ptrace(PTRACE_CONT, tid, nullptr, (void*)(intptr_t)sig_to_deliver) == 0) return true;
    int e = errno;
    __android_log_print(ANDROID_LOG_ERROR, TAG, "PTRACE_CONT continue failed tid=%d sig=%d: errno=%d (%s)", tid, sig_to_deliver, e, strerror(e));
    if (e == ESRCH) return false;
    errno = 0;
    if (ptrace(PTRACE_SYSCALL, tid, nullptr, (void*)(intptr_t)sig_to_deliver) == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "PTRACE_SYSCALL fallback ok tid=%d", tid);
        return true;
    }
    __android_log_print(ANDROID_LOG_ERROR, TAG, "PTRACE_SYSCALL fallback failed tid=%d: errno=%d (%s)", tid, errno, strerror(errno));
    return errno == ESRCH ? false : false;
}

void ptrace_syscall_intercept(pid_t root_pid, bool resumed_by_caller, std::atomic<bool>* tracer_running) {
    struct Guard {
        std::atomic<bool>* f;
        ~Guard() { if (f) f->store(false, std::memory_order_release); }
    } guard{tracer_running};
    if (tracer_running) tracer_running->store(true, std::memory_order_release);

    __android_log_print(ANDROID_LOG_INFO, TAG, "ptrace loop thread start for pid=%d tid=%d resumed_by_caller=%d", root_pid, (int)gettid(), resumed_by_caller ? 1 : 0);
    if (kill(root_pid, 0) == 0) __android_log_print(ANDROID_LOG_INFO, TAG, "loop: kill(pid,0) ok for %d", root_pid);
    else __android_log_print(ANDROID_LOG_WARN, TAG, "loop: kill(pid,0) failed for %d errno=%d (%s)", root_pid, errno, strerror(errno));

    std::unordered_map<pid_t, TraceeState> states;
    states[root_pid] = TraceeState{};

    const long trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT |
                            PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (!resumed_by_caller) {
        errno = 0;
        if (ptrace(PTRACE_SETOPTIONS, root_pid, nullptr, (void*)trace_opts) == -1) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "loop initial PTRACE_SETOPTIONS failed pid=%d: errno=%d (%s)", root_pid, errno, strerror(errno));
        }
        errno = 0;
        if (ptrace(PTRACE_CONT, root_pid, nullptr, nullptr) == -1) {
            int e = errno;
            __android_log_print(ANDROID_LOG_WARN, TAG, "loop initial PTRACE_CONT failed for pid=%d: errno=%d (%s)", root_pid, e, strerror(e));
            errno = 0;
            if (ptrace(PTRACE_SYSCALL, root_pid, nullptr, nullptr) == -1) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "loop initial PTRACE_SYSCALL failed for pid=%d: errno=%d (%s)", root_pid, errno, strerror(errno));
                return;
            } else {
                __android_log_print(ANDROID_LOG_INFO, TAG, "loop initial PTRACE_SYSCALL ok pid=%d (fallback)", root_pid);
            }
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "loop initial PTRACE_CONT ok pid=%d (resumed from loop thread)", root_pid);
        }
    } else {
        // Родитель уже продолжил tracee, но опции полезно гарантировать.
        errno = 0;
        if (ptrace(PTRACE_SETOPTIONS, root_pid, nullptr, (void*)trace_opts) == -1) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "loop: PTRACE_SETOPTIONS (resumed) pid=%d errno=%d (%s)", root_pid, errno, strerror(errno));
        }
        __android_log_print(ANDROID_LOG_INFO, TAG, "loop: tracee already resumed by caller, entering wait loop");
    }

    int stop_count = 0;
    while (!states.empty()) {
        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid == -1) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "waitpid: no more traced children");
                break;
            }
            __android_log_print(ANDROID_LOG_WARN, TAG, "waitpid failed: errno=%d (%s)", errno, strerror(errno));
            break;
        }

        stop_count++;
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "waitpid #%d tid=%d status=0x%x stopped=%d exited=%d signaled=%d",
                            stop_count, (int)tid, status, WIFSTOPPED(status), WIFEXITED(status), WIFSIGNALED(status));

        if (WIFEXITED(status)) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "Tracee exited: tid=%d code=%d", tid, WEXITSTATUS(status));
            states.erase(tid);
            if (tid == root_pid && states.empty()) break;
            continue;
        }
        if (WIFSIGNALED(status)) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Tracee killed by signal: tid=%d sig=%d", tid, WTERMSIG(status));
            states.erase(tid);
            if (tid == root_pid && states.empty()) break;
            continue;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        if (states.find(tid) == states.end()) {
            states[tid] = TraceeState{};
            __android_log_print(ANDROID_LOG_INFO, TAG, "Tracking new tracee tid=%d", tid);
        }
        TraceeState& st = states[tid];

        int sig = WSTOPSIG(status);
        int event = (status >> 16) & 0xff;
        bool syscall_trap = (sig == (SIGTRAP | 0x80));
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "stopped tid=%d sig=%d event=%d syscall_trap=%d", tid, sig, event, syscall_trap ? 1 : 0);

        int sig_to_deliver = 0;

        if (event == PTRACE_EVENT_EXIT) {
            unsigned long ev = 0;
            if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &ev) == 0)
                __android_log_print(ANDROID_LOG_INFO, TAG, "PTRACE_EVENT_EXIT tid=%d status=%lu", tid, ev);
        } else if (event == PTRACE_EVENT_EXEC) {
            unsigned long ev = 0;
            if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &ev) == 0)
                __android_log_print(ANDROID_LOG_INFO, TAG, "PTRACE_EVENT_EXEC tid=%d former_tid=%lu", tid, ev);
            // exec() сбрасывает состояние; возможная незавершённая пара syscall
            st.in_syscall = false;
            st.last_syscall_nr = -1;
        } else if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
            unsigned long new_tid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid) == 0) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "PTRACE_EVENT_CLONE/FORK tid=%d new_tid=%lu event=%d", tid, new_tid, event);
                if (new_tid != 0) {
                    states[(pid_t)new_tid] = TraceeState{};
                    // Новый tracee будет/уже остановлен; дождёмся его в waitpid(-1). Явно продолжать здесь не обязательно.
                }
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "PTRACE_GETEVENTMSG failed for clone/fork tid=%d errno=%d (%s)", tid, errno, strerror(errno));
            }
        }

        if (!syscall_trap && sig != SIGTRAP) {
            // Реальный сигнал (включая SIGSTOP/SIGCONT и др.) — пробрасываем tracee.
            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL || sig == SIGBUS || sig == SIGFPE || sig == SIGSYS) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Tracee fatal/crash signal: tid=%d signal=%d", tid, sig);
            }
            sig_to_deliver = sig;
            if (sig_to_deliver != 0) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "delivering signal to tracee tid=%d sig=%d", tid, sig_to_deliver);
            }
        }

        if (syscall_trap) {
#if defined(__aarch64__)
            struct iovec iov;
            union {
                struct user_regs_struct regs;
                char pad[sizeof(struct user_regs_struct) + 1];
            } u;
            iov.iov_base = &u;
            iov.iov_len = sizeof(u.regs);

            errno = 0;
            bool got_regs = (ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov) == 0);
            if (!got_regs) {
                int ge = errno;
                __android_log_print(ANDROID_LOG_WARN, TAG, "GETREGSET failed tid=%d: errno=%d (%s)", tid, ge, strerror(ge));
                usleep(1000);
                errno = 0;
                got_regs = (ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov) == 0);
                if (got_regs) {
                    __android_log_print(ANDROID_LOG_INFO, TAG, "GETREGSET retry ok tid=%d", tid);
                } else {
                    __android_log_print(ANDROID_LOG_WARN, TAG, "GETREGSET retry failed tid=%d: errno=%d (%s)", tid, errno, strerror(errno));
                }
            }

            if (got_regs) {
                long syscall_num = (long)u.regs.regs[8];
                long arg0 = (long)u.regs.regs[0];
                long arg1 = (long)u.regs.regs[1];
                long arg2 = (long)u.regs.regs[2];
                long arg3 = (long)u.regs.regs[3];
                long arg4 = (long)u.regs.regs[4];
                long arg5 = (long)u.regs.regs[5];

                if (!st.in_syscall) {
                    st.last_syscall_nr = syscall_num;
                    __android_log_print(ANDROID_LOG_INFO, TAG, "SYSCALL-ENTER tid=%d nr=%ld a0=%ld a1=%ld a2=%ld a3=%ld a4=%ld a5=%ld",
                                        tid, syscall_num, arg0, arg1, arg2, arg3, arg4, arg5);
                    switch (syscall_num) {
                        case SYS_openat:
                            handle_openat(tid, arg0, arg1, arg2, arg3);
                            break;
                        case SYS_read:
                            handle_read(tid, arg0, arg1, arg2);
                            break;
                        case SYS_write:
                            handle_write(tid, arg0, arg1, arg2);
                            break;
                        case SYS_ioctl:
                            handle_ioctl(tid, arg0, arg1, arg2);
                            break;
                        default:
                            break;
                    }
                } else {
                    // На AArch64 номер syscall (x8) может быть перезаписан на выходе, возвращаемое значение в x0.
                    __android_log_print(ANDROID_LOG_INFO, TAG, "SYSCALL-EXIT  tid=%d nr=%ld ret=%ld (x0=%ld)", tid, st.last_syscall_nr, arg0, arg0);
                }
                st.in_syscall = !st.in_syscall;
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "SYSCALL-stop tid=%d (regs unavailable, skipping to avoid state desync)", tid);
            }
#else
            (void)st;
            __android_log_print(ANDROID_LOG_WARN, TAG, "ptrace GETREGS not supported on this arch (tid=%d)", tid);
#endif
        } else if (sig == SIGTRAP && event != 0) {
            // ptrace event stop (EXEC/EXIT/CLONE/FORK/VFORK...), не является syscall enter/exit
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "ptrace event-stop tid=%d event=%d (no syscall state change)", tid, event);
        }

        if (continue_tracee(tid, sig_to_deliver)) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "continued tid=%d delivered_sig=%d", tid, sig_to_deliver);
        } else {
            if (errno == ESRCH || kill(tid, 0) == -1) {
                __android_log_print(ANDROID_LOG_INFO, TAG, "tracee gone, removing tid=%d", tid);
                states.erase(tid);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "continue failed but tid=%d seems alive; keeping tracked", tid);
            }
        }
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "ptrace loop end root_pid=%d remaining=%zu", root_pid, states.size());
}