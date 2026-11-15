#include "a10engine.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>

// Netlink-сокеты гостя (uevent): эмулируем bind/setsockopt, чтобы init не падал.
#ifndef __NR_dup3
#define __NR_dup3 24   // aarch64: dup3(oldfd, newfd, 0) == dup2
#endif
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

void mark_logfd(int fd) {
    if (fd < 0) return;
    for (int i = 0; i < A10_MAX_LOGFD; i++) {
        if (g_logfd[i] == 0) {
            g_logfd[i] = fd;
            return;
        }
    }
}

bool is_logfd(int fd) {
    for (int i = 0; i < A10_MAX_LOGFD; i++) {
        if (g_logfd[i] == fd) return true;
    }
    return false;
}

int socket(int domain, int type, int protocol) {
    REAL_FN(real, "socket", int, (int, int, int));
    if (!real) { errno = ENOSYS; return -1; }
    int fd = real(domain, type, protocol);
    plog("A10_Preload: socket(domain=%d, type=%d) -> fd=%d (errno=%d)", domain, type, fd, errno);
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

// Перевод пути AF_UNIX гостя в host-путь (по mount-таблице). Без этого bind() гостя
// создал бы сокет в ФС ТЕЛЕФОНА (/dev/socket/...) или вообще не смог бы (нет прав).
static bool unix_host_path(const struct sockaddr_un* un, char* out, size_t outsz) {
    if (!un || !un->sun_path[0]) return false;
    if (un->sun_path[0] == '/') return host_path_of(un->sun_path, out, outsz);
    return false;
}

int bind(int fd, const struct sockaddr* addr, socklen_t len) {
    REAL_FN(real, "bind", int, (int, const struct sockaddr*, socklen_t));
    if (is_netlink_fd(fd)) return 0;   // bind на netlink-группу = EPERM на хосте
    if (addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un* un = (const struct sockaddr_un*)addr;
        char host[900];
        if (unix_host_path(un, host, sizeof(host))) {
            // Каталог сокета в гостевой ФС должен существовать.
            char dir[900];
            snprintf(dir, sizeof(dir), "%s", host);
            char* slash = strrchr(dir, '/');
            if (slash) {
                *slash = '\0';
                mkdir_p(dir);
            }
            struct sockaddr_un hu {};
            hu.sun_family = AF_UNIX;
            snprintf(hu.sun_path, sizeof(hu.sun_path), "%s", host);
            plog("A10_Preload: bind(fd=%d) %s -> %s", fd, un->sun_path, host);
            if (!real) { errno = ENOSYS; return -1; }
            return real(fd, (struct sockaddr*)&hu, (socklen_t)sizeof(hu));
        }
    }
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
bool is_socket_fd(int fd) {
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
    int r = real(oldfd, newfd);
    plog("A10_Preload: dup2(%d -> %d) -> %d", oldfd, newfd, r);
    // Путь гостя переезжает вместе с fd — иначе /proc/self/fd/N нового fd пуст.
    if (r >= 0) {
        const char* p = track_path_of(oldfd);
        if (p && *p) {
            track_add(newfd, -1, DEVK_PLAIN);
            track_set_path(newfd, p);
        }
    }
    return r;
}

// ---------------------------------------------------------------- ФС: изменения
// Запись разрешена только в mount'ы, помеченные в таблице флагом "rw"
// (или "chmod_ok"). Путей вне таблицы гость не касается — ФС телефона защищена.
static bool guest_socket_exists(const char* sun_path) {
    if (!sun_path || sun_path[0] == '\0') return false;   // абстрактное имя: у нас таких нет
    char host[900];
    if (!host_path_of(sun_path, host, sizeof(host))) return false;
    struct stat st {};
    if (stat(host, &st) != 0) return false;
    return S_ISSOCK(st.st_mode);
}

// ---------------------------------------------------------------- сокет logd гостя
// Гостевая liblog шлёт LOG(INFO/ERROR) в сокет logd (/dev/socket/logdw), которого в
// гостевой ФС нет. Раньше connect() просто «успевал», а запись в неподключённый сокет
// уходила в никуда — все сообщения гостя терялись (и поэтому мы не видели его ошибок).
// Теперь: гостя подключаем к socketpair, отдельный поток читает сообщения и печатает их
// в консоль гостя. Формат logd — бинарный (заголовок + приоритет + tag + текст),
// поэтому печатаем читаемые байты.
static void* guest_log_reader(void* arg) {
    int fd = (int)(intptr_t)arg;
    char buf[4096];
    for (;;) {
        ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        char out[4200];
        int o = 0;
        for (ssize_t i = 0; i < n && o < (int)sizeof(out) - 2; i++) {
            unsigned char c = (unsigned char)buf[i];
            out[o++] = (c >= 32 && c < 127) ? (char)c : ' ';
        }
        out[o] = '\0';
        // Ведущие пробелы (заголовок сообщения) убираем.
        char* t = out;
        while (*t == ' ') t++;
        plog("[guest log] %s", t);
    }
    return nullptr;
}

int connect(int fd, const struct sockaddr* addr, socklen_t len) {
    REAL_FN(real, "connect", int, (int, const struct sockaddr*, socklen_t));
    // liblog гостя стучится в сокет logd, которого в гостевой ФС нет: протокол
    // несовместим с хостовым, сообщения терялись бы. Эмулируем подключение и печатаем
    // сообщения гостя сами.
    if (fd >= 0 && addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un* un = (const struct sockaddr_un*)addr;
        char host[900];
        bool have_host = unix_host_path(un, host, sizeof(host));
        if (have_host) {
            // Настоящий сокет гостя (например property-сервис гостя) — подключаемся
            // по host-пути (путь гостя на хосте не существует).
            struct stat st {};
            if (stat(host, &st) == 0 && S_ISSOCK(st.st_mode)) {
                struct sockaddr_un hu {};
                hu.sun_family = AF_UNIX;
                snprintf(hu.sun_path, sizeof(hu.sun_path), "%s", host);
                plog("A10_Preload: connect %s -> %s (сокет гостя)", un->sun_path, host);
                if (!real) { errno = ENOSYS; return -1; }
                return real(fd, (struct sockaddr*)&hu, (socklen_t)sizeof(hu));
            }
        }
        if (!guest_socket_exists(un->sun_path)) {
            // Сокета гостя нет -> эмулируем: подключаем fd гостя к socketpair, поток
            // читает сообщения и печатает их (иначе все LOG() гостя пропадают).
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
                // Сырым dup3: наш dup2 перенаправляет stdout/stderr в консоль гостя.
                if (syscall(__NR_dup3, sv[1], fd, 0) < 0) {
                    close(sv[0]);
                    close(sv[1]);
                } else {
                    close(sv[1]);
                    pthread_t th;
                    if (pthread_create(&th, nullptr, guest_log_reader, (void*)(intptr_t)sv[0]) == 0) {
                        pthread_detach(th);
                    } else {
                        close(sv[0]);
                    }
                    plog("A10_Preload: connect %s -> эмулированный сокет гостя (лог в консоль)",
                         un->sun_path);
                }
                return 0;
            }
        }
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, addr, len);
}

// Запись гостя в эмулированный kmsg: печатаем в консоль гостя. Логи гостя (LOG(INFO),
// LOG(ERROR)) идут именно в /dev/kmsg — без этого их не видно.
void guest_kmsg_out(int fd, const char* buf, size_t n) {
    if (!buf || !n) return;
    if (dev_kind_of_fd(fd) != DEVK_KMSG) return;
    guest_out("[guest kmsg]", fd, buf, n);
}

// Печать пакета гостя (в logd уходит бинарный формат — покажем читаемые байты).
void dump_guest_log(const char* buf, size_t n) {
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

// epoll_ctl: гость регистрирует сокет property-сервиса в epoll. Если хост запрещает
// epoll_ctl (seccomp/EPERM) или fd не поддерживает epoll — гость падает с FATAL.
extern "C" int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    REAL_FN(real, "epoll_ctl", int, (int, int, int, struct epoll_event*));
    if (!real) { errno = ENOSYS; return -1; }
    int r = real(epfd, op, fd, event);
    if (r < 0) {
        struct stat st {};
        int kind = -1;
        if (syscall(__NR_fstat, fd, &st) == 0) {
            kind = (st.st_mode & S_IFMT) == S_IFSOCK ? 1 : 0;   // 1 = сокет
        }
        // Что это за fd: /proc/self/fd/N хоста (тот же процесс) покажет тип узла.
        char link[256] = "?";
        char lpath[64];
        snprintf(lpath, sizeof(lpath), "/proc/self/fd/%d", fd);
        ssize_t ln = syscall(__NR_readlinkat, AT_FDCWD, lpath, link, sizeof(link) - 1);
        if (ln > 0) link[ln] = '\0';
        plog("A10_Preload: epoll_ctl(epfd=%d, op=%d, fd=%d) -> %d errno=%d (%s) [fd=%s, узел=%s, "
             "путь=%s]",
             epfd, op, fd, r, errno, strerror(errno), kind == 1 ? "сокет" : "НЕ сокет", link,
             track_path_of(fd) ? track_path_of(fd) : "?");
        // EPERM = ядро не считает этот fd опрашиваемым (обычный файл/каталог).
        // Гость на этом FATAL-ает ("epoll_ctl failed to add fd") — не даём ему умереть:
        // регистрацию считаем успешной (событий по этому fd не будет).
        if (errno == EPERM) {
            plog("A10_Preload: epoll_ctl — считаем успешным (fd=%d не опрашиваемый), гость продолжает",
                 fd);
            return 0;
        }
    }
    return r;
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    for (int i = 0; i < iovcnt; i++) {
        guest_kmsg_out(fd, (const char*)iov[i].iov_base, iov[i].iov_len);
    }
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
    guest_kmsg_out(fd, (const char*)buf, len);
    if ((is_logfd(fd) || (fd != g_console_fd && is_socket_fd(fd))) && buf) {
        dump_guest_log((const char*)buf, len);
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, buf, len, flags, addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr* msg, int flags) {
    REAL_FN(real, "sendmsg", ssize_t, (int, const struct msghdr*, int));
    if (msg && msg->msg_iov) {
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            guest_kmsg_out(fd, (const char*)msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        }
    }
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

// Кэш списка контекстов гостя + собственное SID-пространство (контекст <-> SID).


// Контекст гостя по SID.
