#include "a10engine.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

void console_raw(const char* buf, size_t n) {
    if (g_console_fd < 0 || n == 0) return;
    // Пишем ЧАСТЯМИ: пайп телефона вмещает только PIPE_BUF (4096) за одну атомарную
    // запись, а большой кусок (например дамп таблицы гостя на 8 КБ) обрывается на
    // свободном месте — и весь вывод после этого теряется (лог 14:55: вторая стадия
    // молчала). Пишем по 1024 и повторяем, пока не уйдёт всё.
    const size_t kChunk = 1024;
    size_t off = 0;
    while (off < n) {
        size_t part = (n - off) < kChunk ? (n - off) : kChunk;
        ssize_t wn = (ssize_t)syscall(__NR_write, g_console_fd, buf + off, part);
        if (wn <= 0) break;          // пайп переполнен или ошибка — дальше писать некуда
        off += (size_t)wn;
    }
}

// Ловим ВСЁ, что гость пишет в свои stdout/stderr — даже если fd уведён в /dev/null.
// Иначе текст LOG(FATAL) теряется (лог 14:40: abort поймали, а текст — нет).
// В конце ставим '\n': без него сообщения гостя слипаются в одну гигантскую строку,
// и logcat её обрезает/отбрасывает (так терялись сообщения гостя в логе 13:31).
void guest_out(const char* prefix, int fd, const char* buf, size_t n) {
    if (fd < 0 || fd > 3 || !buf || n == 0) return;
    char tmp[400];
    size_t len = n < sizeof(tmp) - 1 ? n : sizeof(tmp) - 1;
    memcpy(tmp, buf, len);
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '\n' || tmp[i] == '\r') tmp[i] = '|';
        else if (tmp[i] < 32) tmp[i] = '.';
    }
    tmp[len] = '\0';
    char out[540];
    int m = snprintf(out, sizeof(out), "%s fd=%d: %s\n", prefix, fd, tmp);
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
void plog(const char* fmt, ...) {
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


// Тип ФС selinuxfs: f_type для statfs/fstatfs. Значение — константа uapi ядра
// (linux/selinux.h), а не «информация о путях».
#ifndef SELINUX_MAGIC
#define SELINUX_MAGIC 0xf97cff8c
#endif

bool trace_slot() {
    if (g_trace_count >= A10_TRACE_MAX) return false;
    g_trace_count++;
    return true;
}

// Путь гостя переводится ТОЛЬКО по mount-таблице. Пути вне таблицы недоступны:
// ничего общего у хоста и гостя (в ФС телефона гость не попадает).
// Поведение задаётся флагами записи: chr=major:minor (устройство гостя),
// selinux (эмулированный selinuxfs), fs=<тип> (тип ФС), trace (диагностика).
