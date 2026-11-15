// a10engine.h — общие объявления движка эмуляции гостя (LD_PRELOAD).
//
// Движок разложен по модулям (a10engine/*.cpp):
//   table.cpp    — mount-таблица гостя (загрузка, поиск, перевод, сохранение)
//   paths.cpp    — перевод путей гостя в host-пути, права, magic ФС
//   console.cpp  — вывод в консоль гостя, перехват сообщений гостя (liblog/abort)
//   sockets.cpp  — сокеты: netlink-эмуляция, logd, connect/writev/sendto
//   devices.cpp  — устройства гостя (null/zero/full/random/kmsg…), трекинг fd
//   procfs.cpp   — виртуальные файлы procfs/selinuxfs гостя
//   selinux.cpp  — контексты SELinux гостя (file_contexts, SID, xattr)
//   fsops.cpp    — файловые операции гостя (open/stat/access/chmod/…)
//   syscalls.cpp — mount/mknod/exec/chdir/clearenv/ioctl/statfs/SIGSYS
//   props.cpp    — свойства гостя (свой файл, не общая область телефона)
//   globals.cpp  — общие переменные состояния
#pragma once

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mounts.h"

// ---------------------------------------------------------------- реестр прав гостя
// Режим файла, который мы расширили ради записи гостя: гостю показываем исходный.
void modes_init(const char* file);
void modes_save(void);
void modes_record(const char* path, unsigned mode);
bool modes_lookup(const char* path, unsigned* mode);

// ---------------------------------------------------------------- перехваты libc
// ВАЖНО: любой перехват функции libc ОБЯЗАН иметь C-линковку, иначе он экспортируется
// с mangling ("_Z5mountPKc...") и гость его не видит (проверка лога 13:06: гостевой
// init ушёл в реальный syscall mount -> SIGSYS -> "Init encountered errors starting
// first stage"). Объявления ниже — гарантия от повтора: если определение в модуле
// окажется с C++-линковкой, компилятор даст ошибку "conflicting declaration".
extern "C" {
int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data);
int umount2(const char* target, int flags);
int ioctl(int fd, int request, ...);
int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* stx);
ssize_t lgetxattr(const char* path, const char* name, void* value, size_t size);
ssize_t fgetxattr(int fd, const char* name, void* value, size_t size);
int lsetxattr(const char* path, const char* name, const void* value, size_t size, int flags);
int setxattr(const char* path, const char* name, const void* value, size_t size, int flags);
int fsetxattr(int fd, const char* name, const void* value, size_t size, int flags);
int removexattr(const char* path, const char* name);
}

using a10mount::Entry;
using a10mount::flag_present;
using a10mount::get_flag;
using a10mount::has_flag;
using a10mount::magic_of;
using a10mount::parse_line;
using a10mount::path_prefix;

// ---------------------------------------------------------------- макросы
// REAL_FN: ленивая загрузка "настоящей" функции libc (RTLD_NEXT).
#define REAL_FN(var, name, rettype, params)     \
    static rettype (*var) params = nullptr;     \
    if (!var) var = (rettype (*) params)dlsym(RTLD_NEXT, name)

// A10_FAIL: лог ошибки перехваченного вызова (по нему видно, какой вызов гостя упал).
#define A10_FAIL(what, path)                                                        \
    plog("A10_Preload: %s(%s) FAILED errno=%d (%s)", (what), (path) ? (path) : "?", \
         errno, strerror(errno))

// ---------------------------------------------------------------- состояние
extern int g_console_fd;
extern char g_rootfs[512];
extern char g_mounts_file[512];
extern char g_modes_file[512];
extern char g_preload[1024];
extern char g_console_env[64];
extern char g_android_root[512];
extern char g_ld_library_path[1024];
extern char g_path[512];

// Таблица гостя.
extern a10mount::Entry g_mounts[128];
extern int g_mount_count;

// Трекинг открытых fd гостя.
#define A10_TRACK_MAX 64
#define A10_PATH_MAX 512
// Сколько первых обращений гостя показывать в трассировке.
#define A10_TRACE_MAX 400
extern int g_track_fd[A10_TRACK_MAX];
extern int g_track_mount[A10_TRACK_MAX];
extern int g_track_kind[A10_TRACK_MAX];
extern char g_track_path[A10_TRACK_MAX][A10_PATH_MAX];
extern int g_track_proc[A10_TRACK_MAX];
extern char* g_virt_data[A10_TRACK_MAX];
extern size_t g_virt_len[A10_TRACK_MAX];
extern size_t g_virt_pos[A10_TRACK_MAX];

// Контексты гостя.
extern char g_ctx_cache[65536];
extern int g_ctx_count;
extern void* g_fc_rules;
extern int g_fc_count;

extern int g_trace_count;

// ---------------------------------------------------------------- консоль
void console_raw(const char* buf, size_t n);
void guest_out(const char* prefix, int fd, const char* buf, size_t n);
void plog(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
bool trace_slot();

// ---------------------------------------------------------------- таблица
void load_mount_table(const char* path);
const a10mount::Entry* lookup_mount(const char* path);
const a10mount::Entry* lookup_guest(const char* path);
bool translate(const char* p, char* out, size_t outsz);
const a10mount::Entry* table_find_exact(const char* guest);
void table_set(const char* guest, const char* host, const char* flags);
void table_save(void);
bool guest_root(char* out, size_t outsz);

// ---------------------------------------------------------------- пути
bool host_path_of(const char* p, char* out, size_t outsz);
bool writable_target(const char* pathname, char* host, size_t hostsz);
unsigned long magic_for_path(const char* path);
unsigned long magic_for_entry(const a10mount::Entry* e);
void mkdir_p(const char* path);

// ---------------------------------------------------------------- устройства
enum DevKind {
    DEVK_PLAIN = 0,   // обычный узел гостевой ФС
    DEVK_NULL,        // чтение -> EOF, запись -> успех
    DEVK_ZERO,        // чтение -> нули
    DEVK_FULL,        // запись -> успех, чтение -> EOF
    DEVK_RANDOM,      // чтение -> энтропия
    DEVK_URANDOM,     // чтение -> энтропия
    DEVK_KMSG,        // запись -> консоль гостя
};

void track_add(int fd, int mount_index, int kind);
void track_del(int fd);
const a10mount::Entry* mount_of_fd(int fd);
int dev_kind_of_fd(int fd);
int dev_kind_by_numbers(int major, int minor);
void track_set_path(int fd, const char* path);
const char* track_path_of(int fd);
void track_set_virt(int fd, char* data, size_t len);
const char* track_take_virt(int fd, size_t* chunk);
void track_set_proc(int fd, int kind);
int proc_kind_of_fd(int fd);
bool is_selinux_fd(int fd);
int guest_shared_memory(const char* name, size_t size);

// ---------------------------------------------------------------- procfs
enum ProcKind {
    PROC_NONE = 0,
    PROC_FILESYSTEMS,
    PROC_MOUNTS,
    PROC_CMDLINE,
    SEL_ENFORCE,
    SEL_STATUS,
    SEL_CONTEXTS,
};
int proc_kind_of_name(const char* base);
ssize_t build_guest_filesystems(char* out, size_t outsz);
ssize_t build_guest_mounts(char* out, size_t outsz);
ssize_t build_guest_contexts(char* out, size_t outsz);

// ---------------------------------------------------------------- selinux
void ensure_ctx_cache(void);
const char* guest_ctx_for_sid(int sid);
int guest_sid_for(const char* ctx);
void load_guest_file_contexts(void);
const char* guest_file_context(const char* path);
bool guest_context_exists(const char* ctx);

// ---------------------------------------------------------------- syscalls
void install_sigsys_handler(void);

// ---------------------------------------------------------------- сокеты
void guest_kmsg_out(int fd, const char* buf, size_t n);
bool is_socket_fd(int fd);
bool is_logfd(int fd);
void mark_logfd(int fd);
void dump_guest_log(const char* buf, size_t n);
