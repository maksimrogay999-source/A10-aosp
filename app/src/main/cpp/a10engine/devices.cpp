#include "a10engine.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

// ---------------------------------------------------------------- shared memory гостя
// Свойства Android — это shared memory ("/dev/__properties__/property_area"). Гость
// создаёт её через SharedMemory::create() -> memfd_create()/ashmem — сырые syscall'ы, мимо
// нас, и область уехала бы в память ТЕЛЕФОНА (shared!). Поэтому подменяем: область
// свойств гостя = обычный файл в гостевой ФС (mmap по нему работает как shared).
int guest_shared_memory(const char* name, size_t size) {
    if (!name) return -1;
    char gp[512], host[900];
    snprintf(gp, sizeof(gp), "/dev/__properties__/%s", name);
    if (!host_path_of(gp, host, sizeof(host))) return -1;
    char dir[900];
    snprintf(dir, sizeof(dir), "%s", host);
    char* slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(dir);
    }
    int fd = (int)syscall(__NR_openat, AT_FDCWD, host, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    if (size) {
        if (syscall(__NR_ftruncate, fd, (off_t)size) < 0) {
            /* размер не критичен — гость сам перезапишет */
        }
    }
    plog("A10_Preload: shared memory гостя '%s' -> файл %s (fd=%d, %zu байт)", name, host, fd, size);
    return fd;
}

extern "C" int memfd_create(const char* name, unsigned int flags) {
    static int (*real)(const char*, unsigned int) = nullptr;
    if (!real) real = (int (*)(const char*, unsigned int))dlsym(RTLD_NEXT, "memfd_create");
    if (name && strstr(name, "property") != nullptr) {
        int fd = guest_shared_memory(name, 0);
        if (fd >= 0) return fd;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(name, flags);
}

extern "C" int ashmem_create_region(const char* name, size_t size) {
    static int (*real)(const char*, size_t) = nullptr;
    if (!real) real = (int (*)(const char*, size_t))dlsym(RTLD_NEXT, "ashmem_create_region");
    if (name && strstr(name, "property") != nullptr) {
        int fd = guest_shared_memory(name, size);
        if (fd >= 0) return fd;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(name, size);
}

void mkdir_p(const char* path) {
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

// Отслеживаемые fd: помним, из какого MOUNT'а таблицы fd получен и что это за
// устройство — по нему определяются эмулируемые свойства (selinuxfs, kmsg, ...).
// Виды устройств (enum DevKind) и лимиты — в a10engine.h.

// Устройство по номерам major/minor (нумерация Linux). Хостовые устройства при этом
// НЕ используются — всё эмулируется.
int dev_kind_by_numbers(int major, int minor) {
    if (major != 1) return DEVK_PLAIN;   // не mem-устройство
    switch (minor) {
        case 3: return DEVK_NULL;
        case 5: return DEVK_ZERO;
        case 7: return DEVK_FULL;
        case 8: return DEVK_RANDOM;
        case 9: return DEVK_URANDOM;
        case 11: return DEVK_KMSG;
        default: return DEVK_PLAIN;
    }
}

// Гостевой путь, открытый на fd: нужен для эмуляции /proc/self/fd/N (libselinux через
// неё узнаёт путь каталога) и для относительных openat().
void track_set_path(int fd, const char* path) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] != fd) continue;
        snprintf(g_track_path[i], A10_PATH_MAX, "%s", path ? path : "");
        return;
    }
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] != 0) continue;
        g_track_fd[i] = fd;
        g_track_mount[i] = -1;
        g_track_kind[i] = DEVK_PLAIN;
        snprintf(g_track_path[i], A10_PATH_MAX, "%s", path ? path : "");
        return;
    }
}

const char* track_path_of(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) return g_track_path[i];
    }
    return nullptr;
}

void track_add(int fd, int mount_index, int kind) {
    if (fd < 0) return;
    // Если такой fd уже отслеживается (fd переиспользован, а close() гостя прошёл мимо
    // перехвата — например fclose() из libc++), переиспользуем слот. Иначе в таблице
    // появляется ДУБЛЬ, и track_take_virt()/proc_kind_of_fd() отдают данные ПРЕДЫДУЩЕГО
    // файла: гость читал пустоту вместо содержимого (было: "No version present in
    // plat_sepolicy_vers.txt", т.к. fd остался от виртуального /proc/cmdline).
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) {
            g_track_mount[i] = mount_index;
            g_track_kind[i] = kind;
            free(g_virt_data[i]);
            g_virt_data[i] = nullptr;
            g_virt_len[i] = 0;
            g_virt_pos[i] = 0;
            g_track_proc[i] = PROC_NONE;
            g_track_path[i][0] = '\0';
            return;
        }
    }
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == 0) {
            g_track_fd[i] = fd;
            g_track_mount[i] = mount_index;
            g_track_kind[i] = kind;
            return;
        }
    }
    // Таблица заполнена — переиспользуем самый старый слот (иначе новые файлы не
    // отслеживаются вообще: путь/вид устройства теряются).
    static int recycle = 0;
    int i = recycle++ % A10_TRACK_MAX;
    free(g_virt_data[i]);
    g_virt_data[i] = nullptr;
    g_virt_len[i] = 0;
    g_virt_pos[i] = 0;
    g_track_fd[i] = fd;
    g_track_mount[i] = mount_index;
    g_track_kind[i] = kind;
    g_track_proc[i] = PROC_NONE;
    g_track_path[i][0] = '\0';
}

void track_del(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) {
            free(g_virt_data[i]);
            g_virt_data[i] = nullptr;
            g_virt_len[i] = 0;
            g_virt_pos[i] = 0;
            g_track_fd[i] = 0;
            g_track_mount[i] = -1;
            g_track_kind[i] = DEVK_PLAIN;
        }
    }
}

// Mount таблицы, из которого получен fd (nullptr — неизвестно/не из таблицы).
const Entry* mount_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd && g_track_mount[i] >= 0) return &g_mounts[g_track_mount[i]];
    }
    return nullptr;
}

// Вид устройства по fd (DEVK_PLAIN — обычный).
int dev_kind_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) return g_track_kind[i];
    }
    return DEVK_PLAIN;
}

// Виртуальные файлы procfs ГОСТЯ: содержимое эмулируется (procfs хоста — это shared,
// гостю он не принадлежит). Тип ФС proc гость объявляет сам, через mount() — тогда
// preload создаёт у него файлы procfs и подменяет их содержимое.

// Содержимое виртуального файла (procfs/selinuxfs) генерируется ОДИН РАЗ при open()
// и выдаётся по частям с позицией — как обычный файл. Иначе гость читает одни и те же
// первые килобайты и не доходит до нужного контекста (было: restorecon -> ENOENT).
void track_set_virt(int fd, char* data, size_t len) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] != fd) continue;
        free(g_virt_data[i]);
        g_virt_data[i] = data;
        g_virt_len[i] = len;
        g_virt_pos[i] = 0;
        return;
    }
}

// Очередной кусок виртуального файла; nullptr — файл не виртуальный.
const char* track_take_virt(int fd, size_t* chunk) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] != fd || !g_virt_data[i]) continue;
        size_t left = g_virt_len[i] - g_virt_pos[i];
        size_t n = left < 65536 ? left : 65536;
        if (n == 0) {
            *chunk = 0;
            return "";
        }
        const char* p = g_virt_data[i] + g_virt_pos[i];
        g_virt_pos[i] += n;
        *chunk = n;
        return p;
    }
    return nullptr;
}

void track_set_proc(int fd, int kind) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) {
            g_track_proc[i] = kind;
            return;
        }
    }
}

int proc_kind_of_fd(int fd) {
    for (int i = 0; i < A10_TRACK_MAX; i++) {
        if (g_track_fd[i] == fd) return g_track_proc[i];
    }
    return PROC_NONE;
}

// Содержимое /proc/filesystems гостя: поддерживаемые типы ФС.
ssize_t read(int fd, void* buf, size_t count) {
    // Виртуальные файлы procfs/selinuxfs гостя: содержимое эмулируется и выдаётся
    // по позиции (как обычный файл).
    size_t vchunk = 0;
    const char* vdata = track_take_virt(fd, &vchunk);
    if (vdata) {
        if (vchunk == 0) return 0;
        size_t cp = vchunk < count ? vchunk : count;
        memcpy(buf, vdata, cp);
        return (ssize_t)cp;
    }
    int pk = proc_kind_of_fd(fd);
    if (pk != PROC_NONE) {
        static char content[262144];
        ssize_t n = 0;
        if (pk == PROC_FILESYSTEMS) n = build_guest_filesystems(content, sizeof(content));
        else if (pk == PROC_MOUNTS) n = build_guest_mounts(content, sizeof(content));
        else if (pk == PROC_CMDLINE) n = 0;
        else if (pk == SEL_ENFORCE) n = snprintf(content, sizeof(content), "0\n");
        else if (pk == SEL_STATUS) n = snprintf(content, sizeof(content), "permissive\n");
        else if (pk == SEL_CONTEXTS) n = build_guest_contexts(content, sizeof(content));
        if (n <= 0) return 0;
        size_t cp = (size_t)n < count ? (size_t)n : count;
        memcpy(buf, content, cp);
        return (ssize_t)cp;
    }
    int kind = dev_kind_of_fd(fd);
    if (kind == DEVK_NULL || kind == DEVK_FULL || kind == DEVK_KMSG) {
        return 0;   // EOF
    }
    if (kind == DEVK_ZERO) {
        if (buf && count) memset(buf, 0, count);
        return (ssize_t)count;
    }
    if (kind == DEVK_RANDOM || kind == DEVK_URANDOM) {
        ssize_t r = (ssize_t)syscall(__NR_getrandom, buf, count, 0);
        if (r < 0) {
            if (buf && count) memset(buf, 0, count);
            r = (ssize_t)count;
        }
        return r;
    }
    ssize_t r = (ssize_t)syscall(__NR_read, fd, buf, count);
    // Диагностика: EOF на обычном файле = гость прочитал пустоту.
    static int eofs = 0;
    if (r == 0 && eofs < 15) {
        eofs++;
        plog("A10_Preload: read(fd=%d, %s) -> EOF (0 байт)", fd,
             track_path_of(fd) ? track_path_of(fd) : "?");
    }
    // Диагностика: крупные чтения гостя (свой отдельный счётчик — обычная трассировка
    // к этому моменту обычно исчерпана). Показывает, прочитал ли гость свой файл целиком.
    static int big_reads = 0;
    if (r >= 4096 && big_reads < 30) {
        big_reads++;
        plog("A10_Preload: read(fd=%d, %s) -> %zd байт", fd, track_path_of(fd) ? track_path_of(fd) : "?",
             r);
    }
    return r;
}

