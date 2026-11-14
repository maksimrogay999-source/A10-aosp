// binary_patcher.cpp — патчинг бинарника init на диске.
// Заменяет syscall инструкции (svc #0) на NOP или ветки к эмулятору.

#include <android/log.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>

#define TAG "A10_Patcher"

static bool patch_syscalls_in_binary(const std::string& input_path, const std::string& output_path) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Patching binary: %s -> %s", input_path.c_str(), output_path.c_str());

    int fd_in = open(input_path.c_str(), O_RDONLY);
    if (fd_in < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open input: %s", strerror(errno));
        return false;
    }

    struct stat st{};
    if (fstat(fd_in, &st) < 0) {
        close(fd_in);
        __android_log_print(ANDROID_LOG_ERROR, TAG, "fstat failed: %s", strerror(errno));
        return false;
    }

    size_t size = st.st_size;
    void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd_in, 0);
    if (data == MAP_FAILED) {
        close(fd_in);
        __android_log_print(ANDROID_LOG_ERROR, TAG, "mmap failed: %s", strerror(errno));
        return false;
    }

    // Копируем в mutable буфер
    std::vector<uint8_t> buffer(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
    munmap(data, size);
    close(fd_in);

    // ARM64: svc #0 = 0xd4000001 (little endian: 01 00 00 d4)
    // NOP = 0xd503201f (little endian: 1f 20 03 d5)
    // BRK #0 = 0xd4200000 (для отладки)
    const uint32_t SVC_ZERO = 0xd4000001;
    const uint32_t NOP_INSN = 0xd503201f;

    size_t patched = 0;
    for (size_t i = 0; i + 3 < buffer.size(); i += 4) {
        uint32_t insn = *reinterpret_cast<uint32_t*>(&buffer[i]);
        if (insn == SVC_ZERO) {
            // Заменяем svc #0 на NOP
            *reinterpret_cast<uint32_t*>(&buffer[i]) = NOP_INSN;
            patched++;
        }
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Patched %zu syscall instructions to NOP", patched);

    if (patched == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "No syscall instructions found, binary may already be patched or different arch");
    }

    // Записываем пропатченный бинарник
    int fd_out = open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open output: %s", strerror(errno));
        return false;
    }

    ssize_t written = write(fd_out, buffer.data(), buffer.size());
    close(fd_out);

    if (written != static_cast<ssize_t>(buffer.size())) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Write failed: %s", strerror(errno));
        unlink(output_path.c_str());
        return false;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Patched binary written to %s (%zu bytes)", output_path.c_str(), buffer.size());
    return true;
}

extern "C" bool patch_init_binary(const char* input_path, const char* output_path) {
    return patch_syscalls_in_binary(input_path, output_path);
}