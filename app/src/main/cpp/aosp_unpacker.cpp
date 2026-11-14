#include "aosp_unpacker.h"
#include <android/log.h>
#include <zip.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <mutex>

#define TAG "A10_Unpack"

static std::string g_status;
static std::mutex g_mutex;

bool aosp_unpack(const std::string& zipPath, const std::string& destDir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_status.find("Unpacked") != std::string::npos) return true;

    // Создаём директорию, если её нет
    mkdir(destDir.c_str(), 0755);

    // Открываем ZIP-архив
    zip_t* zip = zip_open(zipPath.c_str(), 0, nullptr);
    if (!zip) {
        g_status = "Failed to open ZIP: " + zipPath;
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open ZIP: %s", zipPath.c_str());
        return false;
    }

    // Распаковываем все файлы
    zip_int64_t num_entries = zip_get_num_entries(zip, 0);
    for (zip_int64_t i = 0; i < num_entries; i++) {
        zip_stat_t st;
        if (zip_stat_index(zip, i, 0, &st) == -1) continue;

        std::string entry_name(st.name);
        std::string out_path = destDir + "/" + entry_name;

        // Создаём директории
        size_t pos = 0;
        while ((pos = out_path.find('/', pos + 1)) != std::string::npos) {
            std::string dir = out_path.substr(0, pos);
            mkdir(dir.c_str(), 0755);
        }

        // Распаковываем файл
        zip_file_t* file = zip_fopen_index(zip, i, 0);
        if (!file) continue;

        FILE* out = fopen(out_path.c_str(), "wb");
        if (!out) {
            zip_fclose(file);
            continue;
        }

        char buf[8192];
        zip_int64_t len;
        while ((len = zip_fread(file, buf, sizeof(buf))) > 0) {
            fwrite(buf, 1, len, out);
        }
        fclose(out);
        zip_fclose(file);
    }

    zip_close(zip);
    g_status = "Unpacked to: " + destDir;
    __android_log_print(ANDROID_LOG_INFO, TAG, "AOSP unpacked to: %s", destDir.c_str());
    return true;
}

std::string aosp_unpack_status() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_status;
}