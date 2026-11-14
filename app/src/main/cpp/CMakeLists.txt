cmake_minimum_required(VERSION 3.22.1)
project("native-lib")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(native-lib SHARED
    native-lib.cpp
    binder_emulator.cpp
    graphics_bridge.cpp
    audio_bridge.cpp
    loader.cpp
    image_extractor.cpp
    ext4_extract.cpp
)

# a10preload: LD_PRELOAD библиотека для перехвата mount/umount/statfs/etc (обходит хостовый seccomp).
# Собирается ТОЛЬКО как native lib (lib/arm64-v8a) — useLegacyPackaging=true распаковывает её
# в nativeLibDir, откуда её грузит LD_PRELOAD. Дубль в assets убран (источник один).
add_library(a10preload SHARED
    a10preload.cpp
)

find_library(log-lib log)
find_library(android-lib android)
find_library(egl-lib EGL)
find_library(opensles-lib OpenSLES)
target_link_libraries(native-lib
    ${log-lib}
    ${android-lib}
    ${egl-lib}
    ${opensles-lib}
)
# a10preload НЕ линкуется с liblog и БЕЗ libc++ (-nostdlib++): весь вывод через raw write
# в консоль (A10_CONSOLE_FD). При exec LD_PRELOAD линкер грузит только preload поверх уже
# готовой libc; зависимости liblog/libc++_shared при exec подтягивались заново — это окно,
# где зависли обе exec-пробы 13:40 (ни одного байта до конструктора).
target_link_options(a10preload PRIVATE -nostdlib++)

# a10stub: bootstrap executable (exec'ается loader'ом, сам ставит seccomp/LD_PRELOAD и exec'ает guest init).
# ВАЖНО: без этой цели в assets/a10stub лежит протухший бинарник.
add_executable(a10stub
    stub_main.cpp
)
target_link_libraries(a10stub
    ${log-lib}
)
add_custom_command(TARGET a10stub POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../assets
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:a10stub> ${CMAKE_CURRENT_SOURCE_DIR}/../assets/a10stub
    COMMENT "Copying a10stub to assets"
)