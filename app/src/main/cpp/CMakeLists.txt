cmake_minimum_required(VERSION 3.22.1)
project("native-lib")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Структура исходников:
#   a10engine/  — движок эмуляции гостя (LD_PRELOAD): mount-таблица, пути,
#                 файловые операции, устройства, procfs/selinuxfs, свойства.
#   bootstrap/  — bootstrap-стаб: готовит ФС гостя, ставит гостевую политику,
#                 собирает mount-таблицу, запускает гостевой init.
#   host/       — сторона ХОСТА: загрузчик, распаковка образа, заглушки.
# ---------------------------------------------------------------------------

add_library(native-lib SHARED
    host/native-lib.cpp
    host/binder_emulator.cpp
    host/graphics_bridge.cpp
    host/audio_bridge.cpp
    host/loader.cpp
    host/image_extractor.cpp
    host/ext4_extract.cpp
    # host/aosp_unpacker.cpp — НЕ собирается: требует libzip (minizip), которого нет в NDK.
    # Распаковка GSI делается хостовым загрузчиком через image_extractor/ext4_extract.
)
target_include_directories(native-lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/host)

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

# a10preload: движок эмуляции гостя. Линкуется БЕЗ liblog и БЕЗ libc++
# (-nostdlib++): весь вывод через raw write в консоль (A10_CONSOLE_FD).
add_library(a10preload SHARED
    a10engine/console.cpp
    a10engine/devices.cpp
    a10engine/fsops.cpp
    a10engine/globals.cpp
    a10engine/init.cpp
    a10engine/modes.cpp
    a10engine/paths.cpp
    a10engine/procfs.cpp
    a10engine/props.cpp
    a10engine/selinux.cpp
    a10engine/sockets.cpp
    a10engine/syscalls.cpp
    a10engine/table.cpp
)
target_include_directories(a10preload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/a10engine)
target_link_options(a10preload PRIVATE -nostdlib++)

# a10stub: bootstrap executable (exec'ается loader'ом, сам ставит seccomp/LD_PRELOAD и exec'ает guest init).
# ВАЖНО: без этой цели в assets/a10stub лежит протухший бинарник.
add_executable(a10stub
    bootstrap/stub_main.cpp
)
target_include_directories(a10stub PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/a10engine)
target_link_libraries(a10stub
    ${log-lib}
)
add_custom_command(TARGET a10stub POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../assets
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:a10stub> ${CMAKE_CURRENT_SOURCE_DIR}/../assets/a10stub
    COMMENT "Copying a10stub to assets"
)
