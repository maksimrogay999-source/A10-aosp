# A10 (com.android.emulA10) — сводка

Нативный эмулятор AOSP (arm64, гость — **GSI Android 10 / Q**) поверх хост-системы Android 16: исполнение на реальном процессоре с перехватом (intercept), без QEMU/KVM.

## Правила работы (жёсткие)

- **Коммит и push:** после успешного этапа гостя и перехода к следующему — коммитить можно и нужно. До подтверждённого успешного перехода (пользователь поставил APK, запустил прогон, результат разобран) — код НЕ коммитить и НЕ пушить, все правки остаются в рабочем дереве. Исключение — по прямой просьбе пользователя.
- Сборка — **только** `tools.Androidgradle.gradle_build_debug` / `gradle_clean` (shell `./gradlew` = permission denied). APK пользователь ставит сам, ставить за него нельзя.
- Ответы — на русском. `log.txt` читать **только** по команде «читай лог»/«чекай лог» и **всегда целиком**.
- **Никакого хардкода путей.** Пути гостя разрешаются ТОЛЬКО через mount-таблицу (`<rootfs>/a10_mounts`): стаб её собирает, preload по ней переводит любой путь. Списков путей в коде быть не должно; поведение задаётся флагами записи, а не «магическими» путями.
- **Ничего общего у хоста и гостя:** `/proc`, `/sys`, `/dev/*`, selinuxfs, logd — всё эмулируется в гостевой ФС; хостовые `/system`, `/vendor`, сокет logd и устройства не используются.
- Никаких `ptrace` и бинарного патчинга. Номера syscall'ов сверять по документации/таблице, а не по памяти.

## Расположение
- Проект: `A10/` (Android/NDK, Kotlin + C++)
- Пакет: `com.android.emulA10`
- APK (debug): `A10/app/build/outputs/apk/debug/app-debug.apk`
- Образ GSI: `/storage/emulated/0/Download/gsi_gms_arm64-exp-QJR1.191112.001-6004257.zip` (system.img + vbmeta.img; vendor.img НЕТ)
- Рабочая папка (rootfs) в приложении: `/data/data/com.android.emulA10/files/aosp`
- Лог: `/storage/emulated/0/MargyCode/A10/log.txt` (Save Log в UI)

## Архитектура эмуляции (главное)

### Mount-таблица гостя — единственный источник правды по путям
- Файл: `<rootfs>/a10_mounts`, формат строки: `<guest> <host> [флаги]`.
- Наполняется автоматически, **без списков путей в коде**:
  1. **скан корня гостевой ФС** (стаб): каждый элемент верхнего уровня → `/<имя>` → `<rootfs>/<имя>`; симлинк → цель (цели абсолютных симлинков переводятся **внутрь** гостевой ФС, иначе гость ушёл бы в ФС хоста);
  2. **`mount()` гостя** (preload): регистрирует точку монтирования — host-путь = корень гостя (запись `/` таблицы) + target, тип ФС = аргумент `filesystemtype`; изменения сохраняются в файл таблицы (доживают до второй стадии);
  3. **`mknod()` гостя**: регистрирует устройство по номерам `major:minor` (`chr=1:11` и т.п.).
- Флаги записи: `rw`, `chmod_ok`, `console`, `selinux`, `logd`, `trace`, `magic=0xHEX` (f_type для statfs/fstatfs), `fallback=путь`, `fs=<тип>`, `chr=major:minor`, `procfs`.

### Эмуляция без «shared» с хостом
| Что | Как |
|---|---|
| `/proc`, `/sys`, `/dev/*` | гость монтирует сам → эмулируются; procfs-файлы (`filesystems`, `mounts`, `cmdline`) — виртуальные, содержимое генерируется |
| `/dev/null`, `zero`, `full`, `random`, `urandom`, `ptmx`, `kmsg` | гость создаёт через `mknod` → эмулируются по номерам устройств (null→EOF, zero→нули, random→`getrandom`, kmsg→консоль гостя) |
| selinuxfs | гость монтирует сам (`mount … selinuxfs`) → эмулируется: запись/ioctl — успех, `fstatfs` отдаёт magic **из записи таблицы** |
| logd | сокета logd хоста нет: `connect()` к любому AF_UNIX, которого нет в гостевой ФС, эмулируется успехом, сообщения гостя печатаются в консоль |
| `/data/data/…/aosp` (хостовый путь) | гость в ФС телефона не попадает: путь вне таблицы → `ENOENT`/`EACCES` |

### Ключевые технические находки (не терять!)
- **fortify-обёртки bionic**: гость собран с `_FORTIFY_SOURCE` → его `open()` превращается в `__open_2`, который зовёт **внутренний `__openat`** напрямую, минуя `open`/`openat`. Без перехвата `__openat`/`__open_2`/`__openat_2` гость читал файлы **хостовыми** путями (например sha-политики SELinux) и молча получал false.
- **Двойной перевод**: `fopen` → bionic → наш же `__openat` → host-путь переводится повторно → `ENOENT`. Перевод идемпотентен: путь, уже указывающий внутрь гостевой ФС, не переводится (`host_path_of()`).
- **SIGSYS**: обработчик, установленный в стабе, при `execve` **сбрасывается** (POSIX) → preload ставит свой обработчик **внутри** процесса init'а. `pkey_alloc` (syscall 219 на aarch64) блокируется seccomp телефона → в обработчике результат подменяется на 0 через `ucontext`.
- **Симлинки гостя**: цель переводится внутрь гостевой ФС; перевод идемпотентен (иначе пути разрастались `…/aosp/data/data/…/aosp/…` каждый прогон).
- **Политика SELinux — гостевая** (AOSP 10 GSI), собирается гостевым же `secilc` (`plat_sepolicy.cil` + `mapping/29.0.cil`, `-c 31`) → 343 241 байт. Ставится в `/sepolicy`, `/system/etc/selinux/precompiled_sepolicy`, `/vendor/…`, `/odm/…` + sha-пары (plat+product) и `plat_sepolicy_vers.txt`.
- **Политика гостя AOSP 10 требует**: `/system/etc/selinux/plat_sepolicy.cil`, `plat_sepolicy_and_mapping.sha256`, `/product/etc/selinux/product_sepolicy_and_mapping.sha256`, `/vendor/etc/selinux/precompiled_sepolicy{,.plat_sepolicy_and_mapping.sha256,.product_sepolicy_and_mapping.sha256}`, `plat_sepolicy_vers.txt` (совпадает с system-версией), а при самостоятельной компиляции — ещё `product_sepolicy.cil`, `product/etc/selinux/mapping/29.0.cil`, `vendor_sepolicy.cil`, `odm_sepolicy.cil`, `plat_pub_versioned.cil`.

## Что реализовано

### Сборка
- Gradle (AGP 8.5.2, Kotlin 1.9.24, NDK 29.x), `arm64-v8a` only, `targetSdk 28`.
- `a10stub` — **executable** (не SHARED), копируется в `assets/` через `add_custom_command` + `androidComponents`.
- `a10preload` — SHARED, только native lib (`lib/arm64-v8a`); без liblog и без libc++ (`-nostdlib++`).
- `packaging { jniLibs { useLegacyPackaging = true } }` — иначе preload не распаковывается в `nativeLibDir` (единственный путь, который линкер разрешает для LD_PRELOAD).

### UI (MainActivity)
- Статус, SurfaceView, лог с кнопками Start/Stop/Clear/Copy/Save Log.
- Авто-кнопки при смерти гостя: вотчдог `loaderGuestAlive()` (`waitpid(WNOHANG)` + EOF из console reader).
- Save Log: logcat → `/storage/emulated/0/MargyCode/A10/log.txt`, буфер очищается.
- Копирование из assets при старте: `a10stub` → `files/a10stub` (chmod +x).
- `AospDocumentsProvider`: доступ к rootfs через Storage Access Framework, authority `com.android.emulA10.documents`, `MANAGE_DOCUMENTS` обязателен.

### Распаковка (внутри приложения)
- ZIP GSI → `files/aosp`; повторное извлечение пропускается, если есть `init`/`system/`.
- `system.img`: sparse → raw → извлечение ext4 нативно (`image_extractor.cpp`, `ext4_extract.cpp`); рекурсивный `chmod +x`.

### Загрузчик (loader.cpp)
- Поиск init: стандартные пути, **симлинки пропускаются** (`lstat` + `S_ISREG`), затем рекурсивно.
- Supervisor-режим: fork → exec стаба (без ptrace). Seccomp user-notif ставится в форк-потомке; если хост блокирует `seccomp()` — таймаут 1 с и fallback (LD_PRELOAD + SIGSYS).

### Bootstrap-stub (stub_main.cpp)
- Скан корня гостевой ФС → mount-таблица; перевод целей симлинков внутрь гостя; дамп таблицы в лог.
- Гостевая SELinux-политика: сборка `secilc`-ом гостя, установка во все места + sha-пары + system/product-версии mapping + пустые CIL-секции (product/vendor/odm) + product-mapping.
- Окружение гостя: `ANDROID_ROOT`, `PATH`, `LD_LIBRARY_PATH` (только внутри rootfs), `LD_PRELOAD`, `A10_CONSOLE_FD`, `A10_ROOTFS`, `A10_MOUNTS_FILE`; `clearenv()` в preload восстанавливает их.
- Exec-проба LD_PRELOAD (A/B): ок-файл + маркер в консоли; winner → LD_PRELOAD для init.

### Preload (a10preload.cpp) — эмуляция syscall'ов гостя
- Перевод путей по таблице; вне таблицы → `ENOENT`/`EACCES` (в ФС телефона гость не попадает).
- Перехваты: `open/openat/open64/openat64/__openat/__open_2/__openat_2`, `stat*`, `access`, `readlink`, `opendir`, `fopen*`, `freopen`, `mkdir*`, `rmdir`, `unlink*`, `rename`, `symlink`, `link`, `chmod*`, `chown*`, `truncate`, `mkstemp*`, `execve/execv`, `chdir`, `read/write`, `mount/umount2`, `mknod`, `statfs/fstatfs`, `connect`, `clearenv`, `close`.
- Эмуляция: `mount`/`mknod` → регистрация в таблице; устройства по major/minor; selinuxfs (запись/ioctl успех, magic из таблицы); procfs-файлы; netlink → unix-socketpair; `clearenv` → восстановление окружения гостя.
- Диагностика: `A10_FAIL(...)` на каждой ошибке + трассировка успешных `open/fopen/access` (до 400) + дамп таблицы при старте.

## Где гость сейчас (состояние на 01:10)

| Стадия | Статус |
|---|---|
| 1. первая (`init`) | ✅ проходит: mount'ы /dev, /dev/pts, /proc, /sys, /sys/fs/selinux, /mnt, /apex, /debug_ramdisk; `mknod` устройств; `execv … second_stage` |
| 2. `selinux_setup` | ✅ проходит: гостевая политика загружена, `execv … second_stage` |
| 3. `second_stage` | ❌ падает: **«Failed to initialize property area»** — гостю не хватает `plat_file_contexts` (fopen не находит) и повторный `open(/dev/__properties__/property_info)` → `ENOENT` |
| 4. property service / servicemanager | ⏳ не начато (дальше — **binder**, `/dev/binder` хоста намеренно не трогаем) |

## Следующие шаги

1. **Property area:** обеспечить гостю `/system/etc/selinux/plat_file_contexts` (в GSI, похоже, только бинарный `.bin` или симлинк — стаб должен привести к текстовому/рабочему виду); разобраться с повторным `open("/dev/__properties__/property_info")` → `ENOENT` (кто удаляет файл) и с `memfd/ashmem`-созданием persistent properties.
2. **Binder:** второй стадии нужен `/dev/binder` — виртуальная реализация в `binder_emulator.cpp` (симлинк на хостовый binder НЕ создаём).
3. **procfs:** минимальный набор файлов (`self/*`, `mounts`, `filesystems`) — эмулируется по `fs=proc`.
4. **ueventd/netlink:** узлы `/dev/*` создаёт гость сам (mknod) — эмуляция работает; реальных uevent-событий нет.
5. **Свойства:** init читает `/system/build.prop` (в rootfs есть) — проверить `ro.build.version.sdk` и прочие, иначе zygote/system_server не поднимутся.
6. **SIGSYS-handler — выполнение syscall:** читать `si_call_addr`, декодировать, выполнять в host-контексте (сейчас для pkey_alloc подставляем 0, остальным возвращается `-ENOSYS`).

## История логов (ключевые этапы)

- **13:40–15:36** — эмуляция вместо блокировок; перехват сообщений гостя (liblog/`android_set_abort_message`), netlink-эмуляция; первая стадия init.
- **19:29–00:12** — SELinux-политика: precompiled-путь, sha-пары plat/product/system_ext, `secilc` гостя (`-c 31` + `mapping/29.0`), fstatfs→SELINUX_MAGIC.
- **21:20–22:00** — **mount-таблица**: пути гостя только через таблицу; symlink-цели внутрь гостя; `LD_LIBRARY_PATH` только внутри rootfs; `A10_MOUNTS_FILE` в env.
- **23:39–00:38** — гость монтирует selinuxfs **сам**; эмуляция procfs (файлы `filesystems/mounts/cmdline`); `chmod("/proc/cmdline")` перестал падать; перехват `__openat` (fortify) — гость наконец читает свои файлы.
- **00:48–01:04** — product-пара sha + гостевой `/odm`; system-версия mapping; пустые CIL-секции product/vendor/odm + product-mapping; **политика загрузилась, гость дошёл до `second_stage`**.
- **01:10** — SIGSYS-handler перенесён в preload (переживает exec); `pkey_alloc` больше не убивает init; падение на **property area** (`plat_file_contexts` не найден).
