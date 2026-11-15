# A10 (com.android.emulA10) — сводка

Нативный эмулятор AOSP (arm64, гость — **GSI Android 10 / Q**) поверх хост-системы Android 16: исполнение на реальном процессоре с перехватом (intercept), без QEMU/KVM.

## Правила работы (жёсткие)

- **Коммит и push:** после успешного этапа гостя и перехода к следующему — коммитить можно и нужно. До подтверждённого успешного перехода (пользователь поставил APK, запустил прогон, результат разобран) — код НЕ коммитить и НЕ пушить, все правки остаются в рабочем дереве. Исключение — по прямой просьбе пользователя.
- Сборка — **только** `tools.Androidgradle.gradle_build_debug` / `gradle_clean` (shell `./gradlew` = permission denied). APK пользователь ставит сам, ставить за него нельзя.
- Ответы — на русском. `log.txt` читать **только** по команде «читай лог»/«чекай лог» и **всегда целиком**.
- **Никакого хардкода путей.** Пути гостя разрешаются ТОЛЬКО через mount-таблицу (`<rootfs>/a10_mounts`): стаб её собирает, preload по ней переводит любой путь. Списков путей в коде быть не должно; поведение задаётся флагами записи, а не «магическими» путями.
- **Идемпотентность перевода.** Корень гостя — `/data/data/…/aosp`, а гостевой путь `/data` тоже есть в таблице. Поэтому уже переведённый (host) путь повторно НЕ переводится (`lookup_guest()`): иначе `…/aosp/data/data/…` (и `ENOENT` при открытии).
- **Ничего общего у хоста и гостя:** `/proc`, `/sys`, `/dev/*`, selinuxfs, logd — всё эмулируется в гостевой ФС; хостовые `/system`, `/vendor`, сокет logd, устройства и **selinuxfs хоста** не используются.
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
| **свойства** | общая область свойств телефона **не используется**: `__system_property_area_init`→0, `__system_property_find`→nullptr, `__system_property_add`/`_get`/`_update` → свой файл гостя `/dev/__properties__/guest_properties` (key=value) |
| **shared memory гостя** | `memfd_create`/`ashmem_create_region` для имён с «property» → обычный файл в гостевой ФС `/dev/__properties__/<name>` (не память телефона) |
| **chown гостя** | `fchown/chown/lchown/fchownat` → успех (гость root); файлы без прав на запись расширяются до 0664 |

### Ключевые технические находки (не терять!)
- **Запись в консоль гостя — только частями по ≤1024 байт.** Пайп телефона даёт атомарность только на `PIPE_BUF` (4096); большая запись (дамп таблицы гостя ~8 КБ) обрывается на свободном месте, и **весь последующий вывод теряется** (лог 14:55: вторая стадия молчала — не было ни одного лога перехватов). `console_raw()` пишем кусками с повтором.
- **Трекер fd гостя — только для гостевых путей.** Наш собственный код (файлы свойств гостя, файлы procfs) открывает файлы по **host-путям**; если такие пути попадают в трекер, то относительный `open()` гостя склеивается с host-путём каталога, и путь гостя «заражается». Правило: `track_set_path()` вызываем только для гостевых путей; `fopen()` тоже отслеживает свой fd (`fileno`) и помечает виртуальный файл procfs.
- **Трекер fd не должен заводить дубль слота.** `close()` гостя часто уходит мимо перехвата (`fclose()` из libc++ зовёт внутренний close) → слот остаётся занятым. Следующий `open()` того же fd добавлял ВТОРОЙ слот, и `track_take_virt()`/`proc_kind_of_fd()` отдавали данные ПРЕДЫДУЩЕГО файла: гость читал пустоту вместо содержимого (`No version present in plat_sepolicy_vers.txt` — fd достался от виртуального `/proc/cmdline`). **Правило: `track_add()` переиспользует слот, если такой fd уже отслеживается** (и чистит виртуальные данные).
- **Реестр прав гостя** (`a10engine/modes.cpp`, файл `<rootfs>/a10_modes`, env `A10_MODES_FILE`): мы расширяем реальные права файлов до 0664, чтобы гость мог писать, но **запоминаем исходный режим** и в `stat()` показываем гостю ИСХОДНЫЙ (propertyinfoparser требует, чтобы `property_info` не был доступен на запись группе/остальным). Реестр переживает перезапуск приложения.
- **Файлы гостя должны выглядеть как root-овые.** `propertyinfoparser` (AOSP 10, `system/core/property_service/libpropertyinfoparser/`) при загрузке `property_info` требует:
  ```c
  if ((fd_stat.st_uid != 0) || (fd_stat.st_gid != 0) ||
      ((fd_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0) ||
      (fd_stat.st_size < sizeof(PropertyInfoArea))) return false;   // -> "Failed to load serialized property info file"
  ```
  Мы — обычное приложение (uid приложения), `chown(0,0)` без CAP_CHOWN невозможен, поэтому в stat-семействе гостю подставляется uid=0, gid=0 (см. реестр прав выше).
- **Проверки доступа SELinux у гостя решаем сами**: `selinux_check_access()` перехватывается и разрешает доступ — ядро хоста не знает гостевых классов (`Unknown class property_service` → `Init cannot set 'ro.bootmode': SELinux permission check failed`).
- **Линковка перехватов — C, иначе гость их не видит.** Функция, определённая в C++ без `extern "C"`, экспортируется с mangling (`_Z5mountPKc...`) и **не перехватывает** libc-функцию: гость уходит в реальный syscall. Симптом: `=== SIGSYS: syscall 40 -> ENOSYS ===` (40 = `mount` на aarch64) и `Init encountered errors starting first stage, aborting` — гость делает 8 mount'ов, все падают, `CHECKCALL` собирает ошибки → FATAL.
  - **Правило:** любой перехват имени libc обязан иметь `extern "C"`. Объявления критичных перехватов вынесены в `a10engine/a10engine.h` — если в модуле определение окажется с C++-линковкой, компилятор даст «conflicting declaration» (защита от повтора).
  - **Проверка после сборки:** `readelf -W --dyn-syms liba10preload.so | grep -w mount` — символ должен быть **без** `_Z`-префикса.
  - Проверено и исправлено 26 перехватов: `mount`, `umount2`, `ioctl`, `statx`, `lgetxattr`, `fgetxattr`, `lsetxattr`, `setxattr`, `fsetxattr`, `removexattr`, `setfsuid`, `setfsgid`, `capset`, `reboot`, `swapon`, `swapoff`, `settimeofday`, `clock_settime`, `sched_setscheduler`, `init_module`, `delete_module`, `kexec_load`, `adjtimex`, `setpriority`, `syslog`, `pivot_root`, `setdomainname`.
  - `ioctl` объявлен как в bionic: `int ioctl(int fd, int request, ...)` (не `unsigned long`) — иначе конфликт с `<sys/ioctl.h>`.
- **Гость читает файлы через fortify**: `fstat` → `__fxstat`, `read` → `__read_chk` — это **внутренние обёртки libc**, мимо нашего перехвата (наши `fstat`/`read` их не видят). Поэтому «нет вызова fstat» в логе ≠ «гость не читал файл».
- **Сообщения гостя (LOG(INFO/ERROR)) идут в `/dev/kmsg`** (init переводит stdout/stderr на kmsg). Часть из них идёт мимо перехвата `write` (внутри libc stdio → служебный `__write`) и попадает в файл `<rootfs>/dev/kmsg` — **его дампит загрузчик при смерти гостя** (`guest-kmsg:`), а стаб — в начале следующего прогона (то есть дамп стаба показывает сообщения **предыдущего** прогона).
- **Каждое сообщение в консоль должно кончаться `\n`**: без перевода строки сообщения гостя слипались в одну гигантскую строку, и logcat её обрезал/отбрасывал (лог 13:31: сообщений гостя в logcat не было, хотя на экране они были).
- **Сокет logd гостя** (`/dev/socket/logdw`): `connect()` к AF_UNIX, которого нет в гостевой ФС, теперь подключает гостя к **socketpair**, а отдельный поток читает сообщения и печатает их в консоль (`[guest log] …`). Раньше `connect()` просто «успевал», запись уходила в никуда — все `LOG()` гостя терялись.
- **Первая стадия init (AOSP 10)** = `system/core/init/first_stage_init.cpp`: `CHECKCALL` на каждую операцию (mount tmpfs /dev, devpts /dev/pts, proc /proc, sysfs /sys, selinuxfs /sys/fs/selinux, tmpfs /mnt, /apex, /debug_ramdisk; mkdir /dev/pts, /dev/socket, /mnt/vendor, /mnt/product; chmod /proc/cmdline; setgroups; mknod /dev/{kmsg,random,urandom,ptmx,null}). Любая ошибка → `LOG(FATAL) "Init encountered errors starting first stage, aborting"`. Текст ошибок уходит в logd гостя (не видно), спасает только `android_set_abort_message`.
- **fortify-обёртки bionic**: гость собран с `_FORTIFY_SOURCE` → его `open()` превращается в `__open_2`, который зовёт **внутренний `__openat`** напрямую, минуя `open`/`openat`. Без перехвата `__openat`/`__open_2`/`__openat_2` гость читал файлы **хостовыми** путями (например sha-политики SELinux) и молча получал false.
- **Двойной перевод**: `fopen` → bionic → наш же `__openat` → host-путь переводится повторно → `ENOENT`. Перевод идемпотентен: путь, уже указывающий внутрь гостевой ФС, не переводится (`host_path_of()`).
- **SIGSYS**: обработчик, установленный в стабе, при `execve` **сбрасывается** (POSIX) → preload ставит свой обработчик **внутри** процесса init'а. `pkey_alloc` (syscall 219 на aarch64) блокируется seccomp телефона → в обработчике результат подменяется на 0 через `ucontext`.
- **Симлинки гостя**: цель переводится внутрь гостевой ФС; перевод идемпотентен (иначе пути разрастались `…/aosp/data/data/…/aosp/…` каждый прогон).
- **Политика SELinux — гостевая** (AOSP 10 GSI), собирается гостевым же `secilc` (`plat_sepolicy.cil` + `mapping/29.0.cil`, `-c 31`) → 343 241 байт. Ставится в `/sepolicy`, `/system/etc/selinux/precompiled_sepolicy`, `/vendor/…`, `/odm/…` + sha-пары (plat+product) и `plat_sepolicy_vers.txt`.
- **Политика гостя AOSP 10 требует**: `/system/etc/selinux/plat_sepolicy.cil`, `plat_sepolicy_and_mapping.sha256`, `/product/etc/selinux/product_sepolicy_and_mapping.sha256`, `/vendor/etc/selinux/precompiled_sepolicy{,.plat_sepolicy_and_mapping.sha256,.product_sepolicy_and_mapping.sha256}`, `plat_sepolicy_vers.txt` (совпадает с system-версией), а при самостоятельной компиляции — ещё `product_sepolicy.cil`, `product/etc/selinux/mapping/29.0.cil`, `vendor_sepolicy.cil`, `odm_sepolicy.cil`, `plat_pub_versioned.cil`.
- **Виртуальные файлы** (procfs/selinuxfs) выдаются **по позиции**: содержимое генерируется один раз при `open()` и читается кусками, как обычный файл. Иначе гость читает одни и те же первые килобайты и не доходит до нужного контекста.
- **Список контекстов гостя** (`/sys/fs/selinux/contexts`) собирается из гостевых файлов `*_contexts` (file/service/property/hwservice/seapp) — только значения вида `u:…`; SID-пространство своё (нумерация по списку).

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

### Структура исходников (`app/src/main/cpp/`)
| Папка | Что внутри |
|---|---|
| `a10engine/` | **движок эмуляции гостя** (LD_PRELOAD `liba10preload.so`), разложен по модулям: `a10engine.h` (общие extern-глобалы, `REAL_FN`, `A10_FAIL`), `table.cpp` (mount-таблица: загрузка/поиск/перевод/сохранение), `paths.cpp` (перевод путей, права, magic ФС), `console.cpp` (консоль гостя, перехват `__android_log_*`/`abort`, `plog`, `trace_slot`), `sockets.cpp` (netlink-эмуляция, logfd, connect/writev/sendto), `devices.cpp` (устройства гостя, трекинг fd/путей, `guest_shared_memory`, `memfd_create`/`ashmem_create_region`), `procfs.cpp` (виртуальные файлы procfs/selinuxfs), `selinux.cpp` (file_contexts гостя, SID-пространство, перехваты гостевой libselinux), `fsops.cpp` (open/stat/access/fopen/chmod/chown…), `syscalls.cpp` (mount/mknod/exec/chdir/clearenv/ioctl/statfs/write/ftruncate/mmap/SIGSYS), `props.cpp` (свойства гостя — свой файл), `globals.cpp` (общие переменные), `init.cpp` (конструктор preload), `mounts.h` (разбор формата mount-таблицы) |
| `bootstrap/` | `stub_main.cpp` — bootstrap-стаб: скан корня гостевой ФС, симлинки внутрь гостя, установка гостевой политики, сборка таблицы, `A10_MOUNTS_FILE` в env |
| `host/` | сторона **хоста**: `loader.cpp` (загрузчик/супервизор), `image_extractor.cpp` + `ext4_extract.cpp` (распаковка system.img), `binder_emulator.cpp`, `graphics_bridge.cpp`, `audio_bridge.cpp`, `native-lib.cpp`. `aosp_unpacker.cpp` **не собирается** (нужен libzip, его нет в NDK) |

> `a10preload.cpp` и `stub_main.cpp`/`loader.cpp` разбиты на модули; старый монолит удалён. Перенос сделан скриптом по маркерам функций, поэтому проверять diff глазами обязательно: после `git checkout` прежние незакоммиченные правки откатываются.

### Preload (a10engine/*) — эмуляция syscall'ов гостя
- Перевод путей по таблице; вне таблицы → `ENOENT`/`EACCES` (в ФС телефона гость не попадает).
- Перехваты: `open/openat/open64/openat64/__openat/__open_2/__openat_2`, `stat*`, `access`, `readlink`, `opendir`, `fopen*`, `freopen`, `mkdir*`, `rmdir`, `unlink*`, `rename`, `symlink`, `link`, `chmod*`, `chown*`, `truncate`, `mkstemp*`, `execve/execv`, `chdir`, `read/write`, `mount/umount2`, `mknod`, `statfs/fstatfs`, `connect`, `clearenv`, `close`.
- Эмуляция: `mount`/`mknod` → регистрация в таблице; устройства по major/minor; selinuxfs (запись/ioctl успех, magic из таблицы); procfs-файлы; netlink → unix-socketpair; `clearenv` → восстановление окружения гостя.
- Диагностика: `A10_FAIL(...)` на каждой ошибке + трассировка успешных `open/fopen/access` (до 400) + дамп таблицы при старте.

## Где гость сейчас (состояние на 01:47)

| Стадия | Статус |
|---|---|
| 1. первая (`init`) | ✅ проходит: mount'ы /dev, /dev/pts, /proc, /sys, /sys/fs/selinux, /mnt, /apex, /debug_ramdisk; `mknod` устройств; `execv … second_stage` |
| 2. `selinux_setup` | ✅ проходит: гостевая политика записана в эмулированный selinuxfs (`/sys/fs/selinux/load`, 343 241 байт), enforce/checkreqprot; `execv … second_stage` |
| 3. `second_stage` | ⏳ прогон **14:32**: **`property_init` пройден** (property_info загрузился — барьер снят правкой root-владения), свойства ставятся (`ro.build.fingerprint`), `restorecon` идёт, **сокет property-сервиса создан** (`Created socket '/dev/socket/property_service'` — починили перевод пути в `bind()`). ❌ Барьер: `epoll_ctl failed to add fd: Operation not permitted` — гость регистрирует сокет в epoll, EPERM. Добавлена диагностика: `epoll_ctl` перехвачен (лог + тип fd), `socket()`/`bind()` с номерами fd, тест epoll в стабе (`epoll-test:`) — выясняем, блокирует ли хост epoll_ctl или fd не поддерживает epoll. |
| 4. restorecon | ✅ пройден (13:19): эмуляция `/proc/self/fd/N` (путь гостя из трекера fd) + `lgetfilecon` по правилам гостя |
| 5. сервисы / servicemanager | ⏳ не начато (дальше — **binder**, `/dev/binder` хоста намеренно не трогаем) |
| 4. restorecon | ✅ пройден (13:19): эмуляция `/proc/self/fd/N` (путь гостя из трекера fd) + `lgetfilecon` по правилам гостя |
| 5. сервисы / servicemanager | ⏳ не начато (дальше — **binder**, `/dev/binder` хоста намеренно не трогаем) |

### Разбор `restorecon failed of /system/bin/init: ENOENT` (01:47)
- Правило в file_contexts **есть** (`/system/bin/init → u:object_r:init_exec:s0`, 541 строка), файл читается ✓.
- Значит, падает проверка контекста: libselinux сверяет контекст со списком `/sys/fs/selinux/contexts`.
- Причины и правки:
  1. список контекстов собирался только из `*_property_contexts` — теперь из **всех** гостевых `*_contexts` (`plat_file_contexts`, `plat_service_contexts`, `plat_property_contexts`, `plat_hwservice_contexts`, `plat_seapp_contexts`), только значения вида `u:…`;
  2. виртуальные файлы выдавались **всегда с начала** — теперь содержимое генерируется один раз при `open()` и выдаётся **по позиции** (буфер 256 КБ, кусками по 64 КБ);
  3. `ioctl(SECURITY_CTX_TO_SID)` возвращает SID **по позиции контекста** в списке гостя; `SID_TO_CTX` — обратно.

## Следующие шаги

1. **Прогон с новым APK** (рефакторинг движка + эмуляция свойств/shared memory/chown): цель — `__system_property_area_init` → property service → servicemanager. Логировать в `log.txt`.
2. **restorecon** — если ENOENT останется, смотреть, какие файлы libselinux открывает (лог `open()` покажет).
3. **init.rc** — в rootfs есть (`/init.rc` в корне гостевой ФС, в таблице есть); гость его проходит, но сервисы из него могут потребовать `/dev/binder` и системных свойств.
4. **Binder:** второй стадии нужен `/dev/binder` — виртуальная реализация в `binder_emulator.cpp` (симлинк на хостовый binder НЕ создаём).
5. **procfs:** минимальный набор файлов (`self/*`, `mounts`, `filesystems`) — эмулируется по `fs=proc`.
6. **ueventd/netlink:** узлы `/dev/*` создаёт гость сам (mknod) — эмуляция работает; реальных uevent-событий нет.
7. **Свойства:** init читает `/system/build.prop` (в rootfs есть) — проверить `ro.build.version.sdk` и прочие, иначе zygote/system_server не поднимутся. Свойства гостя лежат в его файле `/dev/__properties__/guest_properties`, свойства телефона не подмешиваются.
8. **SIGSYS-handler — выполнение syscall:** читать `si_call_addr`, декодировать, выполнять в host-контексте (сейчас для pkey_alloc подставляем 0, остальным возвращается `-ENOSYS`).

## История логов (ключевые этапы)

- **13:16** — **первая стадия прошла целиком** (после починки C-линковки): 8 mount'ов, `mknod` устройств, `execv … selinux_setup`; selinuxfs отдал magic из таблицы, политика гостя загрузилась. Барьер — `restorecon` (`readlink("/proc/self/fd/N")` → ENOENT). Починено эмуляцией `/proc/self/fd/N` + трекером путей fd.
- **13:06** — прогон после рефакторинка движка: гость упал в **первой** стадии («Init encountered errors starting first stage»). Разбор: `mount()` не перехватывался (C++-линковка → символ `_Z5mount...`), 8 mount'ов ушли в реальный syscall → SIGSYS(40) → ENOSYS → `CHECKCALL` → FATAL. Исправлено 26 перехватов, добавлены объявления-перехваты в `a10engine.h` как защита от повтора.
- **13:40–15:36** — эмуляция вместо блокировок; перехват сообщений гостя (liblog/`android_set_abort_message`), netlink-эмуляция; первая стадия init.
- **19:29–00:12** — SELinux-политика: precompiled-путь, sha-пары plat/product/system_ext, `secilc` гостя (`-c 31` + `mapping/29.0`), fstatfs→SELINUX_MAGIC.
- **21:20–22:00** — **mount-таблица**: пути гостя только через таблицу; symlink-цели внутрь гостя; `LD_LIBRARY_PATH` только внутри rootfs; `A10_MOUNTS_FILE` в env.
- **23:39–00:38** — гость монтирует selinuxfs **сам**; эмуляция procfs (файлы `filesystems/mounts/cmdline`); `chmod("/proc/cmdline")` перестал падать; перехват `__openat` (fortify) — гость наконец читает свои файлы.
- **00:48–01:04** — product-пара sha + гостевой `/odm`; system-версия mapping; пустые CIL-секции product/vendor/odm + product-mapping; **политика загрузилась, гость дошёл до `second_stage`**.
- **01:10** — SIGSYS-handler перенесён в preload (переживает exec); `pkey_alloc` больше не убивает init.
- **01:18–01:33** — найден **двойной перевод** путей: корень гостя = `/data/data/…/aosp`, а гостевой путь `/data` тоже есть в таблице → host-путь переводился сам в себя (`…/aosp/data/data/…`). Исправлено через `lookup_guest()`: уже переведённый путь не переводится повторно.
- **01:38–01:47** — `plat_file_contexts` читается ✓, **property area инициализировалась** ✓; барьер — `restorecon` (см. выше).
