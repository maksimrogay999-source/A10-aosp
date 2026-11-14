# A10 (com.android.emulA10) — сводка

Нативный эмулятор AOSP (arm64) поверх хост-системы Android: исполнение на реальном процессоре с перехватом (intercept), без QEMU/KVM.

## Правила работы (жёсткие)

- **Коммит и push — ТОЛЬКО после проверки пользователем.** Пока пользователь не установил APK, не запустил прогон и не дал команду «читай лог» (и результат не разобран) — код НЕ коммитить и НЕ пушить. Все правки остаются в рабочем дереве. Исключение — только по прямой просьбе пользователя.
- Сборка — **только** `tools.Androidgradle.gradle_build_debug` / `gradle_clean` (shell `./gradlew` = permission denied). APK пользователь ставит сам, ставить за него нельзя.
- Ответы — на русском. `log.txt` читать **только** по команде «читай лог»/«чекай лог» и **всегда целиком**.
- Никаких `ptrace` и бинарного патчинга. Номера syscall'ов сверять по документации/таблице, а не по памяти.
- Инцидент 14:19: коммит `3eddbdb` («эмуляция») был запушен до проверки — нарушение правила выше.

## Расположение
- Проект: `A10/` (Android/NDK, Kotlin + C++)
- Пакет: `com.android.emulA10`
- APK (debug): `A10/app/build/outputs/apk/debug/app-debug.apk`
- Образ GSI: `/storage/emulated/0/Download/gsi_gms_arm64-exp-QJR1.191112.001-6004257.zip`
- Рабочая папка (rootfs) в приложении: `/data/data/com.android.emulA10/files/aosp`
- Лог: `/storage/emulated/0/MargyCode/A10/log.txt` (Save Log в UI)

## Что реализовано

### Сборка
- Gradle (AGP 8.5.2, Kotlin 1.9.24, NDK 29.x), `arm64-v8a` only, `targetSdk 28`.
- `a10stub` — собирается как **executable** (не SHARED), копируется в `assets/` через `add_custom_command` + `androidComponents` (mergeAssets зависит от buildCMake).
- `a10preload` — собирается как SHARED и упаковывается ТОЛЬКО как native lib (`lib/arm64-v8a`); копирование в assets убрано (дубль удалён — источник один). Линкуется БЕЗ liblog и БЕЗ libc++ (`target_link_options(a10preload PRIVATE -nostdlib++)`) — см. Bootstrap-stub/LD_PRELOAD.
- В `app/build.gradle.kts` включён `packaging { jniLibs { useLegacyPackaging = true } }` — иначе с AGP 8 `extractNativeLibs=false` и `liba10preload.so` НЕ распаковывается в `nativeLibDir`, а это единственный путь, который линкер разрешает для LD_PRELOAD.

### UI (MainActivity)
- Статус, SurfaceView для вывода, лог с кнопками Start/Stop/Clear/Copy/Save Log.
- **Авто-кнопки при смерти гостя:** вотчдог-поток раз в секунду зовёт JNI `loaderGuestAlive()` (loader: `waitpid(WNOHANG)` + флаг EOF из console reader). На смерть — Start enabled, Stop disabled, статус «Guest init exited».
- **Save Log:** сохраняет logcat в `/storage/emulated/0/MargyCode/A10/log.txt` (приоритет: по пакету/PID'ам приложения, затем по UID, затем по тегам `A10_Loader`/`A10_Ptrace`/`A10_Stub`, затем полный буфер) и очищает буфер (`logcat -c`).
- **Копирование из assets при старте:** `a10stub` → `files/a10stub` (chmod +x). Копия preload больше не делается.
- **DocumentProvider (`AospDocumentsProvider`):** доступ к rootfs через Storage Access Framework. Корневой каталог: `files/aosp`. Authority: `com.android.emulA10.documents`. Просмотр/открытие/создание/удаление/переименование файлов гостя через системные файловые менеджеры.

### Распаковка (внутри приложения)
- Распаковка ZIP GSI в `files/aosp`.
- Если уже есть `init` или `system/` — повторное извлечение пропускается.
- Детекция после распаковки: логирование наличия `boot.img`/`vbmeta.img` (GSI не содержит boot — это ожидаемо).
- Извлечение `system.img`: конвертация **sparse → raw** (`system.img.raw`) и извлечение **ext4** в rootfs нативно (`image_extractor.cpp`, `ext4_extract.cpp`).
- Рекурсивный `chmod +x` после извлечения.

### Загрузчик (loader.cpp)
- Поиск init в `/init`, `/sbin/init`, `/system/bin/init`, `/system/bin/init_second_stage`, `/bin/init`, `/system/xbin/init`, затем рекурсивно.
- **Legacy-режим (без stub):** fork + PTRACE_TRACEME + SIGSTOP → PTRACE_SETOPTIONS → PTRACE_CONT → ptrace loop thread. Оставлен для отката.
- **Supervisor-режим (с stub):** fork → exec stub (без ptrace, без SIGSTOP). Stub устанавливает seccomp-фильтр, передаёт notify_fd через SCM_RIGHTS. Loader запускает supervisor receiver thread. Ptrace не используется.
- Стоп неблокирующий (SIGKILL + неблокирующий reap).

### Bootstrap-stub (stub_main.cpp)
- Собирается как **executable** (`a10stub`), не SHARED (у SHARED нет точки входа для execve). Цель `add_executable(a10stub)` в CMakeLists.txt ОБЯЗАТЕЛЬНА — без неё в `assets/a10stub` остаётся протухший бинарник (так уже случилось 14.11: цель потерялась, полдня гоняли старый стаб).
- Запускается первым: `a10stub <guest_init> <rootfs_dir>`.
- **Seccomp user-notif — обязательный этап, в fork-потомке ("seccomp worker"):** `SIGSYS=SIG_IGN` → fork → в потомке `PR_SET_NO_NEW_PRIVS` + фильтр `SECCOMP_RET_USER_NOTIF` (~35 критичных syscalls) → notify_fd уходит супервизору через SCM_RIGHTS по `A10_SUPERVISOR_FD` → ack `'O'` в CLOEXEC-пайп → `execve(init)`. Родитель ждёт ack: если потомка убили на syscall `seccomp()` (хост, SECCOMP_RET_KILL — SIG_IGN не спасает), родитель делает fallback: закрывает sup-сокет (супервизор корректно завершается) и exec'ает init напрямую с LD_PRELOAD + SIGSYS. Так seccomp выполняется каждый запуск и не ломает launch.
- **LD_PRELOAD (`liba10preload.so`) — ЭМУЛЯЦИЯ, а не блокировки.** Перехваченные вызовы **выполняются по-настоящему** (реальные syscall'ы по переведённым путям), а не имитируются:
  - **Перевод путей гостя:** `/system,/vendor,/product,/apex,/odm,/oem,/dev,/data,/mnt,/cache,/metadata,/sdcard,/storage,/sepolicy` → `<rootfs>/...` (env `A10_ROOTFS`). `/proc` и `/sys` остаются реальными (настоящее ядро хоста).
  - **Файловые операции — честные:** `open/openat/stat/lstat/fstat/fstatat/statx/access/mkdir/mkdirat/rmdir/unlink/unlinkat/rename/symlink/link/readlink/chmod/chown/truncate/opendir` — перевод пути + настоящий syscall. Запись разрешена только внутрь rootfs и в `/proc`,`/sys` (вне — `EACCES`), чтобы гость не писал в ФС телефона.
  - **Привилегированные вызовы** (`mount`, `umount2`, `mknod`, `setgroups`, `setuid*`, `reboot`, `swapon`, `capset`, `chroot`, `pivot_root`…) — эмулируются успехом + запись в консоль (прав на хосте нет).
  - **arm64-особенность:** на arm64 нет syscall'ов `mkdir/unlink/rename/symlink/link/readlink` — только `*at`-варианты (`mkdirat=34, unlinkat=35, symlinkat=36, linkat=37, renameat=38, readlinkat=78, newfstatat=79, faccessat=48, fchmodat=53, fchownat=54, statx=332`), поэтому реальные функции берутся через `dlsym(RTLD_NEXT, ...)` libc.
  - **exec переводится:** `execve/execv` с гостевым путём → `<rootfs>/...` (иначе init второй стадии запустил бы ХОСТОВЫЙ `/system/bin/init`!). `chdir("/")` → rootfs.
  - **SELinux эмулируется:** `access(/system/etc/selinux/plat_sepolicy.cil)` → ENOENT (нет vendor-раздела → не split-политика), гостю отдаётся монолитный `/sepolicy` (прекомпилированная политика гостя), запись в `/sys/fs/selinux/*` и `setxattr` (restorecon) считаются успешными, `__system_property_get("ro.boot.selinux")` → `"1"` (SELinux отключён).
  - **clearenv:** init стирает окружение перед exec второй стадии — перехватчик восстанавливает `LD_LIBRARY_PATH`/`PATH` гостя, иначе его бинарники не найдут свои библиотеки.
  - **Зависимостей нет:** DT_NEEDED = `libc/libdl/libm` (без liblog, без libc++): при exec линкер грузит только preload поверх готовой libc.
- **Подготовка гостевой ФС (стаб):** каталоги (`/dev`, `/dev/pts`, `/dev/socket`, `/data/property`, `/mnt/*`, `/apex`…), симлинки `<rootfs>/dev/{null,kmsg,urandom,random,ptmx,zero,full,tty}` → настоящие устройства хоста (цель абсолютная → ядро откроет реальный узел), монолитная политика `<rootfs>/sepolicy`. `chdir(rootfs)` — корень гостя.
- **SIGSYS handler (вместо SIG_IGN):** `sigaction(SIGSYS, SA_SIGINFO)` до seccomp-этапа — выживает через exec, наследуется init'ом. **SIG_IGN не работает против SECCOMP_RET_TRAP:** ядро шлёт SIGSYS через force_sig, не глядя на SIG_IGN (лог 13:40: init умер `Fatal signal 31, syscall 40` при SIG_IGN). Установленный handler force_sig ДОСТАВЛЯЕТ; после возврата handler'а ядро возвращает -ENOSYS из заблокированного syscall'а. Handler пишет в консоль `SIGSYS caught: syscall N -> ENOSYS` (из si_syscall) — init выживает, видно, какой syscall хост блокирует.
- **Окружение guest init:**
  - `ANDROID_ROOT=<rootfs>/system`
  - `PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin`
  - `LD_LIBRARY_PATH=<rootfs>/system/lib64:<rootfs>/system/lib:<rootfs>/lib64:<rootfs>/lib:<rootfs>/vendor/lib64:<rootfs>/vendor/lib`
  - `LD_PRELOAD=<nativeLibDir>/liba10preload.so` (nativeLibDir = `/data/app/~~.../lib/arm64`, передаётся loader'ом через env `A10_NATIVE_LIB_DIR`; пути из filesDir линкер не разрешает)
  - `A10_CONSOLE_FD=<fd>` — номер консольного пайпа и ВНУТРИ init (preload-конструктор читает его из env для перехвата /dev/kmsg).
  - Перед exec стаб пишет дамп финального env в консоль (строки `[env] ...` в теге `A10_Guest`).
- **Exec-проба LD_PRELOAD:** перед seccomp-этапом стаб fork'ает потомка, который exec'ает СЕБЯ ЖЕ (argv без аргументов, тот же envp с LD_PRELOAD + A10_CONSOLE_FD + A10_PROBE_LABEL + A10_PROBE_OK_FILE). Конструктор preload ПЕРВЫМ делом (raw-сисколлы openat/write/close) пишет ok-файл и маркер `=== a10preload.so LOADED at exec (probe X) ===` в консоль. Родитель ПОЛЛИТ ok-файл каждые 20мс: появился — `PROBE_LOADED` (линкер загрузил preload; потомка добивают, его судьба дальше не важна). Нет ok-файла и нет exit за 1500мс — `PROBE_HUNG` (зависание до/в конструкторе). Exit без ok-файла — `PROBE_NOT_LOADED` (линкер молча пропустил). В потомке пробы logd-вызовы стаба отключены (проверяется линкер, а не наш лог).

### Seccomp-супервизор (loader.cpp)
- `seccomp_supervisor_loop`: цикл `RECV/ID_VALID/SEND(CONTINUE)` (allow) для перехваченных syscalls.
- `start_supervisor_receiver_thread`: отдельный поток, принимает notify_fd через socketpair.
- **Принцип:** ядро берёт самое строгое seccomp-действие из всех фильтров. Если хост блокирует syscall через `KILL`/`TRAP`/`ERRNO`, наш `USER_NOTIF` не сработает (более слабый приоритет). Для таких syscalls используется LD_PRELOAD + SIGSYS=SIG_IGN.
  - **Важно:** хостовый seccomp может заблокировать сам syscall `seccomp` (SECCOMP_SET_MODE_FILTER). Поэтому SIGSYS-handler устанавливается **до** запуска seccomp-воркера. При `SECCOMP_RET_KILL` сигнал не доставляется вообще — но воркер живёт в fork-потомке, и его смерть родитель обрабатывает fallback'ом (LD_PRELOAD + SIGSYS-handler).

### Перехват (ptrace, legacy)
- `ptrace_intercept.cpp`: логирование stop/exec/exit/clone/fork/vfork, сигналов, syscall openat/read/write/ioctl. Диагностика. Не используется в supervisor-режиме.

### Binder
- Виртуальный эмулятор-заглушка (`binder_emulator.cpp`), без открытия реального `/dev/binder`. Логирование типов транзакций. Полная эмуляция — TODO.

### Графика/аудио
- Заготовки мостов EGL/OpenSL ES (`graphics_bridge.cpp`, `audio_bridge.cpp`) и SurfaceView.

### Обработка ошибок
- Краши (UncaughtExceptionHandler) пишутся в лог UI.
- Остановка неблокирующая (SIGKILL + неблокирующий reap).
- UI корректно обновляет Start/Stop.

## Текущие ограничения / известные проблемы

- **Эмуляция vs блокировка (14:19):** переход с «подменить результат на 0» на «выполнить syscall по-настоящему с переводом путей». Причина: init 13:58 умер не на syscall'е, а на своём же `LOG(FATAL) << "Init encountered errors starting first stage, aborting"` — список `CHECKCALL` (mount/mkdir/mknod/chmod/setgroups) дал не-нули: `mkdir("/dev/pts")` → EEXIST, `mknod("/dev/kmsg")` → EEXIST, `chmod("/proc/cmdline")` → EPERM. Выдуманные stat/statfs тоже вводили init в заблуждение (selinuxfs «считалась» смонтированной).
- **Следующая стена после первой стадии — binder:** второй стадии нужен `/dev/binder` (servicemanager). Настоящий binder хоста трогать нельзя — нужна виртуальная реализация (`binder_emulator.cpp` — заглушка). Ожидаемый порядок: first stage → `execv("/system/bin/init","selinux_setup")` → SELinux → `execv(..."second_stage")` → property service → servicemanager (binder) → ueventd → zygote.
- **Хостовый seccomp (untrusted_app_27):** блокирует `mount` (syscall 40) через `KILL`/`TRAP`. Наш `USER_NOTIF` не может переопределить — приоритет ниже. Решение: LD_PRELOAD (перехват на уровне libc) + SIGSYS-handler (страховка).
- **SIGSYS handler — выполнение syscall:** текущий handler пишет в консоль `SIGSYS caught: syscall N` и возвращает управление (ядро отдаёт -ENOSYS). В будущем: читать `info->si_call_addr` (адрес инструкции), декодировать syscall, выполнять нужный в host-контексте и записывать результат в `x0`.
- **Инициализация системы:** `boot.img`/ramdisk не используется — окружение нужно инициализировать самостоятельно (свойства, сервисы, mounts).
- **Неполный перехват/окружение:** нет подмены путей syscalls, нет виртуализации `/dev/binder`, нет mounts/properties/сервисов AOSP.
- **Ext4-экстрактор:** best-effort; извлечение system.img (~2+ ГБ) ресурсоёмко.
- **Android `init`:** ожидает PID 1, собственные mounts, `/dev`, `/proc`, свойства. Без полной инициализации init падает или зависает.

## История логов (ключевые этапы)

1. **Лог 09:27 (legacy, без stub):** stub не найден → PTRACE_TRACEME/SIGSTOP/PTRACE_CONT → `execve(path)` init успешен (`PTRACE_EVENT_EXEC` event=4) → tracee сразу исчезает (`ESRCH`, `tracee gone`). Ранняя гибель после exec (окружение/линкер/зависимости).

2. **Лог 09:44 (legacy, stub найден):** stub найден в `files/a10stub` (39216 байт), supervisor socketpair создан, fork child (supervisor=1, no ptrace). Stub запустился, seccomp NEW_LISTENER ok, notify_fd передан, supervisor loop start, `getpid` (nr=172) перехвачен и continued. Init упал на линковке: `CANNOT LINK EXECUTABLE "init": library "libbacktrace.so" not found`.

3. **Лог 10:00 (LD_LIBRARY_PATH добавлен):** stub найден (39216 байт), supervisor работает, init линкуется. Краш: `SIGSYS (SYS_SECCOMP), syscall 40 (mount)` → `FirstStageMain` → `mount+8`. Хостовый seccomp убивает `mount`.

4. **Лог 10:05 (текущий):** stub + LD_PRELOAD + SIGSYS handler. Ожидается: mount перехвачен LD_PRELOAD (fake success), SIGSYS handler как страховка. Init должен пройти mount и продолжить инициализацию.

5. **Лог 10:25:** SIGSYS=SIG_IGN перенесён **перед** `try_install_user_notif_probe` (хостовый seccomp убивал процесс при вызове syscall `seccomp` до установки страховки). Supervisor перехватывает **все** syscalls через `SECCOMP_RET_USER_NOTIF` (не только `getpid`) — супервизор логирует каждый. Ожидается: supervisor получит notify_fd, handoff завершится, init продолжит выполнение после mount.

## История логов — консольная эра (pipe → тег `A10_Guest`)

6. **Лог 12:56:** LD_DEBUG=libs убил init мгновенно (у бионического линкера нет категории «libs» — usage и exit). Валидная категория: `dynamic` (только по маркер-файлу `files/enable_ld_debug`). Вывод: **никогда не ставить невалидные значения LD_DEBUG**.
7. **Лог 13:00:** LD_PRELOAD впервые загрузился — `dlopen preload OK: /data/app/~~.../lib/arm64/liba10preload.so` в стабе (useLegacyPackaging). Init после fallback-exec молчал: в env init не было `A10_CONSOLE_FD`.
8. **Лог 13:05 (с A10_CONSOLE_FD в env):** `=== a10stub: exec guest init (fallback) ===` → только безвредные avc «tests» → **init жив, но нем 19.5с** до ручного Stop. Конструктор preload внутри init НЕ отработал (нет строки A10_Preload после exec), Fatal signal нет. Вывод: либо линкер молча не грузит LD_PRELOAD при exec, либо init заблокирован на syscall'е (как seccomp() — блокируется навсегда). Диагностика 13:17: exec-проба + дамп env в консоль.
9. **Лог 13:40 (LD_DEBUG=dynamic):** обе exec-пробы ДОЛИНКОВАЛИ preload (все `finished linking`), затем зависли В КОНСТРУКТОРАХ — ни logcat, ни консоли, ни ok-файла (у потомков проб в env НЕ было A10_CONSOLE_FD — конструктор был слеп; первым действием конструктора был logd — подозреваемый №1). Стратегия «обе пробы HUNG → init БЕЗ LD_PRELOAD» сработала: init слинковал все deps из rootfs (~70мс) и впервые дошёл до FirstStageMain, но умер на первом mount: `Fatal signal 31 (SIGSYS), code 1 (SYS_SECCOMP), syscall 40`, бэктрейс `mount+8` (init 5586, x8=0x28). Выводы: (1) **SIG_IGN НЕ спасает от SECCOMP_RET_TRAP** (force_sig игнорирует SIG_IGN) — выжить может только перехват ДО syscall'а (LD_PRELOAD) или НАСТОЯЩИЙ SIGSYS-handler; (2) preload отвязан от liblog/libc++ (`-nostdlib++`, raw-консольный вывод), конструктор сделан exec-безопасным (raw-сисколлы: ok-файл → консоль, logd убран); (3) ok-файл пробы поллится в цикле ожидания — LOADED фиксируется даже если потомок зависнет позже; (4) A10_CONSOLE_FD добавлен в env потомков проб; (5) LD_DEBUG снова только по маркер-файлу `files/enable_ld_debug`.
10. **Лог 13:58 (ПРОРЫВ):** проба A — `LOADED at exec (probe A)` за ~20мс (ok-файл + маркер в консоли), winner = `nativeLibDir/liba10preload.so`. env init: ANDROID_ROOT/PATH/LD_LIBRARY_PATH/LD_PRELOAD/A10_CONSOLE_FD (без LD_DEBUG). seccomp-воркер: PR_SET_NO_NEW_PRIVS ok → seccomp() nr=277 hang → таймаут 1000мс → fallback (штатно). **init 18422 пережил mount:** конструктор preload отработал уже внутри init (`=== a10preload.so LOADED (constructor) ===`), перехваты `statfs(selinuxfs) x2, mount x7, mkdir x4, setgroups x1` — mount вернул 0, SIGSYS больше нет. Дальше init упал на **SIGABRT** (не SIGSYS!): `abort+156 → libbase.so x2 → init x2 → __libc_init` — это AOSP `LOG(FATAL)` при загрузке SELinux-политики: наш `statfs("/sys/fs/selinux")` вернул SELINUX_MAGIC → init считает selinuxfs смонтированной → `LoadPolicy()` читает `/sys/fs/selinux/policy` → ENOENT → abort. Итог: перехват syscall'ов работает, следующий барьер — SELinux.

11. **Лог 14:36/14:40 (диагностика сообщений гостя):** вся первая стадия прошла чисто (8 `mount`, 4 `mkdir`, 5 `mknod`, `chmod`, `setgroups` — «ok»), но init умирал на SIGABRT **молча**. Причина: сообщения гостя идут `libbase` → её собственный `DT_NEEDED liblog.so` (локальная область библиотеки важнее глобальной — наш preload их не перехватывает) → сокет `/dev/socket/logdw`, которого в гостевом `/dev` нет. Исправления: перехват `__android_log_write/print/vprint`, `__android_log_assert`, `android_set_abort_message` (Android передаёт туда текст FATAL), `abort()`, `write`/`writev` на fd≤3, `dup2` (stdout/stderr гостя остаются на консоли), arm64-алиасы `open64/openat64/stat64/lstat64/fstat64/fstatat64` (иначе `/dev/kmsg` открывался мимо нас).
12. **Лог 14:50 (ПРИЧИНА НАЙДЕНА):** `android_set_abort_message` дал текст: **`Could not open uevent socket`**. init первой стадии создаёт NETLINK_KOBJECT_UEVENT-сокет и `bind()` на группу 1 → на хосте EPERM (нужен CAP_NET_ADMIN) → `LOG(FATAL) → abort`. Исправление: эмуляция netlink — `socket(AF_NETLINK)` помечается, `bind`/`setsockopt` для такого fd = успех, при невозможности создать сокет подставляется unix-socketpair; + симлинк `<rootfs>/dev/socket/logdw` → сокет logd хоста.
13. **Лог 14:55 (ПЕРВАЯ СТАДИЯ ПРОЙДЕНА):** netlink-эмуляция сработала → init прошёл first stage и переexec'нулся (`execv /system/bin/init -> <rootfs>/system/bin/init`), второй процесс пошёл как `/system/bin/init selinux_setup`. Но вторая стадия стартовала **БЕЗ preload**: init делает `clearenv()`, а наш перехват восстанавливал только `LD_LIBRARY_PATH`/`PATH`, но не `LD_PRELOAD` → SELinux грузился без эмуляции → снова FATAL (и текст опять потерялся: маркера конструктора не было). Исправление: `clearenv()` восстанавливает `LD_PRELOAD`, `A10_CONSOLE_FD`, `A10_ROOTFS`, `ANDROID_ROOT`, `LD_LIBRARY_PATH`, `PATH`; selinuxfs открывается настоящим `/sys/fs/selinux/<name>` (чтобы `fstatfs` дал SELINUX_MAGIC и libselinux согласился грузить политику), запись в него — успех.

14. **Лог 15:25 (диагностика политики):** в rootfs полный GSI — `/system/etc/selinux/` содержит `plat_sepolicy.cil` (1.3 МБ), `mapping/{26.0,27.0,28.0,29.0}.cil`, plat_*_contexts; `/product/etc/selinux/` — `product_sepolicy.cil` + sha; `/vendor`, `/odm` — нет (штатно для GSI). Выводы: (1) `plat_sepolicy.cil` — **текстовый CIL** (hex `28726f6c65206f626a6563745f72290a` = `(role object_r).`); (2) secilc падал с `Bad policy version: 29.0` — потому что `-c` это **числовая версия политики** (дефолт гостевого secilc = 31), а не версия mapping'а, и mapping-файл вообще не передавался. Гость дошёл до `[guest FATAL] Unable to load SELinux policy` (его собственная компиляция упала — нет mapping/vendor-файлов). Исправления: secilc зовётся с `-c <число>` + `mapping/<версия>.cil` (перебор 29.0→26.0 и -c 31→28, без -c), готовая бинарная политика ставится на все пути: `/sepolicy`, `/system/etc/selinux/precompiled_sepolicy` и `/vendor/etc/selinux/precompiled_sepolicy` + `precompiled_sepolicy.plat_sepolicy_and_mapping.sha256` (копия системного) → гость находит её через `FindPrecompiledSplitPolicy` и не зовёт secilc сам. Хак `access(plat_sepolicy.cil)→ENOENT` в preload **убран** (он ломал `IsSplitPolicyDevice()`).

15. **Лог 15:34 (политика собрана — load ещё не проходит):** secilc с `-c 31 mapping=29.0` собрал гостевую политику (343241 байт), она ставится на все пути (`/sepolicy`, `/system/etc/selinux/precompiled_sepolicy`, `/vendor/etc/selinux/precompiled_sepolicy` + sha) ✓. Но гость всё равно `[guest FATAL] Unable to load SELinux policy`: libselinux проверяет `is_selinuxfs(fd)` через **fstatfs** — наш эмулированный `/sys/fs/selinux/*` это `/dev/null`, у него `f_type != SELINUX_MAGIC` → libselinux отказывается грузить политику. Исправление: перехват `fstatfs` для отмеченных selinux-fd → отдаём `SELINUX_MAGIC` (0xf97cff8c). Заодно: `install_guest_policy` читает источник целиком в память (иначе первый dst с O_TRUNC обрезал файл, который читается → «политика 0 байт»), а пустые остатки политики удаляются на старте.

## Следующие шаги (после 15:36)

1. **Прогон сборки 15:36 (fstatfs → SELINUX_MAGIC):** Start, ~30 сек, «читай лог». Ожидание: гость грузит гостевую политику → `execv ... second_stage` → property service → servicemanager.
2. **Следующая стена — binder:** второй стадии нужен `/dev/binder` (servicemanager). Настоящий binder хоста использовать нельзя — реализовать виртуальный (`binder_emulator.cpp`). Симлинк `/dev/binder` НЕ создаём намеренно (иначе гость займёт binder телефона!).
3. **ueventd:** реальных uevent-событий нет (наш netlink-сокет пустой) — узлы `/dev/*` создавать нечем; при необходимости — ретрансляция хостовых событий.
4. **Свойства:** init грузит свойства из файлов (в т.ч. `/system/build.prop` — он в rootfs есть) — проверить, что `ro.build.version.sdk` и прочие видны; иначе zygote/system_server не поднимутся.
5. **SIGSYS handler — выполнение syscall:** читать `si_call_addr`, декодировать, выполнять в host-контексте, результат в x0.
6. **Развитие супервизора:** подмена путей (openat/faccessat/statx/…), политика deny/redirect.
7. **Bootstrap/окружение гостя:** инициализация AOSP без `boot.img` (dev/proc/sys, сервисы/init-flow), виртуализация binder.
8. **Диагностика (по желанию):** трассировка линкера — маркер-файл `files/enable_ld_debug` (adb: `adb shell run-as com.android.emulA10 touch files/enable_ld_debug`).
