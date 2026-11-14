# A10 (com.android.emulA10) — сводка

Нативный эмулятор AOSP (arm64) поверх хост-системы Android: исполнение на реальном процессоре с перехватом (intercept), без QEMU/KVM.

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
- **LD_PRELOAD (`liba10preload.so`):** перехватывает `mount()`/`umount2()`/`umount()` и десятки других на уровне libc — fake success. БЕЗ зависимостей (DT_NEEDED: libc/libm/libdl, `-nostdlib++`, без liblog): при exec линкер должен грузить ТОЛЬКО preload поверх уже готовой libc — зависимости liblog/libc++_shared при exec подтягивались заново, и в этом окне зависли обе exec-пробы 13:40. Весь вывод — raw write в консоль (env `A10_CONSOLE_FD`), никакого logd.
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

- **Сейчас preload «блокирует», а не эмулирует:** перехваченные syscall'ы возвращают fake-success (0) — это заглушка. Правильный путь — ЭМУЛЯЦИЯ: выполнять syscall в host-контексте с подменой путей гостя и/или подменой данных (например `/sys/fs/selinux/policy`, `/proc`, `/sys`). Первый барьер на этом пути — SELinux: init требует рабочую policy (или корректный признак «selinux выключен» — `ro.boot.selinux=0`, тогда init пропускает LoadPolicy). Варианты: (а) перехватить чтение `build.prop`/свойств и подставить `ro.boot.selinux=0`; (б) эмулировать `selinuxfs` (mount → создать виртуальный каталог + отдавать policy из файла хоста); (в) отключить проверку statfs(SELINUX_MAGIC), чтобы init не считал selinuxfs смонтированной.
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

## Следующие шаги (после 13:40)

1. **Прогон сборки 13:56 (raw-консольный preload, SIGSYS-handler):** Start, ~20 сек, «читай лог». Ожидание в `A10_Guest`: `probe A: constructor LOADED at exec - path WORKS` → `winner: LD_PRELOAD=...` → дамп `[env]` с LD_PRELOAD → seccomp-воркер (hang на seccomp() 1с → fallback, штатно) → в init `=== a10preload.so LOADED (constructor) ===` → `A10_Preload: BLOCKED mount (nr=40) -> 0` на каждом mount → init идёт дальше FirstStageMain.
2. **Если пробы снова HUNG без единого байта** — зависание в линкер-фазе загрузки preload (зависимости уже исключены) → план B: exec гостевого init через гостевой `<rootfs>/system/bin/linker64` (линкер GSI обработает LD_PRELOAD по своим правилам).
3. **Если init прошёл mount:** смотрим `SIGSYS caught: syscall N` — handler ловит все прочие TRAP'ы хоста; каждый N добавляем в перехват preload (mknod/ mkdir/access есть; symlink/unlink/... — по показаниям лога).
4. **SIGSYS handler — выполнение syscall:** читать `si_call_addr`, декодировать, выполнять в host-контексте, результат в x0.
5. **Развитие супервизора:** обработка `exec/clone/fork`, подмена путей (openat/faccessat/statx/…), политика deny/redirect.
6. **Bootstrap/окружение гостя:** инициализация AOSP без `boot.img` (dev/proc/sys через перехват, свойства, сервисы/init-flow), виртуализация binder.
7. **DocumentProvider:** тестирование доступа к rootfs через файловые менеджеры.
8. **Диагностика (по желанию):** трассировка линкера — создать маркер-файл `files/enable_ld_debug` (adb: `adb shell run-as com.android.emulA10 touch files/enable_ld_debug`).
