package com.android.emulA10

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipFile

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var clearLogButton: Button
    private lateinit var copyLogButton: Button
    private lateinit var saveLogButton: Button
    private lateinit var surfaceView: EmulatorSurfaceView
    private var isRunning = false
    private val logs = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 32, 16, 16)
        }

        statusText = TextView(this).apply {
            textSize = 14f
            text = "A10 Native Emulator\n\nReady"
        }
        layout.addView(statusText)

        val buttonLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val buttonLayout2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }

        startButton = Button(this).apply {
            text = "Start"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { startEmulator() }
        }
        buttonLayout.addView(startButton)

        stopButton = Button(this).apply {
            text = "Stop"
            isEnabled = false
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { stopEmulator() }
        }
        buttonLayout.addView(stopButton)

        clearLogButton = Button(this).apply {
            text = "Clear"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { clearLog() }
        }
        buttonLayout2.addView(clearLogButton)

        copyLogButton = Button(this).apply {
            text = "Copy"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { copyLog() }
        }
        buttonLayout2.addView(copyLogButton)

        saveLogButton = Button(this).apply {
            text = "Save Log"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { saveLogcat() }
        }
        buttonLayout2.addView(saveLogButton)

        layout.addView(buttonLayout)
        layout.addView(buttonLayout2)

        // Добавляем SurfaceView для отрисовки
        surfaceView = EmulatorSurfaceView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                2f
            )
        }
        layout.addView(surfaceView)

        val scrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        logText = TextView(this).apply {
            textSize = 12f
            text = "Logs will appear here..."
            setTypeface(typeface, android.graphics.Typeface.NORMAL)
        }
        scrollView.addView(logText)
        layout.addView(scrollView)

        setContentView(layout)

        // Проверяем доступ к файлам при запуске
        checkStoragePermission()

        // Устанавливаем обработчик крашей
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            appendLog("❌ CRASH: ${throwable.message}")
            throwable.printStackTrace()
        }
    }

    private fun checkStoragePermission() {
        if (!Environment.isExternalStorageManager()) {
            appendLog("❌ No access to all files. Please grant permission.")
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } else {
            appendLog("✅ Access to all files granted")
        }
    }

    // ==== Авто-переключение кнопок при смерти гостевого init ====
    // Поллер раз в секунду спрашивает loader_guest_alive(); на смерть — Start enabled, Stop disabled.
    private var guestWatchdog: Thread? = null

    private fun startGuestWatchdog() {
        stopGuestWatchdog()
        guestWatchdog = Thread {
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                val alive = try {
                    loaderGuestAlive()
                } catch (t: Throwable) {
                    true // нативная функция недоступна — не трогаем UI
                }
                if (!alive) {
                    runOnUiThread {
                        if (isRunning) {
                            isRunning = false
                            startButton.isEnabled = true
                            stopButton.isEnabled = false
                            statusText.text = "A10 Native Emulator\n\nGuest init exited"
                            surfaceView.stopRendering()
                            appendLog("⛔ Guest init exited — Start enabled, Stop disabled")
                        }
                    }
                    return@Thread
                }
            }
        }.also { it.isDaemon = true; it.start() }
    }

    private fun stopGuestWatchdog() {
        guestWatchdog?.interrupt()
        guestWatchdog = null
    }

    private fun startEmulator() {
        if (isRunning) return
        if (!Environment.isExternalStorageManager()) {
            appendLog("❌ Cannot start without all files access")
            checkStoragePermission()
            return
        }
        lifecycleScope.launch {
            startButton.isEnabled = false
            try {
                val status = initializeEmulator()
                withContext(Dispatchers.Main) {
                    statusText.text = status
                    val ok = status.startsWith("✅")
                    isRunning = ok
                    startButton.isEnabled = !ok
                    stopButton.isEnabled = ok
                    if (ok) {
                        surfaceView.startRendering()
                        startGuestWatchdog()
                    } else {
                        surfaceView.stopRendering()
                    }
                }
            } catch (e: Exception) {
                appendLog("❌ Error: ${e.message}")
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    isRunning = false
                    startButton.isEnabled = true
                    stopButton.isEnabled = false
                    surfaceView.stopRendering()
                }
            }
        }
    }

    private fun stopEmulator() {
        // Разрешаем остановку даже если состояние рассинхронизировалось
        lifecycleScope.launch {
            stopGuestWatchdog()
            stopButton.isEnabled = false
            try {
                withContext(Dispatchers.IO) {
                    loaderShutdown()
                }
                withContext(Dispatchers.Main) {
                    statusText.text = "A10 Native Emulator\n\nStopped"
                    isRunning = false
                    startButton.isEnabled = true
                    stopButton.isEnabled = false
                    surfaceView.stopRendering()
                    appendLog("Emulator stopped")
                }
            } catch (e: Exception) {
                appendLog("❌ Error stopping: ${e.message}")
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    isRunning = false
                    startButton.isEnabled = true
                    stopButton.isEnabled = false
                    surfaceView.stopRendering()
                }
            }
        }
    }

    private fun clearLog() {
        logs.clear()
        logText.text = ""
        appendLog("Log cleared")
    }

    private fun copyLog() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = android.content.ClipData.newPlainText("A10 Logs", logs.toString())
        clipboard.setPrimaryClip(clip)
        appendLog("Log copied to clipboard")
    }

    private fun saveLogcat() {
        if (!Environment.isExternalStorageManager()) {
            appendLog("❌ Cannot save logcat without all files access")
            checkStoragePermission()
            return
        }
        lifecycleScope.launch {
            saveLogButton.isEnabled = false
            appendLog("Saving logcat to /storage/emulated/0/MargyCode/A10/log.txt ...")
            val msg = withContext(Dispatchers.IO) {
                try {
                    val outDir = File("/storage/emulated/0/MargyCode/A10")
                    if (!outDir.exists()) outDir.mkdirs()
                    val outFile = File(outDir, "log.txt")
                    val pkg = packageName
                    val uid = android.os.Process.myUid()

                    fun runProc(cmd: Array<String>): Triple<Int, String, String> {
                        val proc = Runtime.getRuntime().exec(cmd)
                        val stdout = proc.inputStream.bufferedReader().readText()
                        val stderr = proc.errorStream.bufferedReader().readText()
                        val code = proc.waitFor()
                        return Triple(code, stdout, stderr)
                    }
                    fun runShell(script: String): Triple<Int, String, String> {
                        return runProc(arrayOf("sh", "-c", script))
                    }

                    val attempts = mutableListOf<String>()
                    var text = ""
                    var used = ""
                    var lastErr = ""

                    // 1) По пакету: собрать PID'ы пакета (включая дочерние процессы) и снять logcat по ним
                    try {
                        val pidScript = "pidof $pkg 2>/dev/null || (ps -A -o PID,NAME 2>/dev/null | grep ' $pkg' | awk '{print \$1}')"
                        val (_, pidsOut, _) = runShell(pidScript)
                        val pids = pidsOut.split(Regex("\\s+")).map { it.trim() }.filter { it.matches(Regex("\\d+")) }.distinct()
                        if (pids.isNotEmpty()) {
                            val pidArgs = pids.flatMap { listOf("--pid", it) }
                            val cmd = arrayOf("logcat", "-d", "-v", "threadtime") + pidArgs.toTypedArray()
                            val (code, stdout, stderr) = runProc(cmd)
                            attempts.add("by-package[pids=${pids.joinToString(",")}]: exit=$code len=${stdout.length}")
                            if (stdout.isNotBlank()) {
                                text = stdout
                                used = "by package $pkg (pids=${pids.joinToString(",")}, exit=$code)"
                            } else {
                                lastErr = "by-package stderr=${stderr.take(200)}"
                            }
                        } else {
                            attempts.add("by-package: no pids found")
                        }
                    } catch (e: Exception) {
                        attempts.add("by-package error: ${e.message}")
                    }

                    // 2) По UID (часто включает все процессы приложения)
                    if (text.isBlank()) {
                        try {
                            val cmd = arrayOf("logcat", "-d", "-v", "threadtime", "--uid", uid.toString())
                            val (code, stdout, stderr) = runProc(cmd)
                            attempts.add("by-uid[$uid]: exit=$code len=${stdout.length}")
                            if (stdout.isNotBlank()) { text = stdout; used = "by uid $uid (exit=$code)" }
                            else lastErr = "by-uid stderr=${stderr.take(200)}"
                        } catch (e: Exception) { attempts.add("by-uid error: ${e.message}") }
                    }

                    // 3) По тегам проекта (включая дочерние процессы, пишущие под A10_*)
                    if (text.isBlank()) {
                        try {
                            val cmd = arrayOf("logcat", "-d", "-v", "threadtime", "A10_Loader:*", "A10_Ptrace:*", "*:S")
                            val (code, stdout, stderr) = runProc(cmd)
                            attempts.add("by-tags: exit=$code len=${stdout.length}")
                            if (stdout.isNotBlank()) { text = stdout; used = "by tags A10_Loader/A10_Ptrace (exit=$code)" }
                            else lastErr = "by-tags stderr=${stderr.take(200)}"
                        } catch (e: Exception) { attempts.add("by-tags error: ${e.message}") }
                    }

                    // 4) Полный буфер (fallback)
                    if (text.isBlank()) {
                        try {
                            val cmd = arrayOf("logcat", "-d", "-v", "threadtime")
                            val (code, stdout, stderr) = runProc(cmd)
                            attempts.add("full: exit=$code len=${stdout.length}")
                            if (stdout.isNotBlank()) { text = stdout; used = "full logcat (exit=$code)" }
                            else lastErr = "full stderr=${stderr.take(200)}"
                        } catch (e: Exception) { attempts.add("full error: ${e.message}") }
                    }

                    if (text.isBlank()) {
                        "❌ Failed to read logcat: $lastErr\nAttempts: ${attempts.joinToString(" | ")}"
                    } else {
                        outFile.writeText(text)
                        try { Runtime.getRuntime().exec(arrayOf("logcat", "-c")).waitFor() } catch (_: Exception) {}
                        "✅ Logcat saved: ${outFile.absolutePath} (${text.length} chars)\nSource: $used\nPackage: $pkg\nAttempts: ${attempts.joinToString(" | ")}\n(logcat buffer cleared)"
                    }
                } catch (e: Exception) {
                    "❌ Save logcat error: ${e.message}"
                }
            }
            appendLog(msg)
            saveLogButton.isEnabled = true
        }
    }

    private fun chmodRecursive(file: File) {
        try {
            if (file.isDirectory) {
                file.setExecutable(true, false)
                file.setReadable(true, false)
                file.setWritable(true, true)
                file.listFiles()?.forEach { chmodRecursive(it) }
            } else {
                file.setExecutable(true, false)
                file.setReadable(true, false)
                file.setWritable(true, true)
            }
        } catch (e: Exception) {
            appendLog("chmod warn: ${file.path}: ${e.message}")
        }
    }

    private fun appendLog(message: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            logs.append(message).append("\n")
            logText.text = logs.toString()
        }
    }

    private suspend fun initializeEmulator(): String = withContext(Dispatchers.IO) {
        appendLog("Starting A10 Emulator...")
        val aospPath = "/storage/emulated/0/Download/gsi_gms_arm64-exp-QJR1.191112.001-6004257.zip"
        val rootfsDir = "/data/data/com.android.emulA10/files/aosp"
        appendLog("Config: aospPath=$aospPath")
        appendLog("Config: rootfsDir=$rootfsDir")
        appendLog("Config: externalStorageManager=${Environment.isExternalStorageManager()}")
        appendLog("Config: filesDir=${filesDir.absolutePath}")

        // Копируем bootstrap-stub executable (a10stub) из assets в filesDir, если есть.
        val stubDst = File(filesDir, "a10stub")
        try {
            val stubIn = assets.open("a10stub")
            stubIn.use { input ->
                FileOutputStream(stubDst).use { output ->
                    input.copyTo(output)
                }
            }
            stubDst.setExecutable(true, false)
            appendLog("stub copied from assets to ${stubDst.absolutePath} (${stubDst.length()} bytes)")
        } catch (e: Exception) {
            appendLog("stub copy from assets failed: ${e.message} (legacy mode)")
        }

        // Копия preload из assets убрана: единственный источник — nativeLibDir APK
        // (useLegacyPackaging=true распаковывает lib/arm64-v8a/liba10preload.so).

        appendLog("Unpacking AOSP image...")
        val unpackOk = unpackAosp(aospPath, rootfsDir)
        if (!unpackOk) {
            appendLog("❌ Failed to unpack AOSP")
            return@withContext "❌ Failed to unpack AOSP"
        }
        appendLog("✅ AOSP unpacked to $rootfsDir")

        appendLog("Initializing loader...")
        val nativeLibDir = applicationInfo.nativeLibraryDir ?: ""
        appendLog("Config: nativeLibDir=$nativeLibDir")

        // LD_PRELOAD берётся только из nativeLibDir (см. loader/stub) — property больше не нужен.

        val loaderOk = try {
            loaderInitWithNativeDir(rootfsDir, nativeLibDir)
        } catch (e: UnsatisfiedLinkError) {
            appendLog("loaderInitWithNativeDir unavailable, fallback: ${e.message}")
            loaderInit(rootfsDir)
        }
        appendLog("loaderInit result=$loaderOk")
        if (!loaderOk) {
            appendLog("❌ Loader init failed")
            return@withContext "❌ Loader init failed"
        }
        appendLog("✅ Loader initialized")

        // Копия preload в rootfs lib64 (совет: путь внутри LD_LIBRARY_PATH гостя).
        // Стаб тестирует её exec-пробой B и, если она грузится при exec, выбирает
        // её как LD_PRELOAD для init.
        try {
            val preloadSrc = File(nativeLibDir, "liba10preload.so")
            if (preloadSrc.exists()) {
                val lib64 = File(rootfsDir, "lib64")
                lib64.mkdirs()
                val preloadDstRoot = File(lib64, "liba10preload.so")
                preloadSrc.copyTo(preloadDstRoot, overwrite = true)
                preloadDstRoot.setReadable(true, false)
                preloadDstRoot.setExecutable(true, false)
                appendLog("preload copied to rootfs lib64: ${preloadDstRoot.absolutePath} (${preloadDstRoot.length()} bytes)")
            } else {
                appendLog("⚠️ preload not found in nativeLibDir, rootfs copy skipped")
            }
        } catch (e: Exception) {
            appendLog("preload copy to rootfs lib64 failed: ${e.message}")
        }

        appendLog("Starting init process...")
        val initPid = loaderStartInit()
        val lastErr = try { loaderLastError() } catch (e: Exception) { e.message ?: "unknown" }
        appendLog("loaderStartInit pid=$initPid lastError=$lastErr")
        if (initPid <= 0) {
            appendLog("❌ Failed to start init process: $lastErr")
            return@withContext "❌ Failed to start init process: $lastErr"
        }
        appendLog("✅ Init process started (PID: $initPid)")

        val status = loaderStatus()
        appendLog("Status: $status")
        return@withContext "✅ A10 Emulator Running\n\n$status\n\nInit PID: $initPid"
    }

    private fun unpackAosp(zipPath: String, destDir: String): Boolean {
        return try {
            appendLog("unpackAosp: zipPath=$zipPath destDir=$destDir")
            val zip = File(zipPath)
            appendLog("unpackAosp: zip exists=${zip.exists()} size=${if (zip.exists()) zip.length() else -1} canRead=${zip.canRead()}")
            if (!zip.exists()) {
                appendLog("❌ ZIP not found: $zipPath")
                return false
            }
            val dest = File(destDir)
            if (!dest.exists()) appendLog("unpackAosp: creating destDir=${dest.mkdirs()}")
            else appendLog("unpackAosp: destDir exists, files=${dest.listFiles()?.size ?: -1}")

            // Если уже есть извлечённая система (init/system), пропускаем
            val initFile = File(dest, "init")
            val systemDir = File(dest, "system")
            appendLog("unpackAosp: initExists=${initFile.exists()} systemDirExists=${systemDir.exists()}")
            if (initFile.exists() || (systemDir.exists() && systemDir.isDirectory)) {
                appendLog("✅ AOSP already extracted, skipping")
                return true
            }

            val zipFile = ZipFile(zipPath)
            appendLog("unpackAosp: zip entries=${zipFile.size()}")
            val entries = zipFile.entries()
            var count = 0
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val outFile = File(dest, entry.name)
                if (count < 20 || count % 500 == 0) {
                    appendLog("unpackAosp: entry[$count]=${entry.name} dir=${entry.isDirectory} size=${entry.size}")
                }
                if (entry.isDirectory) {
                    outFile.mkdirs()
                } else {
                    outFile.parentFile?.mkdirs()
                    zipFile.getInputStream(entry).use { input ->
                        outFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    count++
                }
            }
            zipFile.close()
            appendLog("Unpacked $count files from ZIP")

            // GSI zip обычно содержит system.img/vbmeta.img (sparse ext4) и иногда boot.img
            val bootImg = File(dest, "boot.img")
            val vbmetaImg = File(dest, "vbmeta.img")
            if (bootImg.exists()) {
                appendLog("Found boot.img (${bootImg.length()} bytes). Извлечение ramdisk/init пока не реализовано — см. AGENTS.md.")
            } else {
                appendLog("boot.img не найден в распакованном архиве (ожидаемо для некоторых GSI). /init может отсутствовать без ramdisk.")
            }
            if (vbmetaImg.exists()) {
                appendLog("Found vbmeta.img (${vbmetaImg.length()} bytes)")
            }

            val systemImg = File(dest, "system.img")
            if (systemImg.exists()) {
                appendLog("Found system.img (${systemImg.length()} bytes). Извлечение внутри приложения (sparse->raw, ext4)...")
                val res = nativeExtractSystem(systemImg.absolutePath, dest.absolutePath)
                if (res == "ok") {
                    appendLog("✅ system.img extracted")
                    chmodRecursive(dest)
                } else {
                    appendLog("❌ Extract failed: $res")
                    return false
                }
            } else {
                appendLog("system.img не найден после распаковки ZIP")
            }
            true
        } catch (e: Exception) {
            appendLog("❌ Unpack error: ${e.message}")
            e.printStackTrace()
            false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        loaderShutdown()
    }

    external fun nativeHello(): String
    external fun loaderInit(rootfsDir: String): Boolean
    external fun loaderInitWithNativeDir(rootfsDir: String, nativeLibDir: String): Boolean
    external fun loaderStartInit(): Int
    external fun loaderGuestAlive(): Boolean
    external fun loaderStatus(): String
    external fun loaderShutdown()
    external fun nativeLog(message: String)
    external fun loaderLastError(): String
    external fun nativeExtractSystem(systemImgPath: String, outDir: String): String

    companion object {
        init { System.loadLibrary("native-lib") }
    }
}