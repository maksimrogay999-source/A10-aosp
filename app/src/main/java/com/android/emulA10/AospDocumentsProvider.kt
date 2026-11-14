package com.android.emulA10

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsProvider
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

/**
 * Провайдер документов, дающий доступ к rootfs AOSP через Storage Access Framework.
 * Корневой каталог: files/aosp (rootfs гостя).
 *
 * ВАЖНО: провайдер ОБЯЗАН быть защищён android.permission.MANAGE_DOCUMENTS —
 * этого требует DocumentsProvider.attachInfo (иначе SecurityException на старте
 * приложения). Разрешение signature-уровня: им владеет системный DocumentsUI («Файлы»),
 * поэтому корень виден именно там.
 */
class AospDocumentsProvider : DocumentsProvider() {

    companion object {
        const val AUTHORITY = "com.android.emulA10.documents"
        const val ROOT_DIR = "aosp"

        private fun getRootFile(context: Context): File =
            File(context.filesDir, "aosp")

        /** Расширения, которые удобно открывать текстовым редактором (политика SELinux — .cil). */
        private val TEXT_EXT = setOf(
            "cil", "txt", "prop", "rc", "conf", "cfg", "ini", "xml", "json",
            "sh", "te", "cil", "contexts", "list", "log"
        )
    }

    override fun onCreate(): Boolean = true

    override fun queryRoots(projection: Array<String>?): Cursor {
        val result = MatrixCursor(arrayOf(
            DocumentsContract.Root.COLUMN_ROOT_ID,
            DocumentsContract.Root.COLUMN_DOCUMENT_ID,
            "title",
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.COLUMN_ICON
        ))

        val context = context ?: return result
        val rootFile = getRootFile(context)
        if (!rootFile.exists()) return result

        val flags = DocumentsContract.Root.FLAG_SUPPORTS_CREATE or
                DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD

        result.newRow().apply {
            add(DocumentsContract.Root.COLUMN_ROOT_ID, ROOT_DIR)
            add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, ROOT_DIR)
            add("title", "A10 Rootfs")
            add(DocumentsContract.Root.COLUMN_FLAGS, flags)
            add(DocumentsContract.Root.COLUMN_ICON, android.R.drawable.ic_menu_manage)
        }
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<String>?): Cursor {
        val context = context ?: throw FileNotFoundException("No context")
        val file = getFileForDocId(context, documentId)
        if (!file.exists()) throw FileNotFoundException("Not found: $documentId")

        val result = MatrixCursor(arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
            Document.COLUMN_FLAGS,
            Document.COLUMN_LAST_MODIFIED
        ))

        result.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, documentId)
            add(Document.COLUMN_DISPLAY_NAME, file.name)
            add(Document.COLUMN_MIME_TYPE, getMimeType(file))
            add(Document.COLUMN_SIZE, if (file.isFile) file.length() else 0L)
            add(Document.COLUMN_FLAGS, flagsFor(file))
            add(Document.COLUMN_LAST_MODIFIED, file.lastModified())
        }
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<String>?,
        sortOrder: String?
    ): Cursor {
        val context = context ?: throw FileNotFoundException("No context")
        val parentFile = getFileForDocId(context, parentDocumentId)
        if (!parentFile.exists() || !parentFile.isDirectory)
            throw FileNotFoundException("Not a directory: $parentDocumentId")

        val result = MatrixCursor(arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
            Document.COLUMN_FLAGS,
            Document.COLUMN_LAST_MODIFIED
        ))

        val files = parentFile.listFiles()?.sortedWith(
            compareBy<File>({ !it.isDirectory }, { it.name.lowercase() })
        ) ?: emptyList()
        for (file in files) {
            val docId = getDocIdForFile(context, file)
            result.newRow().apply {
                add(Document.COLUMN_DOCUMENT_ID, docId)
                add(Document.COLUMN_DISPLAY_NAME, file.name)
                add(Document.COLUMN_MIME_TYPE, getMimeType(file))
                add(Document.COLUMN_SIZE, if (file.isFile) file.length() else 0L)
                add(Document.COLUMN_FLAGS, flagsFor(file))
                add(Document.COLUMN_LAST_MODIFIED, file.lastModified())
            }
        }
        return result
    }

    /** Обязательно для флагa FLAG_SUPPORTS_IS_CHILD, иначе часть менеджеров не листает вложенные папки. */
    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        val context = context ?: return false
        val parent = getFileForDocId(context, parentDocumentId).canonicalFile
        val child = getFileForDocId(context, documentId).canonicalFile
        return child.path.startsWith(parent.path + File.separator)
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val context = context ?: throw FileNotFoundException("No context")
        val file = getFileForDocId(context, documentId)
        if (!file.exists()) throw FileNotFoundException("Not found: $documentId")
        val accessMode = ParcelFileDescriptor.parseMode(mode)
        return ParcelFileDescriptor.open(file, accessMode)
    }

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String
    ): String {
        val context = context ?: throw FileNotFoundException("No context")
        val parentFile = getFileForDocId(context, parentDocumentId)
        if (!parentFile.exists() || !parentFile.isDirectory)
            throw FileNotFoundException("Not a directory: $parentDocumentId")

        val file = File(parentFile, displayName)
        if (!file.createNewFile())
            throw IOException("Failed to create: $displayName")
        return getDocIdForFile(context, file)
    }

    override fun deleteDocument(documentId: String) {
        val context = context ?: throw FileNotFoundException("No context")
        val file = getFileForDocId(context, documentId)
        if (!file.exists()) throw FileNotFoundException("Not found: $documentId")
        if (file.isDirectory) {
            if (!file.deleteRecursively()) throw IOException("Failed to delete dir: $documentId")
        } else if (!file.delete()) {
            throw IOException("Failed to delete: $documentId")
        }
    }

    override fun renameDocument(documentId: String, displayName: String): String? {
        val context = context ?: throw FileNotFoundException("No context")
        val file = getFileForDocId(context, documentId)
        if (!file.exists()) throw FileNotFoundException("Not found: $documentId")
        val newFile = File(file.parentFile, displayName)
        if (!file.renameTo(newFile)) throw IOException("Failed to rename")
        return getDocIdForFile(context, newFile)
    }

    private fun flagsFor(file: File): Int = if (file.isDirectory) {
        Document.FLAG_DIR_SUPPORTS_CREATE or
                Document.FLAG_SUPPORTS_DELETE or
                Document.FLAG_SUPPORTS_REMOVE
    } else {
        Document.FLAG_SUPPORTS_WRITE or
                Document.FLAG_SUPPORTS_DELETE or
                Document.FLAG_SUPPORTS_REMOVE
    }

    private fun getDocIdForFile(context: Context, file: File): String {
        val rootFile = getRootFile(context)
        val relativePath = file.relativeTo(rootFile).path
        return "$ROOT_DIR/$relativePath"
    }

    private fun getFileForDocId(context: Context, docId: String): File {
        val rootFile = getRootFile(context)
        if (docId == ROOT_DIR) return rootFile
        var rel = docId
        if (rel.startsWith("$ROOT_DIR/")) rel = rel.removePrefix("$ROOT_DIR/")
        // Защита от выхода за пределы rootfs.
        val file = File(rootFile, rel)
        val rootPath = rootFile.canonicalPath
        val filePath = file.canonicalPath
        if (filePath != rootPath && !filePath.startsWith(rootPath + File.separator)) {
            throw FileNotFoundException("Outside root: $docId")
        }
        return file
    }

    private fun getMimeType(file: File): String {
        if (file.isDirectory) return Document.MIME_TYPE_DIR
        val ext = file.name.substringAfterLast('.', "").lowercase()
        return when {
            ext in TEXT_EXT -> "text/plain"
            ext == "img" -> "application/octet-stream"
            ext == "so" -> "application/x-sharedlib"
            ext == "apk" -> "application/vnd.android.package-archive"
            ext == "cil" -> "text/plain"
            else -> "application/octet-stream"
        }
    }
}
