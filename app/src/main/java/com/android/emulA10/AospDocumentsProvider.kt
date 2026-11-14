package com.android.emulA10

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Point
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
 * Корневой каталог: files/aosp (rootfs).
 * Позволяет просматривать/открывать файлы гостя через системные файловые менеджеры.
 */
class AospDocumentsProvider : DocumentsProvider() {

    companion object {
        const val AUTHORITY = "com.android.emulA10.documents"
        const val ROOT_DIR = "aosp"

        private fun getRootFile(context: Context): File =
            File(context.filesDir, "aosp")
    }

    override fun onCreate(): Boolean = true

    override fun queryRoots(
        projection: Array<String>?
    ): Cursor {
        val result = MatrixCursor(arrayOf(
            DocumentsContract.Root.COLUMN_ROOT_ID,
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

        val flags = if (file.isDirectory) {
            Document.FLAG_DIR_SUPPORTS_CREATE or Document.FLAG_SUPPORTS_REMOVE
        } else {
            Document.FLAG_SUPPORTS_WRITE or Document.FLAG_SUPPORTS_REMOVE
        }

        result.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, documentId)
            add(Document.COLUMN_DISPLAY_NAME, file.name)
            add(Document.COLUMN_MIME_TYPE, getMimeType(file))
            add(Document.COLUMN_SIZE, if (file.isFile) file.length() else 0L)
            add(Document.COLUMN_FLAGS, flags)
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

        val files = parentFile.listFiles()?.sortedBy { it.isFile } ?: emptyList()
        for (file in files) {
            val docId = getDocIdForFile(context, file)
            val flags = if (file.isDirectory) {
                Document.FLAG_DIR_SUPPORTS_CREATE or Document.FLAG_SUPPORTS_REMOVE
            } else {
                Document.FLAG_SUPPORTS_WRITE or Document.FLAG_SUPPORTS_REMOVE
            }
            result.newRow().apply {
                add(Document.COLUMN_DOCUMENT_ID, docId)
                add(Document.COLUMN_DISPLAY_NAME, file.name)
                add(Document.COLUMN_MIME_TYPE, getMimeType(file))
                add(Document.COLUMN_SIZE, if (file.isFile) file.length() else 0L)
                add(Document.COLUMN_FLAGS, flags)
                add(Document.COLUMN_LAST_MODIFIED, file.lastModified())
            }
        }
        return result
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
        if (!file.delete()) throw IOException("Failed to delete: $documentId")
    }

    override fun renameDocument(documentId: String, displayName: String): String? {
        val context = context ?: throw FileNotFoundException("No context")
        val file = getFileForDocId(context, documentId)
        if (!file.exists()) throw FileNotFoundException("Not found: $documentId")
        val newFile = File(file.parentFile, displayName)
        if (!file.renameTo(newFile)) throw IOException("Failed to rename")
        return getDocIdForFile(context, newFile)
    }

    private fun getDocIdForFile(context: Context, file: File): String {
        val rootFile = getRootFile(context)
        val relativePath = file.relativeTo(rootFile).path
        return "$ROOT_DIR/$relativePath"
    }

    private fun getFileForDocId(context: Context, docId: String): File {
        val rootFile = getRootFile(context)
        return if (docId == ROOT_DIR) rootFile
        else File(rootFile, docId.removePrefix("$ROOT_DIR/"))
    }

    private fun getMimeType(file: File): String {
        return when {
            file.isDirectory -> Document.MIME_TYPE_DIR
            file.name.endsWith(".img") -> "application/octet-stream"
            file.name.endsWith(".so") -> "application/x-sharedlib"
            file.name.endsWith(".apk") -> "application/vnd.android.package-archive"
            else -> "application/octet-stream"
        }
    }
}