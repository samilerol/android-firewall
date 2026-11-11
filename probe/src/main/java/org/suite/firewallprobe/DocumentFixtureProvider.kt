package org.suite.firewallprobe

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.os.Handler
import android.os.Looper
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Signature-restricted local document fixture; this module never ships in the firewall. */
class DocumentFixtureProvider : ContentProvider() {
    private val writers = AtomicInteger()
    override fun onCreate() = true
    override fun getType(uri: Uri) = "application/vnd.android.package-archive"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        require(uri.path == "/status")
        return MatrixCursor(arrayOf("active")).apply { addRow(arrayOf(writers.get())) }
    }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r" || uri.path !in setOf("/apk", "/slow-apk")) throw FileNotFoundException("Unknown read-only fixture")
        val file = File(requireNotNull(context).applicationInfo.sourceDir)
        if (uri.path == "/apk") return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
        if (writers.incrementAndGet() > 2) { writers.decrementAndGet(); throw FileNotFoundException("Fixture busy") }
        val pipe = try { ParcelFileDescriptor.createPipe() } catch (e: Exception) { writers.decrementAndGet(); throw e }
        val handler = Handler(Looper.getMainLooper())
        val expire = Runnable { runCatching { pipe[1].close() } }
        handler.postDelayed(expire, 30000)
        thread(name = "document-fixture") {
            try {
                ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { output ->
                    file.inputStream().use { input ->
                        val buffer = ByteArray(16384)
                        val deadline = System.nanoTime() + 30_000_000_000L
                        while (System.nanoTime() < deadline) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            output.write(buffer, 0, count)
                            Thread.sleep(50)
                        }
                    }
                }
            } catch (_: Exception) { /* Reader cancellation closes the pipe. */ }
            finally { handler.removeCallbacks(expire); writers.decrementAndGet() }
        }
        return pipe[0]
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri = throw UnsupportedOperationException("Read only")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = throw UnsupportedOperationException("Read only")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = throw UnsupportedOperationException("Read only")
}
