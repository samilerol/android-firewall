package org.suite.security

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArchiveLimitsTest {
    private fun archive(): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }
        return output.toByteArray()
    }
    private fun withFile(bytes: ByteArray, action: (File) -> Unit) {
        val file = File.createTempFile("archive-test-", ".zip")
        try { file.writeBytes(bytes); action(file) } finally { file.delete() }
    }
    private fun reject(bytes: ByteArray) = withFile(bytes) { file ->
        try { ArchiveLimits.check(file); fail("Unsafe archive accepted") } catch (_: IllegalArgumentException) { }
        catch (_: IllegalStateException) { }
    }
    @Test fun normalArchiveAndCommentAreAccepted() {
        withFile(archive()) { ArchiveLimits.check(it) }
        val data = archive().toMutableList()
        data[data.size - 2] = 3
        data.addAll(listOf(65.toByte(), 66.toByte(), 67.toByte()))
        withFile(data.toByteArray()) { ArchiveLimits.check(it) }
    }
    @Test fun excessiveEntryCountIsRejectedBeforeOpeningZipFile() {
        val bytes = archive()
        val end = bytes.size - 22
        bytes[end + 8] = 0xff.toByte(); bytes[end + 9] = 0xff.toByte()
        bytes[end + 10] = 0xff.toByte(); bytes[end + 11] = 0xff.toByte()
        reject(bytes)
    }
    @Test fun oversizedDirectoryAndInvalidOffsetsAreRejected() {
        val bytes = archive()
        bytes[bytes.size - 22 + 15] = 1 // directory size > 8 MiB
        reject(bytes)
        val offset = archive()
        offset[offset.size - 22 + 16] = 0
        reject(offset)
    }
    @Test fun forgedCountAndDirectoryRecordAreRejected() {
        val count = archive()
        count[count.size - 22 + 8] = 2; count[count.size - 22 + 10] = 2
        reject(count)
        val header = archive()
        val central = header.indices.first { i -> i + 3 < header.size && header[i] == 0x50.toByte() && header[i + 1] == 0x4b.toByte() && header[i + 2] == 1.toByte() && header[i + 3] == 2.toByte() }
        header[central + 28] = 0xff.toByte(); header[central + 29] = 0xff.toByte()
        reject(header)
    }
    @Test fun truncatedSplitAndNonArchiveInputsAreRejected() {
        reject(byteArrayOf(1))
        reject(archive().dropLast(1).toByteArray())
        val split = archive()
        split[split.size - 22 + 4] = 1
        reject(split)
        reject(ByteArray(100))
    }
}
