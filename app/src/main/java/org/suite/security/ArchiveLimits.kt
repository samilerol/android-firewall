package org.suite.security

import java.io.File
import java.io.RandomAccessFile

/** Bound the central directory BEFORE ZipFile allocates its entry index. ZIP64/split APKs are unsupported. */
internal object ArchiveLimits {
    fun check(file: File) {
        RandomAccessFile(file, "r").use { input ->
            require(input.length() in 22..(100L * 1024 * 1024)) { "Invalid APK archive size" }
            val size = minOf(input.length(), 65557).toInt()
            val tail = ByteArray(size)
            input.seek(input.length() - size)
            input.readFully(tail)
            fun u16(i: Int) = (tail[i].toInt() and 255) or ((tail[i + 1].toInt() and 255) shl 8)
            fun u32(i: Int) = u16(i).toLong() or (u16(i + 2).toLong() shl 16)
            val end = (size - 22 downTo 0).firstOrNull {
                u32(it) == 0x06054b50L && it + 22 + u16(it + 20) == size
            } ?: error("Missing ZIP end record")
            require(u16(end + 4) == 0 && u16(end + 6) == 0) { "Split archives are unsupported" }
            val entries = u16(end + 10)
            require(entries in 1..20000 && u16(end + 8) == entries) { "Too many archive entries or unsupported ZIP64" }
            val directorySize = u32(end + 12)
            val directoryOffset = u32(end + 16)
            require(directorySize in 46..(8L * 1024 * 1024)) { "Archive directory exceeds metadata limits" }
            val absoluteEnd = input.length() - size + end
            require(directoryOffset + directorySize == absoluteEnd) { "Invalid or unsupported archive directory bounds" }
            // Do not trust the EOCD count: validate each central record without allocating ZipEntry objects.
            val header = ByteArray(46)
            fun word(i: Int) = (header[i].toInt() and 255) or ((header[i + 1].toInt() and 255) shl 8)
            var position = directoryOffset
            var actual = 0
            while (position < absoluteEnd) {
                require(position + 46 <= absoluteEnd && ++actual <= 20000) { "Invalid or excessive central records" }
                input.seek(position)
                input.readFully(header)
                require(word(0) == 0x4b50 && word(2) == 0x0201) { "Invalid central record" }
                position += 46L + word(28) + word(30) + word(32)
                require(position <= absoluteEnd) { "Truncated central record" }
            }
            require(actual == entries) { "Archive entry count mismatch" }
        }
    }
}
