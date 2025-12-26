package com.bearminds.crypto.rncryptor

/**
 * Test vectors for RNCryptor compatibility testing.
 * Based on official RNCryptor test vectors from: https://github.com/RNCryptor/RNCryptor-Spec
 */

/**
 * KDF (Key Derivation Function) test vector.
 * Tests PBKDF2 key derivation.
 */
data class KDFTestVector(
    val title: String,
    val version: Int,
    val password: String,
    val salt: ByteArray,
    val expectedKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KDFTestVector

        if (title != other.title) return false
        if (version != other.version) return false
        if (password != other.password) return false
        if (!salt.contentEquals(other.salt)) return false
        if (!expectedKey.contentEquals(other.expectedKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = title.hashCode()
        result = 31 * result + version
        result = 31 * result + password.hashCode()
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + expectedKey.contentHashCode()
        return result
    }
}

/**
 * Password-based encryption test vector.
 * Tests full encrypt/decrypt flow with password.
 */
data class PasswordTestVector(
    val title: String,
    val version: Int,
    val password: String,
    val encryptionSalt: ByteArray,
    val hmacSalt: ByteArray,
    val iv: ByteArray,
    val plaintext: ByteArray,
    val expectedCiphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PasswordTestVector

        if (title != other.title) return false
        if (version != other.version) return false
        if (password != other.password) return false
        if (!encryptionSalt.contentEquals(other.encryptionSalt)) return false
        if (!hmacSalt.contentEquals(other.hmacSalt)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!plaintext.contentEquals(other.plaintext)) return false
        if (!expectedCiphertext.contentEquals(other.expectedCiphertext)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = title.hashCode()
        result = 31 * result + version
        result = 31 * result + password.hashCode()
        result = 31 * result + encryptionSalt.contentHashCode()
        result = 31 * result + hmacSalt.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + plaintext.contentHashCode()
        result = 31 * result + expectedCiphertext.contentHashCode()
        return result
    }
}

/**
 * Parses hex string to byte array.
 * Handles spaces in hex string.
 */
fun String.hexToByteArray(): ByteArray {
    val hex = this.replace(" ", "")
    if (hex.isEmpty()) return ByteArray(0)

    return ByteArray(hex.length / 2) { i ->
        ((hex[i * 2].digitToInt(16) shl 4) or hex[i * 2 + 1].digitToInt(16)).toByte()
    }
}

/**
 * Parses test vector files in RNCryptor format.
 */
object TestVectorParser {

    /**
     * Reads a test vector file from resources.
     */
    private fun readResourceFile(resourcePath: String): List<String> {
        // Use TestVectorParser class reference instead of javaClass for cross-platform compatibility
        val content = TestVectorParser::class.java.getResourceAsStream(resourcePath)
            ?.bufferedReader()
            ?.readText()
            ?: throw IllegalArgumentException("Resource not found: $resourcePath")

        return content.lines()
    }

    /**
     * Reads next non-comment, non-empty line.
     */
    private fun readNextLine(iterator: Iterator<String>): String? {
        while (iterator.hasNext()) {
            val line = iterator.next().trim()
            if (line.isNotEmpty() && !line.startsWith("#")) {
                return line
            }
        }
        return null
    }

    /**
     * Reads next field value.
     * Format: "field_name: value"
     */
    private fun readNextField(iterator: Iterator<String>, expectedField: String, required: Boolean = true): String? {
        val line = readNextLine(iterator)
        if (line == null) {
            if (required) {
                throw IllegalStateException("Expected field '$expectedField' but reached end of file")
            }
            return null
        }

        val colonIndex = line.indexOf(':')
        if (colonIndex == -1) {
            throw IllegalStateException("Invalid line format (no colon): $line")
        }

        val field = line.substring(0, colonIndex).trim()
        val value = line.substring(colonIndex + 1).trim()

        if (field != expectedField) {
            throw IllegalStateException("Expected field '$expectedField' but got '$field'")
        }

        return value
    }

    /**
     * Parses KDF test vectors from kdf-v3 file.
     */
    fun parseKDFVectors(): List<KDFTestVector> {
        val lines = readResourceFile("/kdf-v3")
        val iterator = lines.iterator()
        val vectors = mutableListOf<KDFTestVector>()

        while (true) {
            val title = readNextField(iterator, "title", required = false) ?: break
            val version = readNextField(iterator, "version")!!.toInt()
            val password = readNextField(iterator, "password")!!
            val salt = readNextField(iterator, "salt_hex")!!.hexToByteArray()
            val key = readNextField(iterator, "key_hex")!!.hexToByteArray()

            vectors.add(KDFTestVector(title, version, password, salt, key))
        }

        return vectors
    }

    /**
     * Parses password-based encryption test vectors from password-v3 file.
     */
    fun parsePasswordVectors(): List<PasswordTestVector> {
        val lines = readResourceFile("/password-v3")
        val iterator = lines.iterator()
        val vectors = mutableListOf<PasswordTestVector>()

        while (true) {
            val title = readNextField(iterator, "title", required = false) ?: break
            val version = readNextField(iterator, "version")!!.toInt()
            val password = readNextField(iterator, "password")!!
            val encSalt = readNextField(iterator, "enc_salt_hex")!!.hexToByteArray()
            val hmacSalt = readNextField(iterator, "hmac_salt_hex")!!.hexToByteArray()
            val iv = readNextField(iterator, "iv_hex")!!.hexToByteArray()
            val plaintext = readNextField(iterator, "plaintext_hex")!!.hexToByteArray()
            val ciphertext = readNextField(iterator, "ciphertext_hex")!!.hexToByteArray()

            vectors.add(PasswordTestVector(
                title, version, password, encSalt, hmacSalt, iv, plaintext, ciphertext
            ))
        }

        return vectors
    }
}
