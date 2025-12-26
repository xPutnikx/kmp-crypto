package com.bearminds.crypto.rncryptor

/**
 * RNCryptor public API.
 *
 * Cross-platform password-based encryption compatible with:
 * - RNCryptor 5.x (iOS Swift)
 * - JNCryptor 1.2.0 (Android Java)
 * - All other RNCryptor v3 implementations
 *
 * Reference: RNCryptor.swift:82-226
 */
object RNCryptor {

    /**
     * Current format version.
     *
     * This always points to the latest stable format (currently v3).
     * For version-locked usage, use RNCryptorV3 directly.
     */
    val Version: Byte = FormatV3.VERSION

    /**
     * Encrypts data with a password.
     *
     * Simple one-shot API for encrypting data. For streaming/incremental
     * encryption, use Encryptor class (Phase 2).
     *
     * Example:
     * ```kotlin
     * val plaintext = "Hello, World!".encodeToByteArray()
     * val ciphertext = RNCryptor.encrypt(plaintext, "myPassword")
     * ```
     *
     * Reference: RNCryptor.swift:104-106
     *
     * @param data Data to encrypt
     * @param password Password for encryption
     * @return Encrypted data in RNCryptor v3 format
     */
    fun encrypt(data: ByteArray, password: String): ByteArray {
        return RNCryptorV3.encrypt(data, password)
    }

    /**
     * Decrypts data with a password.
     *
     * Simple one-shot API for decrypting data. For streaming/incremental
     * decryption, use Decryptor class (Phase 2).
     *
     * Example:
     * ```kotlin
     * try {
     *     val plaintext = RNCryptor.decrypt(ciphertext, "myPassword")
     *     println(plaintext.decodeToString())
     * } catch (e: RNCryptorException.HMACMismatch) {
     *     println("Wrong password or corrupted data")
     * }
     * ```
     *
     * Reference: RNCryptor.swift:111-113
     *
     * @param data Encrypted data in RNCryptor v3 format
     * @param password Password used for encryption
     * @return Decrypted plaintext
     * @throws RNCryptorException if decryption fails
     */
    fun decrypt(data: ByteArray, password: String): ByteArray {
        return RNCryptorV3.decrypt(data, password)
    }
}

/**
 * Convenience extension for String encryption.
 */
fun String.encryptRNCryptor(password: String): ByteArray {
    return RNCryptor.encrypt(this.encodeToByteArray(), password)
}

/**
 * Convenience extension for String decryption.
 */
fun ByteArray.decryptRNCryptor(password: String): String {
    val plaintext = RNCryptor.decrypt(this, password)
    return plaintext.decodeToString()
}
