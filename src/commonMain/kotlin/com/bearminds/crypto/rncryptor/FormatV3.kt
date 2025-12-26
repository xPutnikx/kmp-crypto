@file:OptIn(DelicateCryptographyApi::class)

package com.bearminds.crypto.rncryptor

import dev.whyoleg.cryptography.BinarySize
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.PBKDF2
import dev.whyoleg.cryptography.algorithms.SHA1

/**
 * RNCryptor v3 format specification constants and utilities.
 *
 * Reference: RNCryptor.swift:231-274
 */
object FormatV3 {

    // Format version and structure
    const val VERSION: Byte = 3                    // RNCryptor.swift:269

    // Key and salt sizes
    const val KEY_SIZE = 32                        // kCCKeySizeAES256 (RNCryptor.swift:233)
    const val SALT_SIZE = 8                        // RNCryptor.swift:235

    // Block and digest sizes
    const val IV_SIZE = 16                         // kCCBlockSizeAES128 (RNCryptor.swift:270)
    const val HMAC_SIZE = 32                       // CC_SHA256_DIGEST_LENGTH (RNCryptor.swift:271)

    // Header sizes for different encryption modes
    const val KEY_HEADER_SIZE = 18                 // 1+1+16 (RNCryptor.swift:272)
    const val PASSWORD_HEADER_SIZE = 34            // 1+1+8+8+16 (RNCryptor.swift:273)

    // PBKDF2 parameters
    const val PBKDF2_ITERATIONS = 10000            // RNCryptor.swift:253

    // Options byte values
    const val OPTIONS_PASSWORD_BASED: Byte = 1    // Password-based encryption
    const val OPTIONS_KEY_BASED: Byte = 0         // Key-based encryption

    /**
     * Derives a cryptographic key from a password using PBKDF2.
     *
     * This function implements the exact same key derivation as RNCryptor/JNCryptor:
     * - Algorithm: PBKDF2
     * - PRF: HMAC-SHA1 (⚠️ NOT SHA256! This is intentional for v3 compatibility)
     * - Iterations: 10,000
     * - Output: 32 bytes (256 bits)
     *
     * Reference: RNCryptor.swift:243-267
     *
     * @param password The password string (will be converted to UTF-8 bytes)
     * @param salt The salt (must be SALT_SIZE bytes)
     * @return Derived key (KEY_SIZE bytes)
     * @throws RNCryptorException.CryptoFailure if key derivation fails
     */
    fun deriveKey(password: String, salt: ByteArray): ByteArray {
        require(salt.size == SALT_SIZE) {
            "Salt must be $SALT_SIZE bytes, got ${salt.size}"
        }
        require(password.isNotEmpty()) {
            "Password must not be empty"
        }

        try {
            val provider = CryptographyProvider.Default

            // Get PBKDF2 algorithm
            val pbkdf2 = provider.get(PBKDF2)

            // Derive key using PBKDF2-HMAC-SHA1
            val passwordBytes = password.encodeToByteArray()
            val derivedKey = pbkdf2.secretDerivation(
                digest = SHA1,
                iterations = PBKDF2_ITERATIONS,
                outputSize = KEY_SIZE.bytes,                 // Output in bytes
                salt = salt
            ) .deriveSecretToByteArrayBlocking(passwordBytes)

            require(derivedKey.size == KEY_SIZE) {
                "PBKDF2 output size mismatch: expected $KEY_SIZE, got ${derivedKey.size}"
            }

            return derivedKey

        } catch (e: Exception) {
            throw RNCryptorException.CryptoFailure(
                "PBKDF2 key derivation failed", e
            )
        }
    }

    /**
     * Builds a header for password-based encryption.
     *
     * Format: [VERSION][OPTIONS][encSalt][hmacSalt][iv]
     * Size: 34 bytes
     *
     * Reference: RNCryptor.swift:338-353
     */
    fun buildPasswordHeader(
        encryptionSalt: ByteArray,
        hmacSalt: ByteArray,
        iv: ByteArray
    ): ByteArray {
        require(encryptionSalt.size == SALT_SIZE) { "Invalid encryption salt size" }
        require(hmacSalt.size == SALT_SIZE) { "Invalid HMAC salt size" }
        require(iv.size == IV_SIZE) { "Invalid IV size" }

        return byteArrayOf(VERSION, OPTIONS_PASSWORD_BASED) +
                encryptionSalt +
                hmacSalt +
                iv
    }

    /**
     * Parses a password-based encryption header.
     *
     * @return Triple of (encryptionSalt, hmacSalt, iv)
     * @throws RNCryptorException.UnknownHeader if header is invalid
     * @throws RNCryptorException.InvalidCredentialType if not password-based
     */
    fun parsePasswordHeader(header: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        require(header.size >= PASSWORD_HEADER_SIZE) {
            "Header too short: ${header.size} < $PASSWORD_HEADER_SIZE"
        }

        // Validate version (RNCryptor.swift:483)
        if (header[0] != VERSION) {
            throw RNCryptorException.UnknownHeader
        }

        // Validate credential type (RNCryptor.swift:487)
        if (header[1] != OPTIONS_PASSWORD_BASED) {
            throw RNCryptorException.InvalidCredentialType
        }

        // Extract salts and IV (RNCryptor.swift:491-493)
        val encryptionSalt = header.sliceArray(2..9)        // Offset 2-9 (8 bytes)
        val hmacSalt = header.sliceArray(10..17)            // Offset 10-17 (8 bytes)
        val iv = header.sliceArray(18..33)                  // Offset 18-33 (16 bytes)

        return Triple(encryptionSalt, hmacSalt, iv)
    }
}
