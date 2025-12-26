package com.bearminds.crypto.rncryptor

import dev.whyoleg.cryptography.random.CryptographyRandom

/**
 * Secure random number generation for cryptographic use.
 *
 * Wraps cryptography-kotlin's secure random implementation, which uses:
 * - iOS: SecRandomCopyBytes
 * - Android: SecureRandom
 * - JVM: SecureRandom
 *
 * Reference: RNCryptor.swift:117-124
 */
object SecureRandom {

    private val random = CryptographyRandom

    /**
     * Generates cryptographically secure random bytes.
     *
     * @param length Number of bytes to generate
     * @return ByteArray of random bytes
     * @throws RNCryptorException.CryptoFailure if RNG fails (should never happen)
     */
    fun nextBytes(length: Int): ByteArray {
        require(length > 0) { "Length must be positive, got $length" }

        return try {
            random.nextBytes(length)
        } catch (e: Exception) {
            throw RNCryptorException.CryptoFailure(
                "Secure random number generation failed", e
            )
        }
    }

    /**
     * Generates a random salt for PBKDF2.
     */
    fun nextSalt(): ByteArray = nextBytes(FormatV3.SALT_SIZE)

    /**
     * Generates a random IV for AES-CBC.
     */
    fun nextIV(): ByteArray = nextBytes(FormatV3.IV_SIZE)
}
