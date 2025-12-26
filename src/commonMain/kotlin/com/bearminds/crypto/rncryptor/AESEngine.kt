@file:OptIn(DelicateCryptographyApi::class)

package com.bearminds.crypto.rncryptor

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES

/**
 * AES-256-CBC encryption/decryption engine.
 *
 * Wraps cryptography-kotlin's AES implementation with RNCryptor-specific configuration:
 * - Algorithm: AES-256 (determined by 32-byte key)
 * - Mode: CBC (Cipher Block Chaining)
 * - Padding: PKCS7 (same as PKCS5 in Java)
 *
 * Reference: RNCryptor.swift:525-607 (Engine class)
 */
class AESEngine private constructor(
    private val key: ByteArray,
    private val iv: ByteArray,
    private val mode: Mode
) {

    enum class Mode {
        ENCRYPT,
        DECRYPT
    }

    private val provider = CryptographyProvider.Default

    init {
        require(key.size == FormatV3.KEY_SIZE) {
            "AES key must be ${FormatV3.KEY_SIZE} bytes (AES-256), got ${key.size}"
        }
        require(iv.size == FormatV3.IV_SIZE) {
            "IV must be ${FormatV3.IV_SIZE} bytes, got ${iv.size}"
        }
    }

    /**
     * Encrypts plaintext using AES-256-CBC with PKCS7 padding.
     *
     * Reference: RNCryptor.swift:564-583 (update method)
     *
     * @param plaintext Data to encrypt
     * @return Ciphertext (will be longer than plaintext due to padding)
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        check(mode == Mode.ENCRYPT) { "Engine is in decrypt mode" }

        return try {
            // Get AES-CBC algorithm
            val aesCbc = provider.get(AES.CBC)

            // Decode our key (we have raw key bytes)
            val aesKey = aesCbc.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, key)

            // Create cipher and encrypt with IV
            val cipher = aesKey.cipher()
            cipher.encryptWithIvBlocking(iv, plaintext)
        } catch (e: Exception) {
            throw RNCryptorException.CryptoFailure(
                "AES encryption failed", e
            )
        }
    }

    /**
     * Decrypts ciphertext using AES-256-CBC with PKCS7 padding.
     *
     * Reference: RNCryptor.swift:585-606 (finalData method)
     *
     * @param ciphertext Data to decrypt
     * @return Plaintext (will be shorter than ciphertext due to padding removal)
     * @throws RNCryptorException.CryptoFailure if decryption fails (bad padding, etc.)
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        check(mode == Mode.DECRYPT) { "Engine is in encrypt mode" }

        return try {
            // Get AES-CBC algorithm
            val aesCbc = provider.get(AES.CBC)

            // Decode our key (we have raw key bytes)
            val aesKey = aesCbc.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, key)

            // Create cipher and decrypt with IV
            val cipher = aesKey.cipher()
            cipher.decryptWithIvBlocking(iv, ciphertext)
        } catch (e: Exception) {
            // Decryption can fail for many reasons:
            // - Bad padding (wrong password)
            // - Corrupted ciphertext
            // - Wrong key/IV
            throw RNCryptorException.CryptoFailure(
                "AES decryption failed (likely due to wrong password or corrupted data)", e
            )
        }
    }

    companion object {
        /**
         * Creates an encryption engine.
         *
         * Reference: RNCryptor.swift:529-550
         */
        fun forEncryption(key: ByteArray, iv: ByteArray): AESEngine {
            return AESEngine(key, iv, Mode.ENCRYPT)
        }

        /**
         * Creates a decryption engine.
         *
         * Reference: RNCryptor.swift:529-550
         */
        fun forDecryption(key: ByteArray, iv: ByteArray): AESEngine {
            return AESEngine(key, iv, Mode.DECRYPT)
        }
    }
}
