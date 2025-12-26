package com.bearminds.crypto.rncryptor

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import com.bearminds.crypto.rncryptor.internal.constantTimeEquals
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * HMAC-SHA256 engine for message authentication.
 *
 * Implements HMAC (Hash-based Message Authentication Code) using SHA-256.
 * Used in RNCryptor to verify data integrity and authenticate the password.
 *
 * Reference: RNCryptor.swift:646-669 (HMACV3 class)
 */
class HMACEngine(private val key: ByteArray) {

    private val provider = CryptographyProvider.Default

    init {
        require(key.size == FormatV3.KEY_SIZE) {
            "HMAC key must be ${FormatV3.KEY_SIZE} bytes, got ${key.size}"
        }
    }

    /**
     * Computes HMAC-SHA256 of the given data.
     *
     * This is a one-shot operation. For incremental HMAC (needed for streaming),
     * use IncrementalHMACEngine instead.
     *
     * Reference: RNCryptor.swift:664-668
     *
     * @param data Data to authenticate
     * @return HMAC value (32 bytes for SHA-256)
     */
    fun compute(data: ByteArray): ByteArray {
        return try {
            // Get HMAC algorithm
            val hmac = provider.get(HMAC)

            // Decode our key (we have raw key bytes)
            val hmacKey = hmac.keyDecoder(SHA256).decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, key)

            // Generate signature
            val result = hmacKey.signatureGenerator().generateSignatureBlocking(data)

            require(result.size == FormatV3.HMAC_SIZE) {
                "HMAC output size mismatch: expected ${FormatV3.HMAC_SIZE}, got ${result.size}"
            }

            result
        } catch (e: Exception) {
            throw RNCryptorException.CryptoFailure(
                "HMAC computation failed", e
            )
        }
    }

    /**
     * Verifies that the computed HMAC matches the expected HMAC.
     *
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param data Data to verify
     * @param expectedHMAC Expected HMAC value
     * @return true if HMAC matches, false otherwise
     */
    fun verify(data: ByteArray, expectedHMAC: ByteArray): Boolean {
        val computedHMAC = compute(data)
        return constantTimeEquals(computedHMAC, expectedHMAC)
    }
}

/**
 * Incremental HMAC engine for streaming operations.
 *
 * Allows computing HMAC over data that arrives in chunks.
 * Useful for Phase 2 (incremental mode).
 *
 * Reference: RNCryptor.swift:646-669
 */
class IncrementalHMACEngine(private val key: ByteArray) {

    private val provider = CryptographyProvider.Default
    private val buffer = mutableListOf<ByteArray>()

    init {
        require(key.size == FormatV3.KEY_SIZE) {
            "HMAC key must be ${FormatV3.KEY_SIZE} bytes, got ${key.size}"
        }
    }

    /**
     * Updates HMAC with additional data.
     *
     * Reference: RNCryptor.swift:660-662
     */
    fun update(data: ByteArray) {
        buffer.add(data)
    }

    /**
     * Finalizes HMAC computation and returns result.
     *
     * After calling this, the engine is invalidated.
     *
     * Reference: RNCryptor.swift:664-668
     */
    fun finalize(): ByteArray {
        return try {
            val allData = buffer.fold(ByteArray(0)) { acc, chunk -> acc + chunk }

            // Get HMAC algorithm
            val hmac = provider.get(HMAC)

            // Decode our key (we have raw key bytes)
            val hmacKey = hmac.keyDecoder(SHA256).decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, key)

            // Generate signature
            val result = hmacKey.signatureGenerator().generateSignatureBlocking(allData)

            buffer.clear()

            require(result.size == FormatV3.HMAC_SIZE) {
                "HMAC output size mismatch: expected ${FormatV3.HMAC_SIZE}, got ${result.size}"
            }

            result
        } catch (e: Exception) {
            throw RNCryptorException.CryptoFailure(
                "HMAC finalization failed", e
            )
        }
    }
}
