package com.bearminds.crypto.rncryptor

/**
 * Base class for all RNCryptor-related exceptions.
 *
 * Reference: RNCryptor.swift:84-101
 */
sealed class RNCryptorException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /**
     * HMAC validation failed. This indicates either:
     * 1. Incorrect password, or
     * 2. Corrupted ciphertext
     *
     * It is not possible to distinguish between these cases in the v3 format.
     *
     * Reference: RNCryptor.swift:87-88
     */
    object HMACMismatch : RNCryptorException(
        "HMAC validation failed - incorrect password or corrupted data"
    )

    /**
     * Unrecognized data format. Usually this means:
     * 1. Wrong version byte (not 0x03)
     * 2. Corrupted header
     * 3. Not RNCryptor format at all
     *
     * Reference: RNCryptor.swift:90-91
     */
    object UnknownHeader : RNCryptorException(
        "Unrecognized data format - not RNCryptor v3 format or corrupted header"
    )

    /**
     * Message is too short to be valid RNCryptor v3 format.
     * Minimum size: 66 bytes (34 header + 32 HMAC, no ciphertext)
     *
     * Reference: RNCryptor.swift:93-94
     */
    object MessageTooShort : RNCryptorException(
        "Message too short - must be at least 66 bytes for RNCryptor v3 format"
    )

    /**
     * Memory allocation failure (should never happen in normal operation).
     *
     * Reference: RNCryptor.swift:96-97
     */
    class MemoryFailure(cause: Throwable) : RNCryptorException(
        "Memory allocation failure", cause
    )

    /**
     * A password-based decryptor was used on key-based ciphertext, or vice-versa.
     * Detected by checking the options byte at offset 1.
     *
     * Reference: RNCryptor.swift:99-100
     */
    object InvalidCredentialType : RNCryptorException(
        "Credential type mismatch - password-based vs key-based format"
    )

    /**
     * Generic encryption/decryption failure (wraps underlying crypto library errors).
     */
    class CryptoFailure(message: String, cause: Throwable? = null) : RNCryptorException(
        "Cryptographic operation failed: $message", cause
    )
}
