package com.bearminds.crypto.rncryptor

import com.bearminds.crypto.rncryptor.internal.constantTimeEquals

/**
 * RNCryptor version 3 format implementation.
 *
 * Provides password-based encryption and decryption compatible with:
 * - RNCryptor 5.x (iOS Swift implementation)
 * - JNCryptor 1.2.0 (Android Java implementation)
 *
 * This is a direct port of RNCryptor v3 specification to Kotlin Multiplatform.
 *
 * Reference: RNCryptor.swift:229-518
 */
object RNCryptorV3 {

    /**
     * Encrypts data with a password using RNCryptor v3 format.
     *
     * This is a one-shot operation. For incremental encryption, use Encryptor class.
     *
     * Format produced:
     * [Version:1][Options:1][EncSalt:8][HMACSalt:8][IV:16][Ciphertext:...][HMAC:32]
     *
     * Reference: RNCryptor.swift:287-292 + 314-316
     *
     * @param plaintext Data to encrypt
     * @param password Password (will be converted to UTF-8)
     * @return Encrypted data in RNCryptor v3 format
     * @throws RNCryptorException.CryptoFailure if encryption fails
     */
    fun encrypt(plaintext: ByteArray, password: String): ByteArray {
        require(password.isNotEmpty()) { "Password must not be empty" }

        // Step 1: Generate random salts and IV (RNCryptor.swift:287-292)
        val encryptionSalt = SecureRandom.nextSalt()
        val hmacSalt = SecureRandom.nextSalt()
        val iv = SecureRandom.nextIV()

        // Step 2: Derive keys from password (RNCryptor.swift:346-347)
        val encryptionKey = FormatV3.deriveKey(password, encryptionSalt)
        val hmacKey = FormatV3.deriveKey(password, hmacSalt)

        // Step 3: Build header (RNCryptor.swift:338-353)
        val header = FormatV3.buildPasswordHeader(encryptionSalt, hmacSalt, iv)

        // Step 4: Encrypt plaintext (RNCryptor.swift:363)
        val engine = AESEngine.forEncryption(encryptionKey, iv)
        val ciphertext = engine.encrypt(plaintext)

        // Step 5: Calculate HMAC over header + ciphertext (RNCryptor.swift:362, 376)
        val hmacEngine = HMACEngine(hmacKey)
        val dataToAuthenticate = header + ciphertext
        val hmac = hmacEngine.compute(dataToAuthenticate)

        // Step 6: Assemble final message (RNCryptor.swift:332)
        return header + ciphertext + hmac
    }

    /**
     * Decrypts data with a password using RNCryptor v3 format.
     *
     * This is a one-shot operation. For incremental decryption, use Decryptor class.
     *
     * Reference: RNCryptor.swift:406-425
     *
     * @param ciphertext Encrypted data in RNCryptor v3 format
     * @param password Password used for encryption
     * @return Decrypted plaintext
     * @throws RNCryptorException.MessageTooShort if data is too short
     * @throws RNCryptorException.UnknownHeader if format is not recognized
     * @throws RNCryptorException.HMACMismatch if password is wrong or data is corrupted
     * @throws RNCryptorException.InvalidCredentialType if not password-based encryption
     */
    fun decrypt(ciphertext: ByteArray, password: String): ByteArray {
        require(password.isNotEmpty()) { "Password must not be empty" }

        // Step 1: Validate minimum length (RNCryptor.swift:438-440)
        // Minimum: 34 (header) + 0 (ciphertext can be empty) + 32 (HMAC) = 66 bytes
        if (ciphertext.size < FormatV3.PASSWORD_HEADER_SIZE + FormatV3.HMAC_SIZE) {
            throw RNCryptorException.MessageTooShort
        }

        // Step 2: Parse header (RNCryptor.swift:442, 479-493)
        val header = ciphertext.sliceArray(0 until FormatV3.PASSWORD_HEADER_SIZE)
        val (encryptionSalt, hmacSalt, iv) = FormatV3.parsePasswordHeader(header)

        // Step 3: Derive keys (RNCryptor.swift:495-496)
        val encryptionKey = FormatV3.deriveKey(password, encryptionSalt)
        val hmacKey = FormatV3.deriveKey(password, hmacSalt)

        // Step 4: Split message and HMAC (RNCryptor.swift:638-640)
        val messageEnd = ciphertext.size - FormatV3.HMAC_SIZE
        val message = ciphertext.sliceArray(0 until messageEnd)  // header + encrypted data
        val receivedHMAC = ciphertext.sliceArray(messageEnd until ciphertext.size)

        // Step 5: Verify HMAC (RNCryptor.swift:638-641)
        // This is CRITICAL for security - must happen before decryption
        val hmacEngine = HMACEngine(hmacKey)
        val computedHMAC = hmacEngine.compute(message)

        if (!constantTimeEquals(computedHMAC, receivedHMAC)) {
            throw RNCryptorException.HMACMismatch
        }

        // Step 6: Extract ciphertext (skip header) (RNCryptor.swift:444)
        val encryptedPayload = ciphertext.sliceArray(
            FormatV3.PASSWORD_HEADER_SIZE until messageEnd
        )

        // Step 7: Decrypt (RNCryptor.swift:642)
        val engine = AESEngine.forDecryption(encryptionKey, iv)
        return engine.decrypt(encryptedPayload)
    }
}
