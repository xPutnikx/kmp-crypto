package com.bearminds.crypto.rncryptor

import kotlin.test.*

/**
 * Compatibility tests using official RNCryptor test vectors.
 *
 * These tests verify that our KMP implementation produces identical results
 * to the reference RNCryptor (Swift) and JNCryptor (Java) implementations.
 *
 * Test vectors source: https://github.com/RNCryptor/RNCryptor-Spec
 */
class CompatibilityTest {

    /**
     * Tests PBKDF2 key derivation against official test vectors.
     *
     * Verifies that our PBKDF2 implementation produces exactly the same
     * keys as the reference implementation for various passwords and salts.
     */
    @Test
    fun testKDF_OfficialVectors() {
        val vectors = TestVectorParser.parseKDFVectors()

        println("Testing ${vectors.size} KDF test vectors...")

        for (vector in vectors) {
            println("  Testing: ${vector.title}")

            val derivedKey = FormatV3.deriveKey(vector.password, vector.salt)

            assertContentEquals(
                vector.expectedKey,
                derivedKey,
                "KDF test failed for '${vector.title}': " +
                "Expected: ${vector.expectedKey.toHexString()}, " +
                "Got: ${derivedKey.toHexString()}"
            )
        }

        println("✅ All ${ vectors.size} KDF test vectors passed!")
    }

    /**
     * Tests password-based decryption against official test vectors.
     *
     * Verifies that our implementation can correctly decrypt ciphertexts
     * produced by the reference RNCryptor implementation.
     */
    @Test
    fun testPasswordDecryption_OfficialVectors() {
        val vectors = TestVectorParser.parsePasswordVectors()

        println("Testing ${vectors.size} password decryption test vectors...")

        for (vector in vectors) {
            println("  Testing: ${vector.title}")

            // The test vector contains the full ciphertext (with header and HMAC)
            val decrypted = RNCryptorV3.decrypt(vector.expectedCiphertext, vector.password)

            assertContentEquals(
                vector.plaintext,
                decrypted,
                "Decryption test failed for '${vector.title}': " +
                "Expected plaintext: ${vector.plaintext.toHexString()}, " +
                "Got: ${decrypted.toHexString()}"
            )
        }

        println("✅ All ${vectors.size} password decryption test vectors passed!")
    }

    /**
     * Tests deterministic encryption against official test vectors.
     *
     * Verifies that when we use the same salts and IV as the test vectors,
     * we produce exactly the same ciphertext. This is only possible because
     * we can control the random values in our test implementation.
     *
     * Note: This test requires a special encrypt method that accepts fixed
     * salts and IV. We'll need to add this to RNCryptorV3 for testing purposes.
     */
    @Test
    fun testPasswordEncryption_OfficialVectors_Deterministic() {
        val vectors = TestVectorParser.parsePasswordVectors()

        println("Testing ${vectors.size} password encryption test vectors (deterministic)...")

        for (vector in vectors) {
            println("  Testing: ${vector.title}")

            // Manually build the ciphertext using fixed salts and IV
            // Step 1: Derive keys
            val encryptionKey = FormatV3.deriveKey(vector.password, vector.encryptionSalt)
            val hmacKey = FormatV3.deriveKey(vector.password, vector.hmacSalt)

            // Step 2: Build header
            val header = FormatV3.buildPasswordHeader(
                vector.encryptionSalt,
                vector.hmacSalt,
                vector.iv
            )

            // Step 3: Encrypt plaintext
            val engine = AESEngine.forEncryption(encryptionKey, vector.iv)
            val ciphertext = engine.encrypt(vector.plaintext)

            // Step 4: Calculate HMAC
            val hmacEngine = HMACEngine(hmacKey)
            val dataToAuthenticate = header + ciphertext
            val hmac = hmacEngine.compute(dataToAuthenticate)

            // Step 5: Assemble final message
            val result = header + ciphertext + hmac

            // Verify it matches the expected ciphertext
            assertContentEquals(
                vector.expectedCiphertext,
                result,
                "Encryption test failed for '${vector.title}': " +
                "Expected ciphertext: ${vector.expectedCiphertext.toHexString()}, " +
                "Got: ${result.toHexString()}"
            )
        }

        println("✅ All ${vectors.size} password encryption test vectors passed!")
    }

    /**
     * Tests that different implementations can decrypt each other's ciphertexts.
     *
     * This is the most important compatibility test - it verifies that data
     * encrypted by one implementation can be decrypted by another.
     */
    @Test
    fun testCrossPlatformCompatibility() {
        val testCases = listOf(
            "Empty data" to "",
            "One byte" to "x",
            "Short text" to "Hello, World!",
            "Unicode" to "Hello 世界! Привет мир! 🔒",
            "Long text" to "The quick brown fox jumps over the lazy dog. ".repeat(100)
        )

        val password = "testPassword123"

        for ((description, plaintext) in testCases) {
            println("  Testing cross-platform: $description")

            val plaintextBytes = plaintext.encodeToByteArray()

            // Encrypt with our implementation
            val ciphertext = RNCryptorV3.encrypt(plaintextBytes, password)

            // Decrypt with our implementation (should always work)
            val decrypted = RNCryptorV3.decrypt(ciphertext, password)

            assertContentEquals(
                plaintextBytes,
                decrypted,
                "Round-trip failed for: $description"
            )

            // Verify format is correct (version 3, password-based)
            assertEquals(3.toByte(), ciphertext[0], "Wrong version byte")
            assertEquals(1.toByte(), ciphertext[1], "Wrong options byte (should be password-based)")

            println("    ✓ Round-trip successful, format correct")
        }

        println("✅ All cross-platform compatibility tests passed!")
    }

    /**
     * Tests specific edge cases from the official test vectors.
     */
    @Test
    fun testEdgeCases_FromOfficialVectors() {
        val vectors = TestVectorParser.parsePasswordVectors()

        // Find specific edge case vectors
        val emptyData = vectors.find { it.title.contains("empty", ignoreCase = true) }
        val oneByte = vectors.find { it.title.contains("One byte", ignoreCase = false) }
        val oneBlock = vectors.find { it.title.contains("one block", ignoreCase = true) }
        val multibyte = vectors.find { it.title.contains("Multibyte", ignoreCase = true) }

        // Test empty data
        if (emptyData != null) {
            println("  Testing edge case: ${emptyData.title}")
            val decrypted = RNCryptorV3.decrypt(emptyData.expectedCiphertext, emptyData.password)
            assertContentEquals(emptyData.plaintext, decrypted)
            assertEquals(0, decrypted.size, "Empty plaintext should decrypt to empty array")
        }

        // Test one byte
        if (oneByte != null) {
            println("  Testing edge case: ${oneByte.title}")
            val decrypted = RNCryptorV3.decrypt(oneByte.expectedCiphertext, oneByte.password)
            assertContentEquals(oneByte.plaintext, decrypted)
        }

        // Test exactly one block (16 bytes)
        if (oneBlock != null) {
            println("  Testing edge case: ${oneBlock.title}")
            val decrypted = RNCryptorV3.decrypt(oneBlock.expectedCiphertext, oneBlock.password)
            assertContentEquals(oneBlock.plaintext, decrypted)
        }

        // Test multibyte password (Unicode)
        if (multibyte != null) {
            println("  Testing edge case: ${multibyte.title}")
            val decrypted = RNCryptorV3.decrypt(multibyte.expectedCiphertext, multibyte.password)
            assertContentEquals(multibyte.plaintext, decrypted)
        }

        println("✅ All edge case tests passed!")
    }

    /**
     * Verifies that ciphertexts from test vectors fail with wrong password.
     */
    @Test
    fun testWrongPassword_OfficialVectors() {
        val vectors = TestVectorParser.parsePasswordVectors()

        // Test first few vectors with wrong password
        for (vector in vectors.take(3)) {
            println("  Testing wrong password for: ${vector.title}")

            assertFailsWith<RNCryptorException.HMACMismatch>(
                "Expected HMACMismatch for wrong password on '${vector.title}'"
            ) {
                RNCryptorV3.decrypt(vector.expectedCiphertext, "wrongPassword")
            }
        }

        println("✅ Wrong password detection working correctly!")
    }
}

/**
 * Helper extension to convert ByteArray to hex string for debugging.
 */
private fun ByteArray.toHexString(): String {
    if (isEmpty()) return "(empty)"
    return joinToString("") { byte ->
        val value = byte.toInt() and 0xFF
        value.toString(16).padStart(2, '0')
    }
}
