package com.bearminds.crypto.rncryptor

import kotlin.test.*

class RNCryptorV3Test {

    @Test
    fun testEncryptDecrypt_RoundTrip() {
        val password = "testPassword123"
        val plaintext = "Hello, RNCryptor!".encodeToByteArray()

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncrypt_ProducesCorrectFormat() {
        val password = "test"
        val plaintext = "data".encodeToByteArray()

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)

        // Check minimum length: 34 (header) + 16 (min AES block with padding) + 32 (HMAC)
        assertTrue(ciphertext.size >= 82, "Ciphertext too short: ${ciphertext.size}")

        // Check version byte
        assertEquals(FormatV3.VERSION, ciphertext[0], "Wrong version byte")

        // Check options byte (should be 1 for password-based)
        assertEquals(FormatV3.OPTIONS_PASSWORD_BASED, ciphertext[1], "Wrong options byte")
    }

    @Test
    fun testEncrypt_RandomnessCheck() {
        val password = "test"
        val plaintext = "same data".encodeToByteArray()

        // Encrypt same data twice
        val ciphertext1 = RNCryptorV3.encrypt(plaintext, password)
        val ciphertext2 = RNCryptorV3.encrypt(plaintext, password)

        // Ciphertexts should be different (due to random salt and IV)
        assertFalse(ciphertext1.contentEquals(ciphertext2), "Ciphertexts should differ due to randomness")

        // But both should decrypt to same plaintext
        val decrypted1 = RNCryptorV3.decrypt(ciphertext1, password)
        val decrypted2 = RNCryptorV3.decrypt(ciphertext2, password)
        assertContentEquals(plaintext, decrypted1)
        assertContentEquals(plaintext, decrypted2)
    }

    @Test
    fun testDecrypt_WrongPasswordThrowsHMACMismatch() {
        val plaintext = "secret".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, "correctPassword")

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, "wrongPassword")
        }
    }

    @Test
    fun testDecrypt_CorruptedDataThrowsHMACMismatch() {
        val plaintext = "data".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, "password").copyOf()

        // Corrupt one byte in the middle
        ciphertext[40] = (ciphertext[40] + 1).toByte()

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, "password")
        }
    }

    @Test
    fun testDecrypt_TooShortThrowsMessageTooShort() {
        val tooShort = ByteArray(65) // Need at least 66

        assertFailsWith<RNCryptorException.MessageTooShort> {
            RNCryptorV3.decrypt(tooShort, "password")
        }
    }

    @Test
    fun testDecrypt_WrongVersionThrowsUnknownHeader() {
        val plaintext = "data".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, "password").copyOf()

        // Change version byte
        ciphertext[0] = 99

        assertFailsWith<RNCryptorException.UnknownHeader> {
            RNCryptorV3.decrypt(ciphertext, "password")
        }
    }

    @Test
    fun testEncryptDecrypt_EmptyData() {
        val password = "password"
        val plaintext = ByteArray(0)

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
        assertEquals(0, decrypted.size)
    }

    @Test
    fun testEncryptDecrypt_SingleByte() {
        val password = "password"
        val plaintext = byteArrayOf(42)

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecrypt_LargeData() {
        val password = "password"
        val plaintext = ByteArray(1024 * 100) { it.toByte() } // 100 KB

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecrypt_UnicodePassword() {
        val password = "пароль🔒密码"
        val plaintext = "Unicode data: 你好世界".encodeToByteArray()

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecrypt_SpecialCharacters() {
        val password = "p@ssw0rd!#$%^&*()"
        val plaintext = "Data with\nnewlines\tand\ttabs\u0000null".encodeToByteArray()

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncryptDecrypt_BinaryData() {
        val password = "password"
        val plaintext = ByteArray(256) { it.toByte() } // All possible byte values

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEncrypt_EmptyPasswordThrows() {
        val plaintext = "data".encodeToByteArray()

        assertFailsWith<IllegalArgumentException> {
            RNCryptorV3.encrypt(plaintext, "")
        }
    }

    @Test
    fun testDecrypt_EmptyPasswordThrows() {
        val ciphertext = ByteArray(66) // Minimum valid size

        assertFailsWith<IllegalArgumentException> {
            RNCryptorV3.decrypt(ciphertext, "")
        }
    }

    @Test
    fun testDecrypt_MinimumValidSize() {
        // Create a minimal valid-looking ciphertext (will fail HMAC, but should pass size check)
        val password = "password"
        val plaintext = ByteArray(0) // Empty plaintext

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)

        // This should work - empty plaintext is valid
        val decrypted = RNCryptorV3.decrypt(ciphertext, password)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testPublicAPI_ConvenienceMethods() {
        val password = "testPassword"
        val plaintext = "Hello, World!".encodeToByteArray()

        // Test RNCryptor object methods
        val ciphertext = RNCryptor.encrypt(plaintext, password)
        val decrypted = RNCryptor.decrypt(ciphertext, password)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testPublicAPI_StringExtensions() {
        val password = "testPassword"
        val originalText = "Hello, RNCryptor Extensions!"

        // Test extension functions
        val encrypted = originalText.encryptRNCryptor(password)
        val decrypted = encrypted.decryptRNCryptor(password)

        assertEquals(originalText, decrypted)
    }

    @Test
    fun testCiphertext_HasCorrectStructure() {
        val password = "test"
        val plaintext = "Hello".encodeToByteArray()

        val ciphertext = RNCryptorV3.encrypt(plaintext, password)

        // Verify structure
        val header = ciphertext.sliceArray(0 until 34)
        val hmac = ciphertext.sliceArray(ciphertext.size - 32 until ciphertext.size)

        // Header should start with version and options
        assertEquals(3.toByte(), header[0])
        assertEquals(1.toByte(), header[1])

        // HMAC should be exactly 32 bytes
        assertEquals(32, hmac.size)
    }

    @Test
    fun testDecrypt_CorruptedHeader() {
        val password = "password"
        val plaintext = "data".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, password).copyOf()

        // Corrupt the salt in the header (this will cause HMAC to fail)
        ciphertext[5] = (ciphertext[5] + 1).toByte()

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, password)
        }
    }

    @Test
    fun testDecrypt_CorruptedIV() {
        val password = "password"
        val plaintext = "data".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, password).copyOf()

        // Corrupt the IV in the header
        ciphertext[25] = (ciphertext[25] + 1).toByte()

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, password)
        }
    }

    @Test
    fun testDecrypt_CorruptedCiphertext() {
        val password = "password"
        val plaintext = "some longer data to ensure we have actual ciphertext".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, password).copyOf()

        // Corrupt a byte in the ciphertext section (after header, before HMAC)
        val ciphertextStart = 34
        val ciphertextEnd = ciphertext.size - 32
        val middleIndex = (ciphertextStart + ciphertextEnd) / 2
        ciphertext[middleIndex] = (ciphertext[middleIndex] + 1).toByte()

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, password)
        }
    }

    @Test
    fun testDecrypt_CorruptedHMAC() {
        val password = "password"
        val plaintext = "data".encodeToByteArray()
        val ciphertext = RNCryptorV3.encrypt(plaintext, password).copyOf()

        // Corrupt the HMAC at the end
        ciphertext[ciphertext.size - 1] = (ciphertext[ciphertext.size - 1] + 1).toByte()

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext, password)
        }
    }

    @Test
    fun testDifferentPasswords_ProduceDifferentCiphertexts() {
        val plaintext = "same data".encodeToByteArray()

        val ciphertext1 = RNCryptorV3.encrypt(plaintext, "password1")
        val ciphertext2 = RNCryptorV3.encrypt(plaintext, "password2")

        // Different passwords should produce different ciphertexts
        assertFalse(ciphertext1.contentEquals(ciphertext2))

        // Each should only decrypt with its own password
        val decrypted1 = RNCryptorV3.decrypt(ciphertext1, "password1")
        assertContentEquals(plaintext, decrypted1)

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext1, "password2")
        }

        val decrypted2 = RNCryptorV3.decrypt(ciphertext2, "password2")
        assertContentEquals(plaintext, decrypted2)

        assertFailsWith<RNCryptorException.HMACMismatch> {
            RNCryptorV3.decrypt(ciphertext2, "password1")
        }
    }
}
