package com.bearminds.crypto.rncryptor

import kotlin.test.*

class FormatV3Test {

    @Test
    fun testDeriveKey_ProducesCorrectLength() {
        val password = "testPassword"
        val salt = ByteArray(FormatV3.SALT_SIZE) { it.toByte() }

        val key = FormatV3.deriveKey(password, salt)

        assertEquals(FormatV3.KEY_SIZE, key.size)
    }

    @Test
    fun testDeriveKey_SameInputProducesSameOutput() {
        val password = "testPassword"
        val salt = ByteArray(FormatV3.SALT_SIZE) { it.toByte() }

        val key1 = FormatV3.deriveKey(password, salt)
        val key2 = FormatV3.deriveKey(password, salt)

        assertContentEquals(key1, key2)
    }

    @Test
    fun testDeriveKey_DifferentSaltProducesDifferentKey() {
        val password = "testPassword"
        val salt1 = ByteArray(FormatV3.SALT_SIZE) { 0x00 }
        val salt2 = ByteArray(FormatV3.SALT_SIZE) { 0xFF.toByte() }

        val key1 = FormatV3.deriveKey(password, salt1)
        val key2 = FormatV3.deriveKey(password, salt2)

        assertFalse(key1.contentEquals(key2))
    }

    @Test
    fun testDeriveKey_DifferentPasswordProducesDifferentKey() {
        val salt = ByteArray(FormatV3.SALT_SIZE) { it.toByte() }

        val key1 = FormatV3.deriveKey("password1", salt)
        val key2 = FormatV3.deriveKey("password2", salt)

        assertFalse(key1.contentEquals(key2))
    }

    @Test
    fun testDeriveKey_EmptyPasswordThrows() {
        val salt = ByteArray(FormatV3.SALT_SIZE)

        assertFailsWith<IllegalArgumentException> {
            FormatV3.deriveKey("", salt)
        }
    }

    @Test
    fun testDeriveKey_WrongSaltSizeThrows() {
        assertFailsWith<IllegalArgumentException> {
            FormatV3.deriveKey("password", ByteArray(4))
        }
    }

    @Test
    fun testBuildPasswordHeader_CorrectSize() {
        val encSalt = ByteArray(FormatV3.SALT_SIZE)
        val hmacSalt = ByteArray(FormatV3.SALT_SIZE)
        val iv = ByteArray(FormatV3.IV_SIZE)

        val header = FormatV3.buildPasswordHeader(encSalt, hmacSalt, iv)

        assertEquals(FormatV3.PASSWORD_HEADER_SIZE, header.size)
    }

    @Test
    fun testBuildPasswordHeader_CorrectFormat() {
        val encSalt = ByteArray(8) { 0xAA.toByte() }
        val hmacSalt = ByteArray(8) { 0xBB.toByte() }
        val iv = ByteArray(16) { 0xCC.toByte() }

        val header = FormatV3.buildPasswordHeader(encSalt, hmacSalt, iv)

        assertEquals(FormatV3.VERSION, header[0])
        assertEquals(FormatV3.OPTIONS_PASSWORD_BASED, header[1])
        assertTrue(header.sliceArray(2..9).all { it == 0xAA.toByte() })
        assertTrue(header.sliceArray(10..17).all { it == 0xBB.toByte() })
        assertTrue(header.sliceArray(18..33).all { it == 0xCC.toByte() })
    }

    @Test
    fun testParsePasswordHeader_RoundTrip() {
        val encSalt = ByteArray(8) { it.toByte() }
        val hmacSalt = ByteArray(8) { (it + 10).toByte() }
        val iv = ByteArray(16) { (it + 20).toByte() }

        val header = FormatV3.buildPasswordHeader(encSalt, hmacSalt, iv)
        val (parsedEncSalt, parsedHmacSalt, parsedIv) = FormatV3.parsePasswordHeader(header)

        assertContentEquals(encSalt, parsedEncSalt)
        assertContentEquals(hmacSalt, parsedHmacSalt)
        assertContentEquals(iv, parsedIv)
    }

    @Test
    fun testParsePasswordHeader_WrongVersionThrows() {
        val header = ByteArray(34)
        header[0] = 99  // Wrong version
        header[1] = FormatV3.OPTIONS_PASSWORD_BASED

        assertFailsWith<RNCryptorException.UnknownHeader> {
            FormatV3.parsePasswordHeader(header)
        }
    }

    @Test
    fun testParsePasswordHeader_WrongCredentialTypeThrows() {
        val header = ByteArray(34)
        header[0] = FormatV3.VERSION
        header[1] = FormatV3.OPTIONS_KEY_BASED  // Should be password-based

        assertFailsWith<RNCryptorException.InvalidCredentialType> {
            FormatV3.parsePasswordHeader(header)
        }
    }

    @Test
    fun testParsePasswordHeader_TooShortThrows() {
        val header = ByteArray(20)  // Too short

        assertFailsWith<IllegalArgumentException> {
            FormatV3.parsePasswordHeader(header)
        }
    }

    @Test
    fun testBuildPasswordHeader_WrongSaltSizeThrows() {
        val wrongSalt = ByteArray(4)
        val correctSalt = ByteArray(FormatV3.SALT_SIZE)
        val iv = ByteArray(FormatV3.IV_SIZE)

        assertFailsWith<IllegalArgumentException> {
            FormatV3.buildPasswordHeader(wrongSalt, correctSalt, iv)
        }

        assertFailsWith<IllegalArgumentException> {
            FormatV3.buildPasswordHeader(correctSalt, wrongSalt, iv)
        }
    }

    @Test
    fun testBuildPasswordHeader_WrongIVSizeThrows() {
        val salt = ByteArray(FormatV3.SALT_SIZE)
        val wrongIV = ByteArray(8)

        assertFailsWith<IllegalArgumentException> {
            FormatV3.buildPasswordHeader(salt, salt, wrongIV)
        }
    }
}
