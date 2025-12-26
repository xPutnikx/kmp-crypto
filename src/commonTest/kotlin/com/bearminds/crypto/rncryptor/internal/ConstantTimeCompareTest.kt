package com.bearminds.crypto.rncryptor.internal

import kotlin.test.*

class ConstantTimeCompareTest {

    @Test
    fun testEqual_SameArray() {
        val array = byteArrayOf(1, 2, 3, 4, 5)
        assertTrue(constantTimeEquals(array, array))
    }

    @Test
    fun testEqual_IdenticalArrays() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4, 5)
        assertTrue(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_DifferentLength() {
        val array1 = byteArrayOf(1, 2, 3)
        val array2 = byteArrayOf(1, 2, 3, 4)
        assertFalse(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_DifferentContent() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4, 6)
        assertFalse(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_FirstByteDifferent() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(2, 2, 3, 4, 5)
        assertFalse(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_LastByteDifferent() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4, 6)
        assertFalse(constantTimeEquals(array1, array2))
    }

    @Test
    fun testEqual_EmptyArrays() {
        val array1 = byteArrayOf()
        val array2 = byteArrayOf()
        assertTrue(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_EmptyAndNonEmpty() {
        val array1 = byteArrayOf()
        val array2 = byteArrayOf(1)
        assertFalse(constantTimeEquals(array1, array2))
    }

    @Test
    fun testEqual_LargeArrays() {
        val size = 1024
        val array1 = ByteArray(size) { it.toByte() }
        val array2 = ByteArray(size) { it.toByte() }
        assertTrue(constantTimeEquals(array1, array2))
    }

    @Test
    fun testNotEqual_LargeArraysOneByteDifferent() {
        val size = 1024
        val array1 = ByteArray(size) { it.toByte() }
        val array2 = ByteArray(size) { it.toByte() }
        array2[512] = (array2[512] + 1).toByte()
        assertFalse(constantTimeEquals(array1, array2))
    }
}
