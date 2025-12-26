package com.bearminds.crypto.rncryptor.internal

/**
 * Constant-time byte array comparison.
 *
 * Regular equality comparison (==) short-circuits on the first difference,
 * which can leak information about the secret value through timing analysis.
 *
 * This function always compares all bytes in constant time, preventing timing attacks.
 *
 * Reference: RNCryptor.swift:753-765 (isEqualInConsistentTime)
 *
 * @param trusted The trusted value (e.g., computed HMAC)
 * @param untrusted The untrusted value (e.g., received HMAC)
 * @return true if arrays are equal, false otherwise
 */
fun constantTimeEquals(trusted: ByteArray, untrusted: ByteArray): Boolean {
    // Start with 0 (equal) only if lengths are equal
    // Reference: RNCryptor.swift:757
    var result: Byte = if (untrusted.size == trusted.size) 0 else 1

    // Handle empty arrays - if lengths differ, we already set result to 1
    // If both are empty, result is 0 and we can return immediately
    if (trusted.isEmpty() || untrusted.isEmpty()) {
        return result.toInt() == 0
    }

    // XOR each byte and accumulate with OR
    // If any bytes differ, result will become non-zero
    // Reference: RNCryptor.swift:758-762
    for (i in untrusted.indices) {
        // Use modulo to wrap around if attacker provides longer array
        // This prevents length leakage while still comparing all attacker bytes
        val trustedIndex = i % trusted.size
        result = (result.toInt() or (trusted[trustedIndex].toInt() xor untrusted[i].toInt())).toByte()
    }

    // Return true only if result is still 0 (no differences found)
    // Reference: RNCryptor.swift:764
    return result.toInt() == 0
}