# Kotlin Multiplatform Encryption Library. Implementation of RNCryptor

A pure Kotlin Multiplatform implementation of the [RNCryptor v3](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md) encryption format.

## Used in Production

This library powers the encryption in **[PassKeep](https://passkeep.pro)** - an offline-first password manager trusted by millions of users:

- [PassKeep for Android](https://play.google.com/store/apps/details?id=com.redeyes.sspasswords)
- [PassKeep for iOS](https://apps.apple.com/app/passkeep-password-manager/id1616037797)

Learn more about how PassKeep protects your data: [Why Trust PassKeep?](https://passkeep.pro/trust)

## Overview

This library provides password-based encryption and decryption that is **100% compatible** with:
- [RNCryptor](https://github.com/RNCryptor/RNCryptor) (iOS/Swift)
- [JNCryptor](https://github.com/TGIO/JNCryptor) (Android/Java)
- All other RNCryptor implementations across languages

Data encrypted with this library can be decrypted by any RNCryptor implementation, and vice versa.

## Why RNCryptor?

RNCryptor is not a custom encryption algorithm - it's a **data format specification** that uses industry-standard, battle-tested cryptographic primitives:

- **AES-256-CBC** - The same encryption used by governments and banks worldwide
- **PBKDF2-HMAC-SHA1** - Secure key derivation with 10,000 iterations
- **HMAC-SHA256** - Message authentication to detect tampering

The RNCryptor format has been [publicly specified](https://github.com/RNCryptor/RNCryptor-Spec) and implemented in [many languages](https://github.com/RNCryptor/RNCryptor#other-languages), making it a trusted choice for cross-platform encryption.

## Installation

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation(project(":crypto"))
}
```

## Usage

### Encrypting Data

```kotlin
import com.bearminds.crypto.rncryptor.RNCryptorV3

val plaintext = "Secret message".encodeToByteArray()
val password = "my-secure-password"

val encrypted = RNCryptorV3.encrypt(plaintext, password)
```

### Decrypting Data

```kotlin
import com.bearminds.crypto.rncryptor.RNCryptorV3

val decrypted = RNCryptorV3.decrypt(encrypted, password)
val message = decrypted.decodeToString() // "Secret message"
```

### Error Handling

```kotlin
import com.bearminds.crypto.rncryptor.RNCryptorV3
import com.bearminds.crypto.rncryptor.RNCryptorException

try {
    val decrypted = RNCryptorV3.decrypt(encrypted, password)
} catch (e: RNCryptorException.HMACMismatch) {
    // Wrong password or data corrupted
} catch (e: RNCryptorException.MessageTooShort) {
    // Invalid encrypted data
}
```

## Security Details

### Encryption Algorithm

| Component         | Algorithm                        |
|-------------------|----------------------------------|
| Encryption        | AES-256 in CBC mode              |
| Key Derivation    | PBKDF2 with HMAC-SHA1            |
| PBKDF2 Iterations | 10,000                           |
| Authentication    | HMAC-SHA256                      |
| Key Size          | 256 bits                         |
| Block Size        | 128 bits                         |
| Salt Size         | 8 bytes (random per encryption)  |
| IV Size           | 16 bytes (random per encryption) |

### Data Format

Encrypted data follows the RNCryptor v3 format:

```
[Version: 1 byte]     = 0x03
[Options: 1 byte]     = 0x01 (password-based)
[Encryption Salt: 8 bytes]
[HMAC Salt: 8 bytes]
[IV: 16 bytes]
[Ciphertext: variable]
[HMAC: 32 bytes]
```

**Total overhead**: 66 bytes (34 byte header + 32 byte HMAC)

### Security Properties

1. **Authenticated Encryption**: HMAC is verified before decryption, preventing tampering attacks
2. **Unique Keys Per Encryption**: Random salts ensure each encryption uses different derived keys
3. **Constant-Time Comparison**: HMAC verification uses constant-time comparison to prevent timing attacks
4. **No Key Reuse**: Random IV ensures the same plaintext produces different ciphertext each time

## Testing

This library includes **55 comprehensive tests**, including:

- All official [RNCryptor test vectors](https://github.com/RNCryptor/RNCryptor-Spec/tree/master/vectors/v3)
- Key derivation (PBKDF2) verification
- Password-based encryption/decryption
- Cross-compatibility validation
- Edge cases and error handling

### Running Tests

```bash
# Run tests on JVM
./gradlew :crypto:jvmTest

# Run tests on all platforms
./gradlew :crypto:allTests
```

### Test Vectors

The library passes all official RNCryptor v3 test vectors from the [RNCryptor-Spec repository](https://github.com/RNCryptor/RNCryptor-Spec/tree/master/vectors/v3):

- `kdf-v3` - Key Derivation Function tests
- `password-v3` - Password-based encryption tests

## Cross-Platform Compatibility

This library has been validated to interoperate with:

| Platform             | Library         | Compatibility |
|----------------------|-----------------|---------------|
| iOS/Swift            | RNCryptor 5.x   | Verified      |
| Android/Java         | JNCryptor 1.2.0 | Verified      |
| Kotlin Multiplatform | This library    | Native        |

Data encrypted on any platform can be decrypted on any other platform using the same password.

## Architecture

```
crypto/src/
├── commonMain/kotlin/com/bearminds/crypto/rncryptor/
│   ├── RNCryptorV3.kt       # Main API (encrypt/decrypt)
│   ├── RNCryptor.kt         # Core encryption logic
│   ├── FormatV3.kt          # Format constants & parsing
│   ├── AESEngine.kt         # AES-256-CBC implementation
│   ├── HMACEngine.kt        # HMAC-SHA256 implementation
│   ├── SecureRandom.kt      # Cryptographic random generation
│   ├── RNCryptorException.kt # Exception types
│   └── internal/
│       └── ConstantTimeCompare.kt  # Timing-safe comparison
└── commonTest/kotlin/com/bearminds/crypto/rncryptor/
    ├── RNCryptorV3Test.kt   # API tests
    ├── FormatV3Test.kt      # Format parsing tests
    ├── CompatibilityTest.kt # Cross-platform tests
    ├── TestVectors.kt       # Official test vector loader
    └── internal/
        └── ConstantTimeCompareTest.kt
```

## Dependencies

This library uses [cryptography-kotlin](https://github.com/nickesk/cryptography-kotlin) for underlying cryptographic primitives, ensuring correct and secure implementations across all platforms.

## License

MIT License - free to use in any project, commercial or otherwise.

This library is developed and maintained as part of [PassKeep](https://passkeep.pro), an offline-first password manager.

See [LICENSE](LICENSE) for full details.

## References

- [RNCryptor Specification v3](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
- [RNCryptor Official Repository](https://github.com/RNCryptor/RNCryptor)
- [RNCryptor Test Vectors](https://github.com/RNCryptor/RNCryptor-Spec/tree/master/vectors/v3)
- [NIST AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [RFC 2898 - PKCS #5](https://www.rfc-editor.org/rfc/rfc2898) (PBKDF2)
- [RFC 2104 - HMAC](https://www.rfc-editor.org/rfc/rfc2104)
