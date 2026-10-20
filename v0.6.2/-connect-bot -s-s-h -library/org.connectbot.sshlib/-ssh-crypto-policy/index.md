//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshCryptoPolicy](index.md)

# SshCryptoPolicy

[jvm]\
class [SshCryptoPolicy](index.md)

Resolved connection policy. Obtain a fresh snapshot with [resolve](-companion/resolve.md) after installing crypto providers. Expressions contain bare names (an exact list), or individually prefixed ^ / + / - entries. Custom overrides always use DEFAULT as their base. Protocol KEX markers are managed separately.

Preset definitions evolve with library releases:

- 
   [CryptoPolicyPreset.DEFAULT](../-crypto-policy-preset/-d-e-f-a-u-l-t/index.md): modern algorithms, with RSA and finite-field DH minimum 2048 bits.
- 
   [CryptoPolicyPreset.FUTURE](../-crypto-policy-preset/-f-u-t-u-r-e/index.md): hybrid post-quantum KEX only, 256-bit encryption keys, and RSA/DH minimum 3072 bits.
- 
   [CryptoPolicyPreset.FIPS](../-crypto-policy-preset/-f-i-p-s/index.md): an AES/SHA-2/NIST ECDH/fixed-DH/RSA-SHA2/ECDSA subset. This is an algorithm filter, not a claim of FIPS validation for the provider or application.
- 
   [CryptoPolicyPreset.LEGACY](../-crypto-policy-preset/-l-e-g-a-c-y/index.md): modern preferences followed by compatibility algorithms, with RSA/DH minimum 1024 bits.

An exact expression is an ordered comma-separated list of names. Delta entries individually use `^` (prepend), `+` (append), or `-` (exclude), for example `^curve25519-sha256,+diffie-hellman-group1-sha1,-ecdh-sha2-nistp256`. Unsupported or unavailable positive entries are skipped and reported in warnings; callers should preserve the original expression. minimumRsaBits and minimumDhBits are independent numeric requirements that explicit algorithm selections cannot bypass. The group1 example therefore also requires `minimumDhBits = 1024`.

Install platform crypto providers before resolving and apply the snapshot with [SshClientConfig.Builder.cryptoPolicy](../-ssh-client-config/-builder/crypto-policy.md). Persist user expressions and preset names, rather than the runtime [catalog](-companion/catalog.md) or resolved algorithm lists. Public-key authentication selections are independent of server host-key selections.

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [algorithms](algorithms.md) | [jvm]<br>val [algorithms](algorithms.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[AlgorithmCategory](../-algorithm-category/index.md), [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;&gt; |
| [minimumDhBits](minimum-dh-bits.md) | [jvm]<br>val [minimumDhBits](minimum-dh-bits.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [minimumRsaBits](minimum-rsa-bits.md) | [jvm]<br>val [minimumRsaBits](minimum-rsa-bits.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [preset](preset.md) | [jvm]<br>val [preset](preset.md): [CryptoPolicyPreset](../-crypto-policy-preset/index.md) |
| [warnings](warnings.md) | [jvm]<br>val [warnings](warnings.md): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AlgorithmPolicyWarning](../-algorithm-policy-warning/index.md)&gt; |