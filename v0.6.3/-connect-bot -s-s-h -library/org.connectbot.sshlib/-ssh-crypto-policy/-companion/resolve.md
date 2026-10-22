//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshCryptoPolicy](../index.md)/[Companion](index.md)/[resolve](resolve.md)

# resolve

[jvm]\

@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [resolve](resolve.md)(preset: [CryptoPolicyPreset](../../-crypto-policy-preset/index.md) = CryptoPolicyPreset.DEFAULT, overrides: [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[AlgorithmCategory](../../-algorithm-category/index.md), [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt; = emptyMap(), minimumRsaBits: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)? = null, minimumDhBits: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)? = null): [SshCryptoPolicy](../index.md)

Resolve a preset or DEFAULT plus custom expressions. Unsupported positive entries are preserved by the caller and skipped here. Size overrides are for Custom and must not be supplied with a non-DEFAULT preset.