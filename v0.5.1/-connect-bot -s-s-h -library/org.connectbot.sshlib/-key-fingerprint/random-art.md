//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KeyFingerprint](index.md)/[randomArt](random-art.md)

# randomArt

[jvm]\
fun [randomArt](random-art.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), keyType: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), keySize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)

ASCII randomart visualization (SHA-256 based, OpenSSH compatible).

#### Return

multi-line ASCII art string

#### Parameters

jvm

| | |
|---|---|
| publicKeyBlob | SSH wire-format public key blob |
| keyType | key type label (e.g. &quot;RSA&quot;, &quot;ED25519&quot;) |
| keySize | key size in bits |