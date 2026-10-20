//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KeyFingerprint](index.md)

# KeyFingerprint

[jvm]\
object [KeyFingerprint](index.md)

SSH key fingerprint utilities.

Produces OpenSSH-compatible fingerprints in SHA-256, MD5, Bubble-Babble, and ASCII randomart formats.

## Functions

| Name | Summary |
|---|---|
| [bubblebabble](bubblebabble.md) | [jvm]<br>fun [bubblebabble](bubblebabble.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>Bubble-Babble fingerprint (phonetic encoding of SHA-1 hash). |
| [md5](md5.md) | [jvm]<br>fun [md5](md5.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>MD5 fingerprint in hex-colon format. |
| [randomArt](random-art.md) | [jvm]<br>fun [randomArt](random-art.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), keyType: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), keySize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>ASCII randomart visualization (SHA-256 based, OpenSSH compatible). |
| [sha256](sha256.md) | [jvm]<br>fun [sha256](sha256.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>SHA-256 fingerprint in Base64 format (OpenSSH default). |