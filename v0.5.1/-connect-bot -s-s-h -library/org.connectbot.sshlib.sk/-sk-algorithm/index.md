//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkAlgorithm](index.md)

# SkAlgorithm

[jvm]\
enum [SkAlgorithm](index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[SkAlgorithm](index.md)&gt; 

OpenSSH FIDO2 / Security Key public-key algorithms.

These algorithms are used for SSH authentication backed by a hardware authenticator (CTAP2 device). The library does not perform CTAP2 signing itself; callers integrate with their own FIDO2 stack and surface the resulting signature via [org.connectbot.sshlib.AuthHandler.onSignatureRequest](../../org.connectbot.sshlib/-auth-handler/on-signature-request.md).

See OpenSSH's `PROTOCOL.u2f` and `draft-miller-ssh-agent` for the on-wire formats.

## Entries

| | |
|---|---|
| [ED25519](-e-d25519/index.md) | [jvm]<br>[ED25519](-e-d25519/index.md)<br>Ed25519 hardware-backed key (`sk-ssh-ed25519@openssh.com`). |
| [ECDSA_P256](-e-c-d-s-a_-p256/index.md) | [jvm]<br>[ECDSA_P256](-e-c-d-s-a_-p256/index.md)<br>ECDSA P-256 hardware-backed key (`sk-ecdsa-sha2-nistp256@openssh.com`). |

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [entries](entries.md) | [jvm]<br>val [entries](entries.md): [EnumEntries](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.enums/-enum-entries/index.html)&lt;[SkAlgorithm](index.md)&gt;<br>Returns a representation of an immutable list of all enum entries, in the order they're declared. |
| [name](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179) | [jvm]<br>val [name](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [ordinal](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179) | [jvm]<br>val [ordinal](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [sshName](ssh-name.md) | [jvm]<br>val [sshName](ssh-name.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |

## Functions

| Name | Summary |
|---|---|
| [valueOf](value-of.md) | [jvm]<br>fun [valueOf](value-of.md)(value: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SkAlgorithm](index.md)<br>Returns the enum constant of this type with the specified name. The string must match exactly an identifier used to declare an enum constant in this type. (Extraneous whitespace characters are not permitted.) |
| [values](values.md) | [jvm]<br>fun [values](values.md)(): [Array](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-array/index.html)&lt;[SkAlgorithm](index.md)&gt;<br>Returns an array containing the constants of this enum type, in the order they're declared. |