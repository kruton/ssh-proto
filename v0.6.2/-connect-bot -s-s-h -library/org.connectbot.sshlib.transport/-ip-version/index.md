//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[IpVersion](index.md)

# IpVersion

[jvm]\
enum [IpVersion](index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[IpVersion](index.md)&gt; 

Controls which IP address families are used for TCP connections.

## Entries

| | |
|---|---|
| [AUTO](-a-u-t-o/index.md) | [jvm]<br>[AUTO](-a-u-t-o/index.md)<br>Use Happy Eyeballs (RFC 8305) to race IPv6 and IPv4. |
| [IPV4_ONLY](-i-p-v4_-o-n-l-y/index.md) | [jvm]<br>[IPV4_ONLY](-i-p-v4_-o-n-l-y/index.md)<br>Connect only over IPv4. |
| [IPV6_ONLY](-i-p-v6_-o-n-l-y/index.md) | [jvm]<br>[IPV6_ONLY](-i-p-v6_-o-n-l-y/index.md)<br>Connect only over IPv6. |

## Properties

| Name | Summary |
|---|---|
| [entries](entries.md) | [jvm]<br>val [entries](entries.md): [EnumEntries](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.enums/-enum-entries/index.html)&lt;[IpVersion](index.md)&gt;<br>Returns a representation of an immutable list of all enum entries, in the order they're declared. |
| [name](-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179) | [jvm]<br>val [name](-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [ordinal](-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179) | [jvm]<br>val [ordinal](-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |

## Functions

| Name | Summary |
|---|---|
| [valueOf](value-of.md) | [jvm]<br>fun [valueOf](value-of.md)(value: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [IpVersion](index.md)<br>Returns the enum constant of this type with the specified name. The string must match exactly an identifier used to declare an enum constant in this type. (Extraneous whitespace characters are not permitted.) |
| [values](values.md) | [jvm]<br>fun [values](values.md)(): [Array](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-array/index.html)&lt;[IpVersion](index.md)&gt;<br>Returns an array containing the constants of this enum type, in the order they're declared. |