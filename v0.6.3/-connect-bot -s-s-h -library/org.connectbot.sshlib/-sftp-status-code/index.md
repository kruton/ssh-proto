//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpStatusCode](index.md)

# SftpStatusCode

[jvm]\
enum [SftpStatusCode](index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[SftpStatusCode](index.md)&gt; 

SFTP status codes (draft-ietf-secsh-filexfer-02 section 7).

## Entries

| | |
|---|---|
| [OK](-o-k/index.md) | [jvm]<br>[OK](-o-k/index.md) |
| [EOF](-e-o-f/index.md) | [jvm]<br>[EOF](-e-o-f/index.md) |
| [NO_SUCH_FILE](-n-o_-s-u-c-h_-f-i-l-e/index.md) | [jvm]<br>[NO_SUCH_FILE](-n-o_-s-u-c-h_-f-i-l-e/index.md) |
| [PERMISSION_DENIED](-p-e-r-m-i-s-s-i-o-n_-d-e-n-i-e-d/index.md) | [jvm]<br>[PERMISSION_DENIED](-p-e-r-m-i-s-s-i-o-n_-d-e-n-i-e-d/index.md) |
| [FAILURE](-f-a-i-l-u-r-e/index.md) | [jvm]<br>[FAILURE](-f-a-i-l-u-r-e/index.md) |
| [BAD_MESSAGE](-b-a-d_-m-e-s-s-a-g-e/index.md) | [jvm]<br>[BAD_MESSAGE](-b-a-d_-m-e-s-s-a-g-e/index.md) |
| [NO_CONNECTION](-n-o_-c-o-n-n-e-c-t-i-o-n/index.md) | [jvm]<br>[NO_CONNECTION](-n-o_-c-o-n-n-e-c-t-i-o-n/index.md) |
| [CONNECTION_LOST](-c-o-n-n-e-c-t-i-o-n_-l-o-s-t/index.md) | [jvm]<br>[CONNECTION_LOST](-c-o-n-n-e-c-t-i-o-n_-l-o-s-t/index.md) |
| [OP_UNSUPPORTED](-o-p_-u-n-s-u-p-p-o-r-t-e-d/index.md) | [jvm]<br>[OP_UNSUPPORTED](-o-p_-u-n-s-u-p-p-o-r-t-e-d/index.md) |

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [code](code.md) | [jvm]<br>val [code](code.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [entries](entries.md) | [jvm]<br>val [entries](entries.md): [EnumEntries](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.enums/-enum-entries/index.html)&lt;[SftpStatusCode](index.md)&gt;<br>Returns a representation of an immutable list of all enum entries, in the order they're declared. |
| [name](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179) | [jvm]<br>val [name](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-372974862%2FProperties%2F-1357994179): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [ordinal](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179) | [jvm]<br>val [ordinal](../../org.connectbot.sshlib.transport/-ip-version/-i-p-v6_-o-n-l-y/index.md#-739389684%2FProperties%2F-1357994179): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |

## Functions

| Name | Summary |
|---|---|
| [valueOf](value-of.md) | [jvm]<br>fun [valueOf](value-of.md)(value: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpStatusCode](index.md)<br>Returns the enum constant of this type with the specified name. The string must match exactly an identifier used to declare an enum constant in this type. (Extraneous whitespace characters are not permitted.) |
| [values](values.md) | [jvm]<br>fun [values](values.md)(): [Array](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-array/index.html)&lt;[SftpStatusCode](index.md)&gt;<br>Returns an array containing the constants of this enum type, in the order they're declared. |