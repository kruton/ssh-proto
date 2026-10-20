//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[enableCertificateHostKeys](enable-certificate-host-keys.md)

# enableCertificateHostKeys

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [enableCertificateHostKeys](enable-certificate-host-keys.md)(enabled: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) = true): [SshClientConfig.Builder](index.md)

Prepend certificate counterparts of configured host key algorithms at build time. Assignment order does not matter. Raw keys remain as fallback; CA trust must be configured in [hostKeyVerifier](host-key-verifier.md). Calling with false disables automatic additions.