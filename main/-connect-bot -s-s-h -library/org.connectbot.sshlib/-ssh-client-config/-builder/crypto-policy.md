//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[cryptoPolicy](crypto-policy.md)

# cryptoPolicy

[jvm]\
fun [cryptoPolicy](crypto-policy.md)(value: [SshCryptoPolicy](../../-ssh-crypto-policy/index.md)): [SshClientConfig.Builder](index.md)

Apply a freshly resolved [SshCryptoPolicy](../../-ssh-crypto-policy/index.md) before any explicit preference reordering. Resolve after installing platform crypto providers. The policy controls all algorithm categories, including public-key authentication, and enforces RSA/DH minimum key sizes. See [SshCryptoPolicy](../../-ssh-crypto-policy/index.md) for presets, custom expression syntax, and capability warnings.

Example: `cryptoPolicy(SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE))`.