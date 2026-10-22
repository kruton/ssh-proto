//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[keepAliveIntervalMs](keep-alive-interval-ms.md)

# keepAliveIntervalMs

[jvm]\
var [keepAliveIntervalMs](keep-alive-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Send an SSH_MSG_IGNORE heartbeat every N milliseconds to keep the connection alive across NAT/VPN/firewall idle timeouts.

The message is a single empty payload that the server silently ignores (RFC 4253 §11.2). It does NOT expect a response — this is purely to prevent intermediaries from killing the TCP connection during idle.

Recommended for long-lived connections behind aggressive firewalls. Set to 0 to disable (default).

Common values: 15000 (15s, sshj default), 30000 (30s).