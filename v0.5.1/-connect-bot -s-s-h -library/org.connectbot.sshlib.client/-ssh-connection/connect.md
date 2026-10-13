//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)/[connect](connect.md)

# connect

[jvm]\
suspend fun [connect](connect.md)(): [ConnectResult](../../org.connectbot.sshlib/-connect-result/index.md)

Initiate SSH connection. Performs SSH version exchange, key exchange, and service negotiation. Returns [ConnectResult.Success](../../org.connectbot.sshlib/-connect-result/-success/index.md) when the transport is ready for authentication calls.