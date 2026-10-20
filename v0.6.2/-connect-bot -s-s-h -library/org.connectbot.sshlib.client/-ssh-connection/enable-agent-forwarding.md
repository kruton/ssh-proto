//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)/[enableAgentForwarding](enable-agent-forwarding.md)

# enableAgentForwarding

[jvm]\
fun [enableAgentForwarding](enable-agent-forwarding.md)(provider: [AgentProvider](../../org.connectbot.sshlib/-agent-provider/index.md))

Enable SSH agent forwarding with the provided agent.

Must be called before the remote server opens agent channels. When agent forwarding is enabled, remote servers can request signatures from your agent provider.

#### Parameters

jvm

| | |
|---|---|
| provider | Agent implementation that handles signing requests |