//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentProvider](index.md)/[signData](sign-data.md)

# signData

[jvm]\
abstract suspend fun [signData](sign-data.md)(context: [AgentSigningContext](../-agent-signing-context/index.md)): [AgentResult](../-agent-result/index.md)&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?&gt;

Sign data with the specified key.

Called when a remote server requests a signature. The provider should:

1. 
   Verify the request is legitimate (check context)
2. 
   Optionally prompt the user for approval
3. 
   Return the signature, or a successful null value to deny the request

#### Return

Successful SSH-encoded signature blob, successful null to refuse, or [AgentResult.Failure](../-agent-result/-failure/index.md) if the provider could not process the request

#### Parameters

jvm

| | |
|---|---|
| context | Rich context about the signing request |