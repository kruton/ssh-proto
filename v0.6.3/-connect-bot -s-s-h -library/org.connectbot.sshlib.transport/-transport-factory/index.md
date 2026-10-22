//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[TransportFactory](index.md)

# TransportFactory

fun interface [TransportFactory](index.md)

Factory for creating transport connections.

Implement this interface to provide custom transport implementations for SSH connections. The library provides [KtorTcpTransportFactory](../-ktor-tcp-transport-factory/index.md) as a default TCP implementation.

Example custom implementation:

```kotlin
class MyTransportFactory : TransportFactory {
    override suspend fun create(): Transport {
        return MyCustomTransport()
    }
}
```

#### Inheritors

| |
|---|
| [KtorTcpTransportFactory](../-ktor-tcp-transport-factory/index.md) |

## Functions

| Name | Summary |
|---|---|
| [create](create.md) | [jvm]<br>abstract suspend fun [create](create.md)(): [Transport](../-transport/index.md)<br>Create and connect a new transport instance. |