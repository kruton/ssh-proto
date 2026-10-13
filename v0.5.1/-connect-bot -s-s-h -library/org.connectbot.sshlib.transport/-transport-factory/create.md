//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[TransportFactory](index.md)/[create](create.md)

# create

[jvm]\
abstract suspend fun [create](create.md)(): [Transport](../-transport/index.md)

Create and connect a new transport instance.

#### Return

A connected [Transport](../-transport/index.md) ready for reading and writing

#### Throws

| | |
|---|---|
| [TransportException](../-transport-exception/index.md) | if connection fails |