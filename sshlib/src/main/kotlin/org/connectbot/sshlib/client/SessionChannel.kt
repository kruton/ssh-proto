/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot.sshlib.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.connectbot.sshlib.SessionExit
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.protocol.ByteString
import org.connectbot.sshlib.protocol.ChannelRequestEnv
import org.connectbot.sshlib.protocol.ChannelRequestExec
import org.connectbot.sshlib.protocol.ChannelRequestPtyReq
import org.connectbot.sshlib.protocol.ChannelRequestShell
import org.connectbot.sshlib.protocol.ChannelRequestSubsystem
import org.connectbot.sshlib.protocol.ChannelRequestWindowChange
import org.connectbot.sshlib.protocol.SshChannelEffect
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.connectbot.sshlib.protocol.createByteString
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

class SessionChannel internal constructor(
    private val connection: SshConnection,
    private val connectionScope: CoroutineScope,
    override val localChannelNumber: Int,
    private var _remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long = 0,
    private val initialWindowSize: Int = 64 * 1024,
    private val canSendChaff: Boolean = false,
    private val obscureKeystrokeTimingIntervalMs: Long = 20L,
    private val obfuscatorClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    private val obfuscatorRandom: Random = Random.Default,
    private val bufferedStdout: Boolean = false,
    private val lifecycle: SshChannelStateMachine = SshChannelStateMachine(SshChannelState.OPEN),
) : SshSession {
    companion object {
        private val logger = LoggerFactory.getLogger(SessionChannel::class.java)
    }

    private val window = LocalChannelWindow(
        initialWindowSize,
        remoteInitial = remoteWindowSizeInitial,
        adjustmentThreshold = maxOf(1, initialWindowSize / 2),
    )
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)

    private val stdoutIngress = Channel<ByteArray>(Channel.UNLIMITED)
    private val stderrIngress = Channel<ByteArray>(Channel.UNLIMITED)
    private val extendedDataIngress = Channel<Pair<Int, ByteArray>>(Channel.UNLIMITED)
    private val _stdout = Channel<ByteArray>(Channel.RENDEZVOUS)
    private val stdoutBufferIngress = Channel<ByteBuffer>(Channel.UNLIMITED)
    private val stdoutBufferConsumed = Channel<Unit>(1)
    private val stdoutBuffers = Channel<ByteBuffer>(Channel.RENDEZVOUS, onUndeliveredElement = {
        stdoutBufferConsumed.trySend(Unit)
    })
    private val _stderr = Channel<ByteArray>(Channel.RENDEZVOUS)
    private val _extendedData = Channel<Pair<Int, ByteArray>>(Channel.RENDEZVOUS)

    @Volatile private var inboundDeliveryOpen = true
    internal val delivery = ChannelDelivery(connectionScope.coroutineContext)

    private val arrayStdout by lazy {
        if (bufferedStdout) {
            val adapter = delivery.launch {
                try {
                    for (buffer in stdoutBuffers) {
                        _stdout.send(buffer.toByteArray())
                        stdoutBufferConsumed.trySend(Unit)
                    }
                } catch (cancelled: CancellationException) {
                    // Cancelling the public array stream abandons its buffer too. Do not leave
                    // the buffer pump waiting forever for acknowledgement from this adapter.
                    stdoutBufferConsumed.cancel(cancelled)
                    stdoutBuffers.cancel(cancelled)
                    throw cancelled
                } catch (failure: Exception) {
                    _stdout.close(failure)
                } finally {
                    _stdout.close()
                }
            }
            // All buffers may have drained through readBuffer(), or explicit close may have
            // retired delivery before the public array adapter was first requested.
            if (adapter == null) _stdout.close()
        }
        _stdout
    }

    init {
        delivery.launch {
            if (bufferedStdout) {
                deliverData(stdoutBufferIngress, stdoutBuffers, { it.remaining() }) { stdoutBufferConsumed.receive() }
            } else {
                deliverData(stdoutIngress, _stdout, { it.size })
            }
        }
        delivery.launch { deliverData(stderrIngress, _stderr, { it.size }) }
        delivery.launch { deliverData(extendedDataIngress, _extendedData, { it.second.size }) }
        delivery.initialize(
            abortStreams = {
                inboundDeliveryOpen = false
                stdoutIngress.cancel()
                stdoutBufferIngress.cancel()
                stderrIngress.cancel()
                extendedDataIngress.cancel()
                stdoutBuffers.close()
                stdoutBufferConsumed.close()
                _stdout.close()
                _stderr.close()
                _extendedData.close()
            },
            resources = connection.deliveryResources,
        )
    }

    // AutoCloseable.close() cannot await the owner. Publish the local API close request
    // immediately; packet authorization remains exclusively in the lifecycle machine.
    @Volatile private var closeRequested = false
    override val isOpen: Boolean get() = !closeRequested && lifecycle.isOpen
    override val remoteChannelNumber: Int get() = _remoteChannelNumber
    override val stdout: ReceiveChannel<ByteArray> get() = arrayStdout
    override val stderr: ReceiveChannel<ByteArray> get() = _stderr

    private val _exitInfo = CompletableDeferred<SessionExit?>()
    override val exitInfo: Deferred<SessionExit?> get() = _exitInfo

    /**
     * Called from the connection's packet loop when the server reports how
     * the remote process terminated (RFC 4254 section 6.10). First report
     * wins; the RFC allows at most one of exit-status/exit-signal.
     */
    internal fun receiveExitInfo(info: SessionExit) {
        _exitInfo.complete(info)
    }

    private var ptyGranted = false
    private var obfuscator: KeystrokeObfuscator? = null
    private val obfuscatorMutex = Mutex()
    private var chaffJob: Job? = null
    private val pendingObfuscatedWrites = AtomicInteger(0)
    private val obfuscatedWritesIdle = Channel<Unit>(Channel.CONFLATED)

    /** Called by tests that need to simulate PTY being granted without a real channel request. */
    internal fun markPtyGranted() {
        ptyGranted = true
    }

    private val obfuscationActive: Boolean
        get() = ptyGranted && canSendChaff && obscureKeystrokeTimingIntervalMs > 0

    internal suspend fun onData(data: ByteString) {
        if (bufferedStdout) onData(data.asReadOnlyBuffer()) else onData(data.data())
    }

    internal suspend fun onData(data: ByteArray) {
        if (bufferedStdout) {
            onData(ByteBuffer.wrap(data).asReadOnlyBuffer())
        } else {
            receiveStdout(data.size) { stdoutIngress.trySend(data).isSuccess }
        }
    }

    // Packet plaintext is owned and never recycled while these views are retained.
    internal suspend fun onData(data: ByteBuffer) {
        if (!bufferedStdout) {
            onData(data.toByteArray())
            return
        }
        val view = data.slice().asReadOnlyBuffer()
        receiveStdout(view.remaining()) { stdoutBufferIngress.trySend(view).isSuccess }
    }

    private suspend fun receiveStdout(size: Int, enqueue: () -> Boolean) {
        if (!lifecycle.receiveData { transition ->
                // After a local CLOSE the peer may still send data until its own CLOSE arrives
                // (RFC 4254 5.3). The lifecycle accepts it without DELIVER_DATA: nobody reads it.
                if (SshChannelEffect.DELIVER_DATA !in transition.effects) return@receiveData
                window.consumeLocal(size)
                if (!enqueue()) {
                    throw org.connectbot.sshlib.SshException("Received data for a closed stdout stream")
                }
            }
        ) {
            throw org.connectbot.sshlib.SshException("Received data after EOF or CLOSE on channel $localChannelNumber")
        }
    }

    internal suspend fun onExtendedData(dataType: Int, data: ByteArray) {
        if (!lifecycle.receiveData { transition ->
                if (SshChannelEffect.DELIVER_DATA !in transition.effects) return@receiveData
                window.consumeLocal(data.size)
                if (dataType == 1) {
                    if (stderrIngress.trySend(data).isFailure) {
                        throw org.connectbot.sshlib.SshException("Received data for a closed stderr stream")
                    }
                } else if (extendedDataIngress.trySend(dataType to data).isFailure) {
                    throw org.connectbot.sshlib.SshException("Received data for a closed extended-data stream")
                }
            }
        ) {
            throw org.connectbot.sshlib.SshException("Received extended data after EOF or CLOSE on channel $localChannelNumber")
        }
    }

    private suspend fun <T> deliverData(
        ingress: ReceiveChannel<T>,
        output: Channel<T>,
        sizeOf: (T) -> Int,
        awaitConsumption: suspend () -> Unit = {},
    ) {
        try {
            for (value in ingress) {
                val size = sizeOf(value)
                output.send(value)
                awaitConsumption()
                val adjust = if (size == 0) 0 else window.releaseLocal(size)
                if (inboundDeliveryOpen && adjust > 0) {
                    try {
                        lifecycle.sendWindowAdjust { connection.sendWindowAdjust(_remoteChannelNumber, adjust) }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (failure: Exception) {
                        // A write admitted before remote CLOSE may fail when auto-disconnect
                        // tears down the writer. That obsolete credit must not drop the tail.
                        if (lifecycle.state != SshChannelState.CLOSED || delivery.isAborted) throw failure
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            output.close(failure)
            connection.transportFailed(failure)
        } finally {
            output.close()
        }
    }

    internal suspend fun onWindowAdjust(bytesToAdd: Long) {
        if (!lifecycle.receiveWindowAdjust {
                window.adjustRemote(bytesToAdd)
                logger.debug("Window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
                if (window.remoteRemaining > 0) windowAvailable.trySend(Unit)
            }
        ) {
            throw org.connectbot.sshlib.SshException("Received window adjustment after CLOSE on channel $localChannelNumber")
        }
    }

    internal suspend fun onEof() {
        if (!lifecycle.receiveEof {
                logger.debug("Received EOF on channel $localChannelNumber")
                finishInboundDelivery()
            }
        ) {
            throw org.connectbot.sshlib.SshException("Received duplicate EOF or EOF after CLOSE on channel $localChannelNumber")
        }
    }

    internal suspend fun onClose() {
        if (!lifecycle.receiveClose { transition ->
                closeResources(
                    replyRequired = SshChannelEffect.SEND_CLOSE in transition.effects,
                    preserveInbound = SshChannelEffect.CLOSE_INBOUND_STREAMS in transition.effects,
                    reason = "Received CLOSE",
                )
                if (SshChannelEffect.CLOSE_CHANNEL in transition.effects) {
                    connection.notifyChannelClosed(localChannelNumber)
                }
            }
        ) {
            logger.debug("Received duplicate CLOSE on channel $localChannelNumber")
        }
    }

    private fun finishInboundDelivery() {
        inboundDeliveryOpen = false
        stdoutIngress.close()
        stdoutBufferIngress.close()
        stderrIngress.close()
        extendedDataIngress.close()
        delivery.finish()
    }

    private fun abortInboundDelivery() {
        delivery.abort()
    }

    private suspend fun closeResources(replyRequired: Boolean, preserveInbound: Boolean, reason: String) {
        logger.debug("$reason on channel $localChannelNumber")
        obfuscatorMutex.withLock {
            obfuscator?.stop()
        }
        chaffJob?.cancel()
        if (preserveInbound) {
            finishInboundDelivery()
        } else {
            abortInboundDelivery()
        }
        if (replyRequired) {
            try {
                connection.sendChannelClose(_remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        windowAvailable.close()
        // Channel is gone; if the server never reported an exit, resolve
        // waiters with "unknown" rather than leaving them suspended.
        _exitInfo.complete(null)
    }

    internal suspend fun onDisconnected() {
        lifecycle.disconnect { transition ->
            closeResources(replyRequired = false, preserveInbound = false, reason = "Disconnected")
            if (SshChannelEffect.CLOSE_CHANNEL in transition.effects) {
                connection.notifyChannelClosed(localChannelNumber)
            }
        }
    }

    internal suspend fun receiveRequest(action: suspend () -> Unit): Boolean = lifecycle.receiveRequest { action() }

    override suspend fun write(data: ByteArray) {
        if (obfuscationActive) {
            writeObfuscated(data)
        } else {
            writeDirect(data)
        }
    }

    private suspend fun writeDirect(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            while (window.remoteRemaining <= 0) {
                windowAvailable.receive()
            }
            var admittedBytes = 0
            if (!lifecycle.sendData {
                    // Four packets per admission keep eight concurrent local admissions below
                    // the ordinary writer's 64-packet capacity. Never wait for credit here.
                    repeat(4) {
                        val position = offset + admittedBytes
                        val chunkSize = window.sendChunkSize(data.size - position, maxPacketSize)
                        if (chunkSize == 0) return@sendData
                        connection.sendChannelData(_remoteChannelNumber, data, position, chunkSize)
                        window.consumeRemote(chunkSize)
                        admittedBytes += chunkSize
                    }
                }
            ) {
                throw org.connectbot.sshlib.SshException("Cannot send data after EOF or CLOSE on channel $localChannelNumber")
            }
            offset += admittedBytes
        }
    }

    private suspend fun writeObfuscated(data: ByteArray) {
        pendingObfuscatedWrites.incrementAndGet()
        try {
            val (obs, justStarted) = obfuscatorMutex.withLock {
                val current = obfuscator ?: KeystrokeObfuscator(
                    obscureKeystrokeTimingIntervalMs,
                    clockMs = obfuscatorClockMs,
                    random = obfuscatorRandom,
                ).also {
                    obfuscator = it
                }
                current to current.recordKeystroke()
            }
            startChaffLoopIfNeeded(obs)

            if (!justStarted) {
                val delayMs = obfuscatorMutex.withLock {
                    obs.delayUntilNextSendMs()
                }
                if (delayMs > 0) {
                    delay(delayMs)
                }
                obfuscatorMutex.withLock {
                    obs.advanceInterval()
                }
            }

            writeDirect(data)
        } finally {
            if (pendingObfuscatedWrites.decrementAndGet() == 0) {
                obfuscatedWritesIdle.trySend(Unit)
            }
        }
    }

    private fun startChaffLoopIfNeeded(obs: KeystrokeObfuscator) {
        if (chaffJob?.isActive == true) return
        chaffJob = connectionScope.launch {
            try {
                while (obfuscatorMutex.withLock { obs.isActive() }) {
                    val delayMs = obfuscatorMutex.withLock {
                        obs.delayUntilNextSendMs()
                    }
                    if (delayMs > 0) {
                        delay(delayMs)
                    }
                    val shouldSendChaff = obfuscatorMutex.withLock {
                        if (!obs.isActive()) {
                            false
                        } else if (pendingObfuscatedWrites.get() > 0) {
                            null
                        } else {
                            obs.advanceInterval()
                            true
                        }
                    }
                    when (shouldSendChaff) {
                        true -> connection.sendChaff()
                        false -> break
                        null -> obfuscatedWritesIdle.receiveCatching()
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                // An admitted packet may fail with a transport error after cancellation.
                // Chaff has no caller to receive it; use the normal connection failure path.
                connection.transportFailed(failure)
            }
        }
    }

    override suspend fun read(): ByteArray? = if (bufferedStdout) {
        readBuffer()?.toByteArray()
    } else {
        _stdout.receiveCatching().getOrNull()
    }

    internal suspend fun readBuffer(): ByteBuffer? = if (bufferedStdout) {
        stdoutBuffers.receiveCatching().getOrNull()?.also { stdoutBufferConsumed.trySend(Unit) }
    } else {
        _stdout.receiveCatching().getOrNull()?.let { ByteBuffer.wrap(it).asReadOnlyBuffer() }
    }

    override suspend fun readExtended(): Pair<Int, ByteArray>? = _extendedData.receiveCatching().getOrNull()

    override suspend fun sendEof() {
        lifecycle.sendEof { connection.sendChannelEof(_remoteChannelNumber) }
    }

    private suspend fun performSendRequest(action: suspend () -> CompletableDeferred<Boolean>?): Boolean {
        var pendingReply: CompletableDeferred<Boolean>? = null
        if (!lifecycle.sendRequest { pendingReply = action() }) return false
        val deferred = pendingReply ?: return true
        return try {
            deferred.await()
        } finally {
            connection.finishChannelRequest(deferred)
        }
    }

    override suspend fun resizeTerminal(
        widthChars: Int,
        heightRows: Int,
        widthPixels: Int,
        heightPixels: Int,
    ): Boolean = performSendRequest {
        logger.debug("Resizing terminal: ${widthChars}x$heightRows")
        connection.beginChannelRequest(
            _remoteChannelNumber,
            "window-change",
            wantReply = false,
        ) { msg ->
            val windowChange = ChannelRequestWindowChange()
            windowChange.setTerminalWidth(widthChars.toLong())
            windowChange.setTerminalHeight(heightRows.toLong())
            windowChange.setTerminalWidthPixels(widthPixels.toLong())
            windowChange.setTerminalHeightPixels(heightPixels.toLong())
            windowChange._check()
            msg.setRequestSpecificFields(windowChange)
        }
    }

    override suspend fun requestPty(
        terminalType: String,
        widthChars: Int,
        heightRows: Int,
        widthPixels: Int,
        heightPixels: Int,
        terminalModes: ByteArray,
    ): Boolean {
        val granted = performSendRequest {
            logger.debug("Requesting PTY: $terminalType ${widthChars}x$heightRows")
            val pendingReply = connection.beginChannelRequest(
                _remoteChannelNumber,
                "pty-req",
                wantReply = true,
            ) { msg ->
                val ptyReq = ChannelRequestPtyReq()

                val termBytes = ByteString()
                termBytes.setLenData(terminalType.length.toLong())
                termBytes.setData(terminalType.toByteArray(Charsets.US_ASCII))
                termBytes._check()
                ptyReq.setTerm(termBytes)

                ptyReq.setTerminalWidth(widthChars.toLong())
                ptyReq.setTerminalHeight(heightRows.toLong())
                ptyReq.setTerminalWidthPixels(widthPixels.toLong())
                ptyReq.setTerminalHeightPixels(heightPixels.toLong())

                val modeString = ByteString()
                modeString.setLenData(terminalModes.size.toLong())
                modeString.setData(terminalModes)
                modeString._check()
                ptyReq.setTerminalModes(modeString)

                ptyReq._check()
                msg.setRequestSpecificFields(ptyReq)
            }
            pendingReply
        }
        if (granted) ptyGranted = true
        return granted
    }

    override suspend fun requestEnv(name: String, value: String): Boolean = sendEnv(name, value, wantReply = true)

    internal suspend fun sendEnv(name: String, value: String, wantReply: Boolean): Boolean {
        if ('\u0000' in name || '\u0000' in value) return false
        return performSendRequest {
            connection.beginChannelRequest(_remoteChannelNumber, "env", wantReply) { msg ->
                val env = ChannelRequestEnv().apply {
                    setVariableName(createByteString(name.toByteArray(Charsets.UTF_8)))
                    setVariableValue(createByteString(value.toByteArray(Charsets.UTF_8)))
                    _check()
                }
                msg.setRequestSpecificFields(env)
            }
        }
    }

    override suspend fun requestShell(): Boolean = performSendRequest {
        logger.debug("Requesting shell on channel $localChannelNumber")
        connection.beginChannelRequest(
            _remoteChannelNumber,
            "shell",
            wantReply = true,
        ) { msg ->
            val shellReq = ChannelRequestShell()
            shellReq._check()
            msg.setRequestSpecificFields(shellReq)
        }
    }

    override suspend fun requestExec(command: String): Boolean = performSendRequest {
        logger.debug("Requesting exec on channel $localChannelNumber: $command")
        connection.beginChannelRequest(
            _remoteChannelNumber,
            "exec",
            wantReply = true,
        ) { msg ->
            val execReq = ChannelRequestExec()
            val cmdString = ByteString()
            cmdString.setLenData(command.toByteArray(Charsets.UTF_8).size.toLong())
            cmdString.setData(command.toByteArray(Charsets.UTF_8))
            cmdString._check()
            execReq.setCommand(cmdString)
            execReq._check()
            msg.setRequestSpecificFields(execReq)
        }
    }

    override suspend fun requestSubsystem(name: String): Boolean = performSendRequest {
        logger.debug("Requesting subsystem on channel $localChannelNumber: $name")
        connection.beginChannelRequest(
            _remoteChannelNumber,
            "subsystem",
            wantReply = true,
        ) { msg ->
            val subsysReq = ChannelRequestSubsystem()
            val nameString = ByteString()
            nameString.setLenData(name.toByteArray(Charsets.US_ASCII).size.toLong())
            nameString.setData(name.toByteArray(Charsets.US_ASCII))
            nameString._check()
            subsysReq.setSubsystemName(nameString)
            subsysReq._check()
            msg.setRequestSpecificFields(subsysReq)
        }
    }

    override fun close() {
        closeRequested = true
        connectionScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                lifecycle.sendClose { transition ->
                    logger.debug("Closing channel $localChannelNumber")
                    obfuscatorMutex.withLock { obfuscator?.stop() }
                    chaffJob?.cancel()
                    abortInboundDelivery()
                    windowAvailable.close()
                    _exitInfo.complete(null)
                    try {
                        connection.sendChannelClose(_remoteChannelNumber)
                    } catch (e: Exception) {
                        logger.debug("Failed to send CHANNEL_CLOSE", e)
                    }
                    if (SshChannelEffect.CLOSE_CHANNEL in transition.effects) {
                        connection.notifyChannelClosed(localChannelNumber)
                    }
                }
            } catch (e: Exception) {
                logger.debug("Channel close ended with the connection", e)
            }
            // A remote CLOSE makes sendClose a no-op, but close() still owns
            // releasing any unread delivery job retained for graceful draining.
            abortInboundDelivery()
            windowAvailable.close()
            _exitInfo.complete(null)
        }.invokeOnCompletion {
            abortInboundDelivery()
            windowAvailable.close()
            _exitInfo.complete(null)
        }
    }
}
