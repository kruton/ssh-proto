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

package org.connectbot.sshlib.client.sftp

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.SftpAttributes
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpDirectoryEntry
import org.connectbot.sshlib.SftpFileHandle
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SftpStatusCode
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.Timeouts
import org.connectbot.sshlib.client.asReadOnlyBuffer
import org.connectbot.sshlib.kaitaiParseFailureOrNull
import org.connectbot.sshlib.protocol.ByteString
import org.connectbot.sshlib.protocol.SftpAcceptedTransition
import org.connectbot.sshlib.protocol.SftpCopyData
import org.connectbot.sshlib.protocol.SftpState
import org.connectbot.sshlib.protocol.SftpStateMachine
import org.connectbot.sshlib.protocol.SftpVersion
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean

private typealias SftpTransition = suspend (suspend (SftpAcceptedTransition) -> Unit) -> Boolean

/**
 * Internal implementation of [SftpClient].
 *
 * SFTP message types (draft-ietf-secsh-filexfer-02 section 3):
 */
internal class SftpClientImpl private constructor(
    private val session: SshSession,
    private val dispatcher: SftpDispatcher,
    private val readJob: Job,
    override val protocolVersion: Int,
    private val stateMachine: SftpStateMachine,
    override val extensions: Set<String>,
    private val requestTimeoutMs: Long,
) : SftpClient {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val closed = AtomicBoolean()

    override val isOpen: Boolean get() = !closed.get() && session.isOpen && stateMachine.state == SftpState.READY

    // --- File I/O ---

    override suspend fun open(path: String, flags: Set<SftpOpenFlag>, attrs: SftpAttributes): SftpResult<SftpFileHandle> {
        val pflags = flags.fold(0) { acc, flag -> acc or flag.value }
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)

        val payload = ByteBuffer.allocate(4 + pathBytes.size + 4 + attrsBytes.size)
        putString(payload, pathBytes)
        payload.putInt(pflags)
        payload.put(attrsBytes)

        return dispatchRequest(SSH_FXP_OPEN, payload.array(), stateMachine::openFile) { response ->
            when (response.type) {
                SSH_FXP_HANDLE -> SftpResult.Success(SftpFileHandle(extractString(response.payloadBuffer)))
                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for OPEN")
            }
        }
    }

    override suspend fun close(handle: SftpFileHandle): SftpResult<Unit> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_CLOSE, payload.array(), stateMachine::closeHandle) { response ->
            if (response.type == SSH_FXP_STATUS) {
                val status = decodeStatus(response.payloadBuffer)
                if (status == SftpStatusCode.OK) {
                    SftpResult.Success(Unit)
                } else {
                    decodeStatusError(response.payloadBuffer)
                }
            } else {
                SftpResult.Success(Unit)
            }
        }
    }

    override suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): SftpResult<ByteArray?> = readData(handle, offset, length) { it.data() }

    internal suspend fun readBuffer(handle: SftpFileHandle, offset: Long, length: Int): SftpResult<ByteBuffer?> = readData(handle, offset, length, ByteString::asReadOnlyBuffer)

    private suspend fun <T> readData(handle: SftpFileHandle, offset: Long, length: Int, decode: (ByteString) -> T): SftpResult<T?> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4)
        putString(payload, handle.handle)
        payload.putLong(offset)
        payload.putInt(length)

        return dispatchRequest(SSH_FXP_READ, payload.array(), stateMachine::readFile) { response ->
            when (response.type) {
                SSH_FXP_DATA -> {
                    // Use the schema's checked byte-string parser rather than another wire reader.
                    val data = ByteString(ByteBufferKaitaiStream(response.payloadBuffer))
                    try {
                        data._read()
                    } catch (failure: RuntimeException) {
                        throw SftpDecodeException(failure.message ?: "Malformed SFTP DATA")
                    }
                    SftpResult.Success(decode(data))
                }

                SSH_FXP_STATUS -> {
                    val status = decodeStatus(response.payloadBuffer)
                    if (status == SftpStatusCode.EOF) {
                        SftpResult.Success(null)
                    } else {
                        decodeStatusError(response.payloadBuffer)
                    }
                }

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READ")
            }
        }
    }

    override suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray): SftpResult<Unit> {
        val header = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4)
        putString(header, handle.handle)
        header.putLong(offset)
        header.putInt(data.size)

        // Snapshot header and data once into the complete owned frame at queue admission.
        return dispatchStatusRequest(SSH_FXP_WRITE, listOf(header.array(), data), stateMachine::writeFile)
    }

    // --- Stat operations ---

    override suspend fun stat(path: String): SftpResult<SftpAttributes> = statRequest(SSH_FXP_STAT, path)

    override suspend fun lstat(path: String): SftpResult<SftpAttributes> = statRequest(SSH_FXP_LSTAT, path)

    private suspend fun statRequest(type: Int, path: String): SftpResult<SftpAttributes> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(type, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_ATTRS -> SftpResult.Success(SftpFileAttributes.decode(response.payloadBuffer))
                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for STAT")
            }
        }
    }

    override suspend fun fstat(handle: SftpFileHandle): SftpResult<SftpAttributes> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_FSTAT, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_ATTRS -> SftpResult.Success(SftpFileAttributes.decode(response.payloadBuffer))
                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for FSTAT")
            }
        }
    }

    override suspend fun setstat(path: String, attrs: SftpAttributes): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_SETSTAT, payload.array())
    }

    override suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes): SftpResult<Unit> {
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + handle.handle.size + attrsBytes.size)
        putString(payload, handle.handle)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_FSETSTAT, payload.array())
    }

    // --- Directory operations ---

    override suspend fun opendir(path: String): SftpResult<SftpFileHandle> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_OPENDIR, payload.array(), stateMachine::openDir) { response ->
            when (response.type) {
                SSH_FXP_HANDLE -> SftpResult.Success(SftpFileHandle(extractString(response.payloadBuffer)))
                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for OPENDIR")
            }
        }
    }

    override suspend fun readdir(handle: SftpFileHandle): SftpResult<List<SftpDirectoryEntry>?> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_READDIR, payload.array(), stateMachine::readDir) { response ->
            when (response.type) {
                SSH_FXP_NAME -> SftpResult.Success(decodeName(response.payloadBuffer))

                SSH_FXP_STATUS -> {
                    val status = decodeStatus(response.payloadBuffer)
                    if (status == SftpStatusCode.EOF) {
                        SftpResult.Success(null)
                    } else {
                        decodeStatusError(response.payloadBuffer)
                    }
                }

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READDIR")
            }
        }
    }

    override suspend fun mkdir(path: String, attrs: SftpAttributes): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_MKDIR, payload.array())
    }

    override suspend fun rmdir(path: String): SftpResult<Unit> = simplePathRequest(SSH_FXP_RMDIR, path)

    // --- File management ---

    override suspend fun remove(path: String): SftpResult<Unit> = simplePathRequest(SSH_FXP_REMOVE, path)

    override suspend fun rename(oldPath: String, newPath: String): SftpResult<Unit> {
        val oldBytes = oldPath.toByteArray(StandardCharsets.UTF_8)
        val newBytes = newPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + oldBytes.size + 4 + newBytes.size)
        putString(payload, oldBytes)
        putString(payload, newBytes)

        return dispatchStatusRequest(SSH_FXP_RENAME, payload.array())
    }

    // --- Server-side data copy (OpenSSH extension) ---

    override suspend fun copyData(
        srcHandle: SftpFileHandle,
        srcOffset: Long,
        length: Long,
        dstHandle: SftpFileHandle,
        dstOffset: Long,
        timeoutMs: Long,
    ): SftpResult<Unit> {
        if (srcOffset < 0 || length < 0 || dstOffset < 0 || timeoutMs < 0) {
            return SftpResult.ProtocolError("Copy offsets, length, and timeout must be non-negative")
        }
        val payload = SftpCopyData().apply {
            setExtensionName(createByteString(EXT_COPY_DATA.toByteArray(StandardCharsets.US_ASCII)))
            setSrcHandle(createByteString(srcHandle.handle))
            setSrcOffset(srcOffset)
            setLength(length)
            setDstHandle(createByteString(dstHandle.handle))
            setDstOffset(dstOffset)
            _check()
        }
        return dispatchStatusRequest(SSH_FXP_EXTENDED, payload.toByteArray(), timeoutMs = timeoutMs)
    }

    // --- Path operations ---

    override suspend fun realpath(path: String): SftpResult<String> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_REALPATH, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_NAME -> {
                    val entries = decodeName(response.payloadBuffer)
                    val filename = entries.firstOrNull()?.filename
                    if (filename != null) {
                        SftpResult.Success(filename)
                    } else {
                        SftpResult.ProtocolError("REALPATH returned empty NAME")
                    }
                }

                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for REALPATH")
            }
        }
    }

    override suspend fun readlink(path: String): SftpResult<String> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_READLINK, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_NAME -> {
                    val entries = decodeName(response.payloadBuffer)
                    val filename = entries.firstOrNull()?.filename
                    if (filename != null) {
                        SftpResult.Success(filename)
                    } else {
                        SftpResult.ProtocolError("READLINK returned empty NAME")
                    }
                }

                SSH_FXP_STATUS -> decodeStatusError(response.payloadBuffer)

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READLINK")
            }
        }
    }

    override suspend fun symlink(targetPath: String, linkPath: String): SftpResult<Unit> {
        val linkBytes = linkPath.toByteArray(StandardCharsets.UTF_8)
        val targetBytes = targetPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + linkBytes.size + 4 + targetBytes.size)
        putString(payload, linkBytes)
        putString(payload, targetBytes)

        return dispatchStatusRequest(SSH_FXP_SYMLINK, payload.array())
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runBlocking {
            stateMachine.disconnect { }
        }
        dispatcher.stop()
        session.close()
    }

    // --- Internal helpers ---

    /**
     * Send a request and map the response.
     */
    private suspend fun <T> dispatchRequest(
        type: Int,
        payload: ByteArray,
        transition: SftpTransition = stateMachine::request,
        timeoutMs: Long = requestTimeoutMs,
        map: (SftpRawPacket) -> SftpResult<T>,
    ): SftpResult<T> = dispatchRequest(type, listOf(payload), transition, timeoutMs, map)

    private suspend fun <T> dispatchRequest(
        type: Int,
        payload: List<ByteArray>,
        transition: SftpTransition = stateMachine::request,
        timeoutMs: Long = requestTimeoutMs,
        map: (SftpRawPacket) -> SftpResult<T>,
    ): SftpResult<T> = when (val result = dispatcher.request(type, payload, timeoutMs) { action -> transition { action() } }) {
        is SftpResult.Success -> try {
            map(result.value)
        } catch (e: SftpDecodeException) {
            SftpResult.ProtocolError(e.message ?: "Malformed SFTP response")
        }

        is SftpResult.ServerError -> result

        is SftpResult.ProtocolError -> result

        is SftpResult.IoError -> result
    }

    /**
     * Send a request that expects SSH_FXP_STATUS with OK.
     */
    private suspend fun dispatchStatusRequest(
        type: Int,
        payload: ByteArray,
        transition: SftpTransition = stateMachine::request,
        timeoutMs: Long = requestTimeoutMs,
    ): SftpResult<Unit> = dispatchStatusRequest(type, listOf(payload), transition, timeoutMs)

    private suspend fun dispatchStatusRequest(
        type: Int,
        payload: List<ByteArray>,
        transition: SftpTransition = stateMachine::request,
        timeoutMs: Long = requestTimeoutMs,
    ): SftpResult<Unit> = dispatchRequest(type, payload, transition, timeoutMs) { response ->
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payloadBuffer)
            if (status == SftpStatusCode.OK) {
                SftpResult.Success(Unit)
            } else {
                decodeStatusError(response.payloadBuffer)
            }
        } else {
            SftpResult.Success(Unit)
        }
    }

    private suspend fun simplePathRequest(type: Int, path: String): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchStatusRequest(type, payload.array())
    }

    companion object {
        private val logger = LoggerFactory.getLogger(SftpClientImpl::class.java)

        // SFTP message types
        private const val SSH_FXP_INIT = 1
        private const val SSH_FXP_VERSION = 2
        private const val SSH_FXP_OPEN = 3
        private const val SSH_FXP_CLOSE = 4
        private const val SSH_FXP_READ = 5
        private const val SSH_FXP_WRITE = 6
        private const val SSH_FXP_LSTAT = 7
        private const val SSH_FXP_FSTAT = 8
        private const val SSH_FXP_SETSTAT = 9
        private const val SSH_FXP_FSETSTAT = 10
        private const val SSH_FXP_OPENDIR = 11
        private const val SSH_FXP_READDIR = 12
        private const val SSH_FXP_REMOVE = 13
        private const val SSH_FXP_MKDIR = 14
        private const val SSH_FXP_RMDIR = 15
        private const val SSH_FXP_REALPATH = 16
        private const val SSH_FXP_STAT = 17
        private const val SSH_FXP_RENAME = 18
        private const val SSH_FXP_READLINK = 19
        private const val SSH_FXP_SYMLINK = 20

        private const val SSH_FXP_STATUS = 101
        private const val SSH_FXP_HANDLE = 102
        private const val SSH_FXP_DATA = 103
        private const val SSH_FXP_NAME = 104
        private const val SSH_FXP_ATTRS = 105

        private const val SSH_FXP_EXTENDED = 200

        private const val SFTP_VERSION = 3

        /** OpenSSH SFTP extension (added in OpenSSH 9.0) for server-side data copy. */
        private const val EXT_COPY_DATA = "copy-data"

        /**
         * Create an SFTP client by performing the INIT/VERSION handshake.
         */
        suspend fun create(
            session: SshSession,
            requestTimeoutMs: Long = Timeouts.DEFAULT_SFTP_REQUEST_TIMEOUT_MS,
        ): SftpResult<SftpClient> = create(session, SftpPacketIO(session), requestTimeoutMs = requestTimeoutMs)

        internal suspend fun create(
            session: SshSession,
            packetIO: SftpPacketTransport,
            readScope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
            requestTimeoutMs: Long = Timeouts.DEFAULT_SFTP_REQUEST_TIMEOUT_MS,
        ): SftpResult<SftpClient> {
            val stateMachine = SftpStateMachine()
            val dispatcher = SftpDispatcher(packetIO, stateMachine)

            // Send SSH_FXP_INIT
            val initPayload = ByteBuffer.allocate(4)
            initPayload.putInt(SFTP_VERSION)
            val initResult = if (stateMachine.sendInit {}) {
                dispatcher.writeRaw(SSH_FXP_INIT, initPayload.array())
            } else {
                return SftpResult.ProtocolError("Failed to admit SFTP INIT")
            }
            when (val w = initResult) {
                is SftpResult.Success -> {}
                is SftpResult.ServerError -> return w
                is SftpResult.ProtocolError -> return w
                is SftpResult.IoError -> return w
            }

            // Read SSH_FXP_VERSION
            val versionPacket = when (val r = dispatcher.readRaw()) {
                is SftpResult.Success -> r.value
                is SftpResult.ServerError -> return r
                is SftpResult.ProtocolError -> return r
                is SftpResult.IoError -> return r
            }
            if (versionPacket.type != SSH_FXP_VERSION) {
                return SftpResult.ProtocolError(
                    "Expected SSH_FXP_VERSION (2), got ${versionPacket.type}",
                )
            }
            val version = try {
                SftpVersion(ByteBufferKaitaiStream(versionPacket.payloadBuffer)).apply { _read() }
            } catch (e: Exception) {
                if (e.kaitaiParseFailureOrNull() == null) throw e
                return SftpResult.ProtocolError("Malformed SSH_FXP_VERSION payload")
            }
            val negotiatedVersion = minOf(SFTP_VERSION.toLong(), version.version()).toInt()
            logger.info("SFTP version negotiated: {} (server: {})", negotiatedVersion, version.version())
            val extensions = version.extensions().map { String(it.name().data(), StandardCharsets.UTF_8) }.toSet()
            if (extensions.isNotEmpty()) {
                logger.info("SFTP server extensions: {}", extensions)
            }

            // Start the background read loop
            val readJob = dispatcher.startReadLoop(readScope)

            return SftpResult.Success(SftpClientImpl(session, dispatcher, readJob, negotiatedVersion, stateMachine, extensions, requestTimeoutMs))
        }

        // --- Wire format helpers ---

        /** Write a length-prefixed string/byte array to a ByteBuffer. */
        private fun putString(buf: ByteBuffer, data: ByteArray) {
            buf.putInt(data.size)
            buf.put(data)
        }

        /** Read a length-prefixed string/byte array from a ByteBuffer. */
        private fun extractString(buf: ByteBuffer): ByteArray = SftpDecoder.readString(buf, "SFTP string")

        /** Decode a STATUS response to get the status code. */
        private fun decodeStatus(payload: ByteBuffer): SftpStatusCode {
            if (payload.remaining() < 4) return SftpStatusCode.FAILURE
            val code = payload.duplicate().int
            return SftpStatusCode.fromCode(code)
        }

        /** Decode a STATUS response into an [SftpResult.ServerError]. */
        private fun decodeStatusError(payload: ByteBuffer): SftpResult.ServerError {
            val buf = payload.duplicate()
            val code = if (buf.remaining() >= 4) SftpDecoder.readInt(buf, "status code") else 4
            val statusCode = SftpStatusCode.fromCode(code)
            val message = if (buf.remaining() >= 4) {
                val msgBytes = extractString(buf)
                String(msgBytes, StandardCharsets.UTF_8)
            } else {
                statusCode.name
            }
            return SftpResult.ServerError(statusCode, message)
        }

        /** Decode a NAME response (used by readdir, realpath, readlink). */
        private fun decodeName(payload: ByteBuffer): List<SftpDirectoryEntry> {
            val buf = payload.duplicate()
            val count = SftpDecoder.readCount(buf, "NAME entry count", minimumElementSize = 12)
            val entries = ArrayList<SftpDirectoryEntry>(count)
            repeat(count) {
                val filename = String(extractString(buf), StandardCharsets.UTF_8)
                val longname = String(extractString(buf), StandardCharsets.UTF_8)
                val attrs = SftpFileAttributes.decode(buf)
                entries.add(SftpDirectoryEntry(filename, longname, attrs))
            }
            return entries
        }
    }
}
