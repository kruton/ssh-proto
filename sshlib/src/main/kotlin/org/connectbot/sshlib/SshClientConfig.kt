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

package org.connectbot.sshlib

import org.connectbot.sshlib.crypto.CipherEntry
import org.connectbot.sshlib.crypto.CompressionEntry
import org.connectbot.sshlib.crypto.KexEntry
import org.connectbot.sshlib.crypto.MacEntry
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.withCertificateHostKeys
import org.connectbot.sshlib.transport.IpVersion
import org.connectbot.sshlib.transport.KtorTcpTransportFactory
import org.connectbot.sshlib.transport.TransportFactory
import java.util.Collections

/**
 * Configuration for SSH client connections.
 *
 * Use the builder DSL to create a configuration:
 * ```kotlin
 * // Simple TCP connection (uses KtorTcpTransport by default)
 * val config = SshClientConfig {
 *     host = "example.com"
 *     port = 22
 *     clientVersion = "SSH-2.0-MyClient_1.0"
 * }
 *
 * // Custom transport
 * val config = SshClientConfig {
 *     transportFactory = MyCustomTransportFactory()
 *     clientVersion = "SSH-2.0-MyClient_1.0"
 * }
 * ```
 */
class SshClientConfig private constructor(
    val transportFactory: TransportFactory,
    val clientVersion: String,
    val hostKeyVerifier: HostKeyVerifier,
    val kexAlgorithms: String,
    val hostKeyAlgorithms: String,
    val encryptionAlgorithms: String,
    val macAlgorithms: String,
    internal val compressionAlgorithms: String,
    val preferPasswordAuth: Boolean,
    val rekeyIntervalMs: Long,
    val rekeyBytesLimit: Long,
    val obscureKeystrokeTimingIntervalMs: Long,
    val autoDisconnectOnLastChannelClose: Boolean,
    val sessionWindowSize: Int,
    val sftpWindowSize: Int,
    val environment: Map<String, String>,
    val keepAliveIntervalMs: Long,
    val pubkeyAlgorithms: String?,
    val cryptoPolicy: SshCryptoPolicy?,
    val algorithmWarningHandler: ((AlgorithmPolicyWarning) -> Unit)?,
) {
    class Builder {
        /**
         * Hostname for TCP connections. Used with default KtorTcpTransport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var host: String = ""

        /**
         * Port for TCP connections. Used with default KtorTcpTransport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var port: Int = 22

        /**
         * Client version string sent during SSH handshake.
         */
        var clientVersion: String = "SSH-2.0-CBSSH_1.0"

        /**
         * Host key verifier.
         */
        var hostKeyVerifier: HostKeyVerifier? = null

        /**
         * Custom transport factory. If not set, uses [KtorTcpTransportFactory]
         * with [host], [port], and [ipVersion].
         */
        var transportFactory: TransportFactory? = null

        /**
         * IP version preference for the default TCP transport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var ipVersion: IpVersion = IpVersion.AUTO

        var kexAlgorithms: String = KexEntry.defaultString
        var hostKeyAlgorithms: String = SignatureEntry.defaultString
        private var certificateHostKeysEnabled: Boolean = false

        /**
         * Prepend certificate counterparts of configured host key algorithms at build time.
         * Assignment order does not matter. Raw keys remain as fallback; CA trust must be
         * configured in [hostKeyVerifier]. Calling with false disables automatic additions.
         */
        @JvmOverloads
        fun enableCertificateHostKeys(enabled: Boolean = true): Builder = apply {
            certificateHostKeysEnabled = enabled
        }

        var encryptionAlgorithms: String = CipherEntry.defaultString
        var macAlgorithms: String = MacEntry.defaultString

        /** Null preserves the historical authentication behavior for existing callers. */
        var pubkeyAlgorithms: String? = null
        private var policy: SshCryptoPolicy? = null

        /** Called when authentication skips a key because of policy. Must return promptly. */
        var algorithmWarningHandler: ((AlgorithmPolicyWarning) -> Unit)? = null

        /**
         * Apply a freshly resolved [SshCryptoPolicy] before any explicit preference reordering.
         * Resolve after installing platform crypto providers. The policy controls all algorithm categories,
         * including public-key authentication, and enforces RSA/DH minimum key sizes.
         * See [SshCryptoPolicy] for presets, custom expression syntax, and capability warnings.
         *
         * Example: `cryptoPolicy(SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE))`.
         */
        fun cryptoPolicy(value: SshCryptoPolicy): Builder = apply {
            policy = value
            kexAlgorithms = value.algorithms.getValue(AlgorithmCategory.KEX).joinToString(",") + ",kex-strict-c-v00@openssh.com,ext-info-c"
            hostKeyAlgorithms = value.algorithms.getValue(AlgorithmCategory.HOST_KEY).joinToString(",")
            encryptionAlgorithms = value.algorithms.getValue(AlgorithmCategory.CIPHER).joinToString(",")
            macAlgorithms = value.algorithms.getValue(AlgorithmCategory.MAC).joinToString(",")
            pubkeyAlgorithms = value.algorithms.getValue(AlgorithmCategory.PUBKEY).joinToString(",")
        }

        /**
         * Enable zlib compression. When true, the client offers
         * `zlib@openssh.com,zlib,none`; when false, only `none`.
         */
        var enableCompression: Boolean = false

        /**
         * When true, prefer `password` over `keyboard-interactive` when both are available.
         * By default, `keyboard-interactive` is preferred.
         */
        var preferPasswordAuth: Boolean = false

        /**
         * Re-key after this many milliseconds. Default: 1 hour.
         */
        var rekeyIntervalMs: Long = 3_600_000L

        /**
         * Re-key after this many wire bytes (sent or received). Default: 1 GB.
         */
        var rekeyBytesLimit: Long = 1_073_741_824L

        /**
         * Quantize outbound keystroke packet timing to this interval (milliseconds) to mask
         * inter-keystroke timing patterns. Requires a PTY session and server support for
         * `ping@openssh.com`. Set to 0 to disable.
         */
        var obscureKeystrokeTimingIntervalMs: Long = 20L

        /**
         * Whether to automatically disconnect the SSH connection when the last channel is closed.
         */
        var autoDisconnectOnLastChannelClose: Boolean = true

        /**
         * Receive window, in bytes, for shells, commands and manually opened subsystems.
         * SFTP channels opened by [SshClient.openSftp] use [sftpWindowSize]. A channel moves at most
         * one window of data per network round trip, so a larger window speeds up bulk transfers
         * on slower links. Each channel may buffer up to this much unread data. Default: 2 MiB.
         * Reduce this for sessions with tighter memory limits.
         */
        var sessionWindowSize: Int = 2 * 1024 * 1024

        /**
         * Receive window, in bytes, for channels opened by [SshClient.openSftp].
         * Default: 8 MiB, to sustain bulk downloads on higher-latency links.
         * Each channel may buffer up to this much unread data; reduce this for tighter memory limits.
         */
        var sftpWindowSize: Int = 8 * 1024 * 1024

        /**
         * Environment variables sent before each session starts, including SFTP.
         * Servers may ignore variables not allowed by their policy (OpenSSH AcceptEnv).
         * Names and values use UTF-8 and must not contain NUL. Only supplied variables are sent.
         */
        var environment: Map<String, String> = emptyMap()

        /**
         * Send an SSH_MSG_IGNORE heartbeat every N milliseconds to keep the
         * connection alive across NAT/VPN/firewall idle timeouts.
         *
         * The message is a single empty payload that the server silently ignores
         * (RFC 4253 §11.2). It does NOT expect a response — this is purely to
         * prevent intermediaries from killing the TCP connection during idle.
         *
         * Recommended for long-lived connections behind aggressive firewalls.
         * Set to 0 to disable (default).
         *
         * Common values: 15000 (15s, sshj default), 30000 (30s).
         */
        var keepAliveIntervalMs: Long = 0L

        fun build(): SshClientConfig {
            val environmentSnapshot = LinkedHashMap(environment)
            require(environmentSnapshot.all { (name, value) -> '\u0000' !in name && '\u0000' !in value }) {
                "Environment names and values must not contain NUL"
            }
            val factory = transportFactory ?: run {
                require(host.isNotBlank()) { "Host must be specified when using default TCP transport" }
                require(port in 1..65535) { "Port must be between 1 and 65535" }
                KtorTcpTransportFactory(host, port, ipVersion)
            }
            require(obscureKeystrokeTimingIntervalMs >= 0) {
                "obscureKeystrokeTimingIntervalMs must be non-negative"
            }
            require(sessionWindowSize > 0) { "sessionWindowSize must be positive" }
            require(sftpWindowSize > 0) { "sftpWindowSize must be positive" }
            require(keepAliveIntervalMs >= 0) {
                "keepAliveIntervalMs must be non-negative"
            }

            policy?.let { selected ->
                val configured = mapOf(
                    AlgorithmCategory.KEX to kexAlgorithms.split(',').filterNot { it in listOf("kex-strict-c-v00@openssh.com", "ext-info-c") },
                    AlgorithmCategory.CIPHER to encryptionAlgorithms.split(','),
                    AlgorithmCategory.MAC to macAlgorithms.split(','),
                    AlgorithmCategory.HOST_KEY to hostKeyAlgorithms.split(','),
                    AlgorithmCategory.PUBKEY to pubkeyAlgorithms.orEmpty().split(','),
                )
                configured.forEach { (category, names) ->
                    if (names.isEmpty() || names.any { it.isEmpty() || it !in selected.algorithms.getValue(category) }) throw SshException("Configured $category algorithms violate cryptographic policy")
                }
            }
            val verifier = hostKeyVerifier
            requireNotNull(verifier) { "hostKeyVerifier must be set" }
            val compressionAlgorithms = if (enableCompression) {
                CompressionEntry.enabledString
            } else {
                CompressionEntry.defaultString
            }

            return SshClientConfig(
                factory,
                clientVersion,
                verifier,
                kexAlgorithms,
                if (certificateHostKeysEnabled) withCertificateHostKeys(hostKeyAlgorithms) else hostKeyAlgorithms,
                encryptionAlgorithms,
                macAlgorithms,
                compressionAlgorithms,
                preferPasswordAuth,
                rekeyIntervalMs,
                rekeyBytesLimit,
                obscureKeystrokeTimingIntervalMs,
                autoDisconnectOnLastChannelClose,
                sessionWindowSize,
                sftpWindowSize,
                Collections.unmodifiableMap(environmentSnapshot),
                keepAliveIntervalMs,
                pubkeyAlgorithms,
                policy,
                algorithmWarningHandler,
            )
        }
    }

    companion object {
        operator fun invoke(block: Builder.() -> Unit): SshClientConfig = Builder().apply(block).build()
    }
}
