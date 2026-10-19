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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.protocol.AsciiString

/**
 * Trust host certificates issued by one of [trustedAuthorities] for [hostname].
 * The hostname is the logical destination name, including with a custom transport,
 * without brackets or a port. CA keys and optional revocations are snapshots.
 */
class CertificateAuthorityVerifier @JvmOverloads constructor(
    private val hostname: String,
    trustedAuthorities: List<PublicKey>,
    private val revocations: SshKeyRevocationList? = null,
) : HostKeyVerifier {
    private val authorities = trustedAuthorities.map { it.copy(encoded = it.encoded.copyOf()) }

    override suspend fun verify(key: PublicKey): Boolean = verifyHostCertificate(key, hostname, authorities, revocations)
}

internal fun verifyHostCertificate(
    key: PublicKey,
    hostname: String,
    authorities: List<PublicKey>,
    revocations: SshKeyRevocationList? = null,
    now: Long = System.currentTimeMillis() / 1000,
): Boolean = try {
    val certificate = SshCertificate.decode(key.encoded)
    key.type == certificate.algorithmName && certificate.type == SshCertificate.Type.HOST &&
        now >= 0 && now.toULong() >= certificate.validAfter && now.toULong() < certificate.validBefore &&
        certificate.principals.any { matchHostPattern(it, hostname) } && certificate.criticalOptions.isEmpty() &&
        certificate.signatureKey in authorities && revocations?.isRevoked(key) != true &&
        validCertificateSignature(certificate)
} catch (_: Exception) {
    false
}

internal fun validCertificateSignature(certificate: SshCertificate): Boolean {
    val algorithm = AsciiString(ByteBufferKaitaiStream(certificate.signature)).apply { _read() }.value()
    if (algorithm !in setOf("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512")) return false
    return SignatureVerifier.verifyWithKeyType(certificate.signatureKey.encoded, certificate.signature, certificate.signedBytes)
}

/** Greedy glob matching avoids regex backtracking on peer-supplied certificate principals. */
internal fun matchHostPattern(pattern: String, hostname: String): Boolean {
    if (pattern.startsWith("|1|")) return false
    var patternIndex = 0
    var hostIndex = 0
    var starIndex = -1
    var retryIndex = 0
    while (hostIndex < hostname.length) {
        when {
            patternIndex < pattern.length &&
                (pattern[patternIndex] == '?' || (pattern[patternIndex] != '*' && pattern[patternIndex].equals(hostname[hostIndex], ignoreCase = true))) -> {
                patternIndex++
                hostIndex++
            }

            patternIndex < pattern.length && pattern[patternIndex] == '*' -> {
                starIndex = patternIndex++
                retryIndex = hostIndex
            }

            starIndex >= 0 -> {
                patternIndex = starIndex + 1
                hostIndex = ++retryIndex
            }

            else -> return false
        }
    }
    while (patternIndex < pattern.length && pattern[patternIndex] == '*') patternIndex++
    return patternIndex == pattern.length
}

internal fun matchesHostPatterns(patterns: List<String>, hostname: String): Boolean = patterns.none { it.startsWith("!") && matchHostPattern(it.drop(1), hostname) } &&
    patterns.any { !it.startsWith("!") && matchHostPattern(it, hostname) }
