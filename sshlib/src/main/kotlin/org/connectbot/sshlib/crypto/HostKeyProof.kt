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

package org.connectbot.sshlib.crypto

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.protocol.GlobalRequestResponseHostkeysProve00Openssh
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature

internal const val HOSTKEYS_PROVE = "hostkeys-prove-00@openssh.com"

internal fun hostKeyProofData(sessionId: ByteArray, key: ByteArray): ByteArray = encodeSshString(HOSTKEYS_PROVE.toByteArray(Charsets.US_ASCII)) + encodeSshString(sessionId) + encodeSshString(key)

/** Verify the entire ordered reply before allowing any persistence, including retirement of old keys. */
internal fun verifyHostKeyProofs(
    keys: List<PublicKey>,
    reply: ByteArray,
    sessionId: ByteArray,
    negotiatedAlgorithm: String,
    allowedAlgorithms: Set<String>,
): Boolean = try {
    val signatures = GlobalRequestResponseHostkeysProve00Openssh(ByteBufferKaitaiStream(reply)).apply { _read() }.signatures()
    signatures.size == keys.size && keys.zip(signatures).all { (key, signature) ->
        val bytes = signature.data()
        val parsedSignature = SshSignature(ByteBufferKaitaiStream(bytes)).apply { _read() }
        val parsedKey = SshPublicKey(ByteBufferKaitaiStream(key.encoded)).apply { _read() }
        if (!parsedSignature._io().isEof || !parsedKey._io().isEof || parsedKey.algorithmName() != key.type) return@all false
        val algorithm = parsedSignature.algorithmName()
        val permitted = if (key.type == "ssh-rsa") {
            // The legacy OpenSSH request permits SHA-1, but we require SHA-2 proofs.
            algorithm in setOf("rsa-sha2-256", "rsa-sha2-512") && algorithm in allowedAlgorithms &&
                (negotiatedAlgorithm !in setOf("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512") || algorithm == negotiatedAlgorithm)
        } else {
            algorithm == key.type && algorithm in allowedAlgorithms
        }
        permitted && SignatureVerifier.verify(key.encoded, bytes, hostKeyProofData(sessionId, key.encoded), algorithm)
    }
} catch (_: Exception) {
    false
}
