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

import java.util.Base64

internal fun certificateResource(name: String): ByteArray = requireNotNull(SshCertificate::class.java.getResourceAsStream("/certificates/$name")).use { it.readBytes() }

internal fun certificateFixture(name: String = "host-ed25519"): SshCertificate = SshCertificate.decode(certificateResource("$name-cert.pub").toString(Charsets.UTF_8))

internal fun certificatePublicKey(name: String = "host-ed25519"): PublicKey = certificateFixture(name).let { PublicKey(it.algorithmName, it.encoded) }

internal fun certificateAuthority(kind: String = "ed25519"): PublicKey {
    val fields = certificateResource("ca-$kind.pub").toString(Charsets.UTF_8).split(' ')
    return PublicKey(fields[0], Base64.getDecoder().decode(fields[1]))
}
