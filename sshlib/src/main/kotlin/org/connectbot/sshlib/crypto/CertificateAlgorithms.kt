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

internal const val CERTIFICATE_SUFFIX = "-cert-v01@openssh.com"

internal val certificateKeyTypes = mapOf(
    "ssh-ed25519$CERTIFICATE_SUFFIX" to "ssh-ed25519",
    "ssh-rsa$CERTIFICATE_SUFFIX" to "ssh-rsa",
    "ecdsa-sha2-nistp256$CERTIFICATE_SUFFIX" to "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384$CERTIFICATE_SUFFIX" to "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521$CERTIFICATE_SUFFIX" to "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519$CERTIFICATE_SUFFIX" to "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256$CERTIFICATE_SUFFIX" to "sk-ecdsa-sha2-nistp256@openssh.com",
)

internal fun certificateSignatureAlgorithm(name: String): String = when (name) {
    "rsa-sha2-256$CERTIFICATE_SUFFIX" -> "rsa-sha2-256"
    "rsa-sha2-512$CERTIFICATE_SUFFIX" -> "rsa-sha2-512"
    else -> certificateKeyTypes[name] ?: name
}

internal fun certificateAlgorithm(name: String): String? = when (name) {
    "ssh-ed25519", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    -> name + CERTIFICATE_SUFFIX

    else -> null
}

internal fun withCertificateHostKeys(names: String): String {
    val configured = names.split(',').filter { it.isNotEmpty() }
    return (configured.mapNotNull(::certificateAlgorithm) + configured).distinct().joinToString(",")
}
