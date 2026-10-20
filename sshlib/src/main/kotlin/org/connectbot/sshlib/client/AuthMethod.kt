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

internal sealed class AuthMethod {
    data object Password : AuthMethod()
    data object PublicKey : AuthMethod()
    data object KeyboardInteractive : AuthMethod()
    data class Unknown(val name: String) : AuthMethod()

    companion object {
        const val PASSWORD = "password"
        const val PUBLIC_KEY = "publickey"
        const val KEYBOARD_INTERACTIVE = "keyboard-interactive"
        const val NONE = "none"
        const val PUBLIC_KEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com"

        fun fromString(name: String): AuthMethod = when (name) {
            PASSWORD -> Password
            PUBLIC_KEY -> PublicKey
            KEYBOARD_INTERACTIVE -> KeyboardInteractive
            else -> Unknown(name)
        }

        fun toSshName(method: AuthMethod): String = when (method) {
            is Password -> PASSWORD
            is PublicKey -> PUBLIC_KEY
            is KeyboardInteractive -> KEYBOARD_INTERACTIVE
            is Unknown -> method.name
        }
    }
}
