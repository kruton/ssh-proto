/*
 * Copyright 2025 Kenny Root
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

/**
 * Example usage of the SSH client.
 *
 * This example demonstrates the basic usage pattern for connecting
 * to an SSH server and authenticating with password.
 */
fun main() {
    val client = SshClient(
        host = "example.com",
        port = 22
    )

    try {
        // Connect and perform key exchange
        if (!client.connect()) {
            println("Failed to connect to SSH server")
            return
        }

        println("Connected to SSH server")

        // Authenticate with password
        if (!client.authenticatePassword("username", "password")) {
            println("Authentication failed")
            return
        }

        println("Successfully authenticated!")

        // At this point, the connection is established and authenticated
        // You can now use channels for executing commands, port forwarding, etc.
        // (Channel support not yet implemented in this minimal version)

    } finally {
        client.disconnect()
        println("Disconnected from SSH server")
    }
}

/**
 * Example with explicit error handling.
 */
fun robustExample() {
    val client = SshClient("example.com")

    try {
        when {
            !client.connect() -> {
                println("ERROR: Failed to connect to SSH server")
                return
            }
            !client.authenticatePassword("user", "pass") -> {
                println("ERROR: Authentication failed")
                return
            }
            !client.isAuthenticated -> {
                println("ERROR: Client not authenticated")
                return
            }
            else -> {
                println("SUCCESS: Connected and authenticated")
                // Perform SSH operations here
            }
        }
    } catch (e: Exception) {
        println("ERROR: Unexpected exception: ${e.message}")
        e.printStackTrace()
    } finally {
        client.disconnect()
    }
}
