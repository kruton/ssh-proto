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

import org.slf4j.LoggerFactory

internal object MlKemProviderFactory {
    private val logger = LoggerFactory.getLogger(MlKemProviderFactory::class.java)

    internal val provider: MlKemProvider by lazy {
        try {
            val p = JavaMlKemProvider()
            logger.debug("Using Java 23+ native ML-KEM implementation")
            p
        } catch (e: Exception) {
            logger.debug("Java KEM API not available, falling back to Kyber Kotlin")
            KyberKotlinMlKemProvider()
        }
    }

    // The bundled Kotlin provider supplies ML-KEM-1024 on Android and JVM 17.
    private val provider1024: MlKemProvider by lazy {
        KyberKotlinMlKemProvider(MlKemParameterSet.ML_KEM_1024)
    }

    fun forParameterSet(parameterSet: MlKemParameterSet): MlKemProvider = when (parameterSet) {
        MlKemParameterSet.ML_KEM_768 -> provider
        MlKemParameterSet.ML_KEM_1024 -> provider1024
    }
}
