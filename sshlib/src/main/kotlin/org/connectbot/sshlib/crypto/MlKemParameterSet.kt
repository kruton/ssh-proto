/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

import asia.hombre.kyber.KyberParameter

/** The FIPS 203 parameter sets used by the RFC 10042 SSH methods. */
internal enum class MlKemParameterSet(val kyberParameter: KyberParameter) {
    ML_KEM_768(KyberParameter.ML_KEM_768),
    ML_KEM_1024(KyberParameter.ML_KEM_1024),
    ;

    val publicKeySize: Int get() = kyberParameter.ENCAPSULATION_KEY_LENGTH
    val privateKeySize: Int get() = kyberParameter.DECAPSULATION_KEY_LENGTH
    val ciphertextSize: Int get() = kyberParameter.CIPHERTEXT_LENGTH
}
