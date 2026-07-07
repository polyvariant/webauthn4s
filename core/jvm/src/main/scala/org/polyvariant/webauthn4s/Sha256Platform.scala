/*
 * Copyright 2026 Polyvariant
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

package org.polyvariant.webauthn4s

import fs2.hashing.HashAlgorithm

/** SHA-256 algorithm handle for fs2's `Hashing`, resolved per platform (see the Native twin for
  * why). On the JVM, fs2's built-in `HashAlgorithm.SHA256` maps to the standard JCA names
  * ("SHA-256" / "HmacSHA256") and works as-is.
  */
private[webauthn4s] object Sha256Platform {
  val algorithm: HashAlgorithm = HashAlgorithm.SHA256
}
