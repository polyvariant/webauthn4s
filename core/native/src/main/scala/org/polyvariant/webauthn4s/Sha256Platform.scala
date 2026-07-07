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

/** SHA-256 algorithm handle for fs2's `Hashing`, resolved per platform.
  *
  * On Native, fs2 resolves digests through OpenSSL's legacy `EVP_get_digestbyname`, and fs2's
  * built-in `HashAlgorithm.SHA256` passes the name "SHA-256". OpenSSL 3.0.x (the system libcrypto
  * on Ubuntu 22.04 and 24.04) only registers the short names in that legacy lookup table, so
  * "SHA-256" comes back null there and every hash/HMAC fails. "SHA256" is the canonical short name
  * (`SN_sha256`) and resolves on every OpenSSL: 1.1, 3.0.x, and newer builds where either name
  * works.
  */
private[webauthn4s] object Sha256Platform {
  val algorithm: HashAlgorithm = HashAlgorithm.Named("SHA256")
}
