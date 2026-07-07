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

/** Verifies an ES256 (ECDSA P-256 + SHA-256) signature — the one crypto primitive WebAuthn
  * assertion verify needs.
  *
  * The same API compiles on JVM (JCA) and Scala Native (OpenSSL FFI); the implementation lives in
  * the platform-specific `Es256Platform`.
  */
object Es256 {

  /** @param publicKeySpki
    *   DER-encoded SubjectPublicKeyInfo (X.509 SPKI) for the EC P-256 public key. JVM parses it via
    *   `X509EncodedKeySpec`, Native via `d2i_PUBKEY` — identical input on both platforms.
    * @param message
    *   the pre-hash signed bytes. SHA-256 is applied internally by the algorithm (for WebAuthn this
    *   is `authenticatorData ‖ SHA256(clientDataJSON)`).
    * @param signature
    *   ASN.1 DER ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }` — exactly what both
    *   `EVP_DigestVerify` and `SHA256withECDSA` consume, so no raw↔DER conversion is needed.
    * @return
    *   true iff the signature is valid for (message, publicKey). Never throws.
    */
  def verifySig(publicKeySpki: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    Es256Platform.verify(publicKeySpki, message, signature)

}
