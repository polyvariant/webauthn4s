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

import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** JVM ES256 verify via JCA.
  *
  * `SHA256withECDSA` hashes `message` internally and consumes the DER ECDSA signature directly, so
  * behaviour matches the Native OpenSSL branch. A malformed key/signature surfaces as a
  * `GeneralSecurityException`; we map it to `false` for parity with Native (which returns a
  * Boolean, never throws).
  */
private[webauthn4s] object Es256Platform {

  def verify(publicKeySpki: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    try {
      val pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeySpki))
      val sig = Signature.getInstance("SHA256withECDSA")
      sig.initVerify(pub)
      sig.update(message)
      sig.verify(signature)
    } catch {
      case _: GeneralSecurityException => false
    }

}
