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

import scodec.bits.ByteVector

/** Cross-platform ES256 verify test. Runs on both JVM (JCA) and Native (OpenSSL FFI) from the same
  * source, proving the two `Es256Platform` branches agree on a known-good vector.
  *
  * The vector was produced once with the `openssl` CLI over a fixed message:
  * {{{
  *   openssl ecparam -name prime256v1 -genkey -noout -out ec_priv.pem
  *   openssl pkey -in ec_priv.pem -pubout -outform DER | base64        # spki
  *   printf '...' > msg.bin; base64 < msg.bin                          # msg
  *   openssl dgst -sha256 -sign ec_priv.pem msg.bin | base64           # sig (DER)
  * }}}
  */
class Es256Test extends munit.FunSuite {

  private val spkiB64: String =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyjdBbHZun4GldMbUbg426GJoq6vSRrxJwXU2QLcQ5JHuIw0S9TNvShSdvWbEw44ziA8UgKR/Appu34jtCXQD+A=="

  private val msgB64: String = "c2lnbmFsLWZ1biBlczI1NiB0ZXN0IHZlY3Rvcg=="

  private val sigB64: String =
    "MEYCIQDCqMAUseAbLPat9YEpi3yY3RTiaUMZw+PwWfe06Fr8YQIhAPxJne6FmLZ8qZgznKUzo8SiVR4BvCWSExCvqQ1ToU2Z"

  private def dec(s: String): Array[Byte] = ByteVector.fromValidBase64(s).toArray

  test("verifies a valid ES256 signature") {
    assert(Es256.verifySig(dec(spkiB64), dec(msgB64), dec(sigB64)))
  }

  test("rejects a tampered signature") {
    val bad = dec(sigB64)
    // Flip the last byte (an s-value bit) — keeps the DER structurally parseable
    // so both platforms take the clean `false` path rather than erroring.
    bad(bad.length - 1) = (bad(bad.length - 1) ^ 0x01).toByte
    assert(!Es256.verifySig(dec(spkiB64), dec(msgB64), bad))
  }

  test("rejects an altered message") {
    val msg = dec(msgB64)
    msg(0) = (msg(0) ^ 0x01).toByte
    assert(!Es256.verifySig(dec(spkiB64), msg, dec(sigB64)))
  }

}
