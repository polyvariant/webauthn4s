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

  // Same message, signed with SHA-256 by keys that are not P-256. Each platform's crypto backend
  // would verify one of these on its own (JCA: P-384; OpenSSL: both), so they pin the curve check.
  private val p384SpkiB64: String =
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECZ8RO6R662yV2WXuXXx74G6K56ZrtS+30jSP6xUCoCayg1alS7OdhiHzY7NQXgyRuL95yRtdN7xsDq2nFSJgm9l6J49KIVgj5PYXsNlTvMcE7Jdlv9ZOKdHdr2JbbP0S"

  private val p384SigB64: String =
    "MGUCMAj414mDTv9RZIbZHcktgfQjwO+9rVPzUSsD4ITKyqND7ZTuwW6vwWXmTArEaaMewwIxAIz9BToJ80BEhKOTarWB7hWNn0m5e4uaN2KUcY1s7hxU0lm4D8oBGFWd0h739SsJRg=="

  private val rsaSpkiB64: String =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/QMoGyrLYyr2pG3Og2hIqBURFWyJ9nbZurQJOwZas25qX4m51V90HIlTYu+rNW62hQgCQ92M3oDXQxjkYlu3sRSuV0PNaXGmTj0LFEXeNwNoGqil4FrmTsH/uPpmLQjaNTFQfuz4pCoSZs9FxUtb9SfyTW/u8aDp1T7xFHpy2QXaGXteIVbjtX43TBKbpRoFqSWnjsHn9ResMnB9e/WLWgj3Zx36S6L7nMEEMExDxM6SBqE2+s/0p69vxSWnTaH6+B7kbWP9kRAG8oaGKS1LXiW8QRwHThyR4720CToiSTXFkh3+SIxDa7uIu7As7c7sBok7IBXw6nUwLw/SRx/EwIDAQAB"

  private val rsaSigB64: String =
    "s0qxSNsUi+qzYu3pzUJaviLSynjwXgxdJ+FdPC5zk0ayXbVWy1ySWR4+kqxdpzdKWNJ6TswNAg7d4BJ6Pd7bjcsdcHxPHhDIEAx5okUPv49MDj3oPxpj5jvrwr70tDSFa8BC2BX07WzhbVP0IRMBjuaTIB/0UYtIcVgUJOEiwME9LuzPhctXNm3B/MiXE2cWeE7A4HJ96OgaQAz/LsrP+ST02qKbl+5hzYI0UFi/hBViby5aQvRjlknRJsL3ub+/4xme5V6KdQTj01xihyoPHCzcl/Vd2bD8fTUOso4Nwtnk4fLJv9nYzKj4G4U2XNt2e3xi4J3GGWfpF8ruFrGljQ=="

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

  test("rejects a valid signature from a P-384 key") {
    assert(!Es256.verifySig(dec(p384SpkiB64), dec(msgB64), dec(p384SigB64)))
  }

  test("rejects a valid signature from an RSA key") {
    assert(!Es256.verifySig(dec(rsaSpkiB64), dec(msgB64), dec(rsaSigB64)))
  }

}
