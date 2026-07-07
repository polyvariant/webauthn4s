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

import org.polyvariant.webauthn4s.AssertionVerifier.Assertion
import org.polyvariant.webauthn4s.AssertionVerifier.Expectations
import scodec.bits.ByteVector
import scodec.bits.hex

/** Cross-platform (JVM + Native) test for the WebAuthn assertion verifier. The vector was
  * synthesised once with `openssl` for rpId `signal.example`, origin `https://signal.example`,
  * challenge `0102…10`, flags `0x01` (UP set), signing `authData ‖ SHA256(clientDataJSON)` with a
  * fresh P-256 key.
  */
class AssertionVerifierTest extends munit.FunSuite {

  private val spki: ByteVector =
    ByteVector.fromValidBase64(
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEztDtTh5D1mC8EZhpRn8rpform1ZWejrS04VllOGeMaoZx6VMN9B68zxH+KLb/xuRl+lytzYBc/FTgaEO0jyC1w=="
    )

  private val authData: ByteVector =
    ByteVector.fromValidBase64("6T21w6AQF/wJIWNdyUDkYKE9QSV19Wb6VPyON9JTNdYBAAAAAQ==")

  private val clientDataJson: ByteVector =
    ByteVector.fromValidBase64(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVFJREJBVUdCd2dKQ2dzTURRNFBFQSIsIm9yaWdpbiI6Imh0dHBzOi8vc2lnbmFsLmV4YW1wbGUifQ=="
    )

  private val signature: ByteVector =
    ByteVector.fromValidBase64(
      "MEQCIDMTFAKgJsWsNj83NHfco0QBedpzJwwkUW+nUg5rqIwnAiACbLRQ+fbPzPS/I1tJO40p8l85eAmmc/cwTsNk3VLvtQ=="
    )

  private val challenge: ByteVector = hex"0102030405060708090a0b0c0d0e0f10"

  private val expected: Expectations =
    Expectations(rpId = "signal.example", origin = "https://signal.example", publicKeySpki = spki)

  private def assertion: Assertion = Assertion(authData, clientDataJson, signature, challenge)

  test("accepts a valid assertion") {
    assertEquals(AssertionVerifier.verify(expected, assertion), Right(()))
  }

  test("rejects a tampered signature") {
    val bad = signature.init :+ (signature.last ^ 0x01).toByte
    assertEquals(
      AssertionVerifier.verify(expected, assertion.copy(signature = bad)),
      Left("signature verification failed"),
    )
  }

  test("rejects a wrong challenge") {
    assertEquals(
      AssertionVerifier.verify(expected, assertion.copy(challenge = hex"00" ++ challenge.tail)),
      Left("challenge mismatch"),
    )
  }

  test("rejects a wrong origin") {
    assertEquals(
      AssertionVerifier.verify(expected.copy(origin = "https://evil.example"), assertion),
      Left("origin mismatch: https://signal.example"),
    )
  }

  test("rejects a wrong rpId") {
    assertEquals(
      AssertionVerifier.verify(expected.copy(rpId = "evil.example"), assertion),
      Left("rpIdHash mismatch"),
    )
  }

  // Multi-device: a backend can accept an assertion if it verifies against ANY
  // trusted SPKI. Model that "any" fold here against a key list with one
  // matching key among decoys.
  private val decoySpki: ByteVector =
    ByteVector.fromValidBase64(
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz9Uzj7pPo0wj2m67Ruv6qy28ftigK2RjKZxl4hi1ObWV9aKwLnTD8Xu+jTIPwH0aiRRrPG0IYxxym6Z53WYKaw=="
    )

  test("accepts when the correct key is present in a trusted list") {
    val keys = List(decoySpki, spki)
    assert(
      keys.exists(k =>
        AssertionVerifier.verify(expected.copy(publicKeySpki = k), assertion).isRight
      )
    )
  }

  test("rejects when no trusted key matches") {
    val keys = List(decoySpki)
    assert(
      !keys.exists(k =>
        AssertionVerifier.verify(expected.copy(publicKeySpki = k), assertion).isRight
      )
    )
  }

}
