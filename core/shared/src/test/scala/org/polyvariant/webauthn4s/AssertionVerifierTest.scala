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

/** Cross-platform (JVM + Native) test for the WebAuthn assertion verifier. The vectors were
  * synthesised with `openssl` for rpId `signal.example`, origin `https://signal.example`, challenge
  * `0102…10`, signing `authData ‖ SHA256(clientDataJSON)` with a fresh P-256 key:
  * {{{
  *   openssl ecparam -name prime256v1 -genkey -noout -out k.pem
  *   { printf 'signal.example' | openssl dgst -sha256 -binary; printf '\x05\x00\x00\x00\x07'; } > ad.bin
  *   { cat ad.bin; openssl dgst -sha256 -binary cdj.bin; } > msg.bin
  *   openssl dgst -sha256 -sign k.pem msg.bin > sig.bin
  * }}}
  * The main vector has flags `0x05` (UP + UV) and sign count 7; the `upOnly` one has flags `0x01`.
  */
class AssertionVerifierTest extends munit.FunSuite {

  private val spki: ByteVector =
    ByteVector.fromValidBase64(
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmbazkB7z9vt2+CRxu4jJoPcXW/aee78enJbfYaQOEZk7YnAztgqOfvUwV/+0D/Zkwuo0Htx4SXocaVS7HMraNw=="
    )

  private val authData: ByteVector =
    ByteVector.fromValidBase64("6T21w6AQF/wJIWNdyUDkYKE9QSV19Wb6VPyON9JTNdYFAAAABw==")

  private val clientDataJson: ByteVector =
    ByteVector.fromValidBase64(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVFJREJBVUdCd2dKQ2dzTURRNFBFQSIsIm9yaWdpbiI6Imh0dHBzOi8vc2lnbmFsLmV4YW1wbGUiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
    )

  private val signature: ByteVector =
    ByteVector.fromValidBase64(
      "MEQCIEgepjpK4GwO48o3rXRdmbAnLja0ByaSvU2vzN0fbmdlAiBWOzWZ4lY6tyXaye7zyNJHn2iHTM5+Wz3Pi6o5U3/b7g=="
    )

  private val upOnlySpki: ByteVector =
    ByteVector.fromValidBase64(
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEztDtTh5D1mC8EZhpRn8rpform1ZWejrS04VllOGeMaoZx6VMN9B68zxH+KLb/xuRl+lytzYBc/FTgaEO0jyC1w=="
    )

  private val upOnlyAuthData: ByteVector =
    ByteVector.fromValidBase64("6T21w6AQF/wJIWNdyUDkYKE9QSV19Wb6VPyON9JTNdYBAAAAAQ==")

  private val upOnlyClientDataJson: ByteVector =
    ByteVector.fromValidBase64(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVFJREJBVUdCd2dKQ2dzTURRNFBFQSIsIm9yaWdpbiI6Imh0dHBzOi8vc2lnbmFsLmV4YW1wbGUifQ=="
    )

  private val upOnlySignature: ByteVector =
    ByteVector.fromValidBase64(
      "MEQCIDMTFAKgJsWsNj83NHfco0QBedpzJwwkUW+nUg5rqIwnAiACbLRQ+fbPzPS/I1tJO40p8l85eAmmc/cwTsNk3VLvtQ=="
    )

  private val challenge: Challenge.Validated =
    Challenge.Validated(hex"0102030405060708090a0b0c0d0e0f10")

  private val expected: Expectations =
    Expectations(rpId = "signal.example", origin = "https://signal.example", publicKeySpki = spki)

  private def assertion: Assertion = Assertion(authData, clientDataJson, signature, challenge)

  test("accepts a valid assertion") {
    assertEquals(AssertionVerifier.verify(expected, assertion).map(_.counter), Right(7L))
  }

  private def upOnlyAssertion: Assertion =
    Assertion(upOnlyAuthData, upOnlyClientDataJson, upOnlySignature, challenge)

  test("rejects a user-present-only assertion by default") {
    assertEquals(
      AssertionVerifier.verify(expected.copy(publicKeySpki = upOnlySpki), upOnlyAssertion),
      Left("user-verified flag not set"),
    )
  }

  test("accepts a user-present-only assertion when user verification is not required") {
    assertEquals(
      AssertionVerifier
        .verify(
          expected.copy(publicKeySpki = upOnlySpki, requireUserVerification = false),
          upOnlyAssertion,
        )
        .map(_.userVerified),
      Right(false),
    )
  }

  test("accepts a sign count that increased") {
    assert(AssertionVerifier.verify(expected.copy(signCount = 6L), assertion).isRight)
  }

  test("rejects a sign count that did not increase") {
    List(7L, 8L).foreach { stored =>
      assertEquals(
        AssertionVerifier.verify(expected.copy(signCount = stored), assertion),
        Left("sign count did not increase (possible cloned authenticator)"),
      )
    }
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
      AssertionVerifier.verify(
        expected,
        assertion.copy(challenge = Challenge.Validated(hex"00" ++ challenge.bytes.tail)),
      ),
      Left("challenge mismatch"),
    )
  }

  test("rejects a wrong origin") {
    assertEquals(
      AssertionVerifier.verify(expected.copy(origin = "https://evil.example"), assertion),
      Left("origin mismatch"),
    )
  }

  test("rejects a wrong rpId") {
    assertEquals(
      AssertionVerifier.verify(expected.copy(rpId = "evil.example"), assertion),
      Left("rpIdHash mismatch"),
    )
  }

  private def withClientData(json: String): Assertion =
    assertion.copy(clientDataJson = ByteVector(json.getBytes("UTF-8")))

  test("rejects clientDataJSON with a missing field instead of throwing") {
    List(
      "challenge" -> """{"type":"webauthn.get","origin":"https://signal.example"}""",
      "origin" -> """{"type":"webauthn.get","challenge":"AQIDBAUGBwgJCgsMDQ4PEA"}""",
      "type" -> """{"challenge":"AQIDBAUGBwgJCgsMDQ4PEA","origin":"https://signal.example"}""",
    ).foreach { (field, json) =>
      val result = AssertionVerifier.verify(expected, withClientData(json))
      assert(
        result.left.exists(_.contains(s"missing required field: $field")),
        s"$field: $result",
      )
    }
  }

  test("error messages don't echo request content") {
    val evil = "evil\r\nINFO forged log line"
    List(
      s"""{"type":"$evil","challenge":"x","origin":"https://signal.example"}""",
      s"""{"type":"webauthn.get","challenge":"x","origin":"$evil"}""",
      s"""{"type":"webauthn.get","challenge":"x","origin":"https://signal.example",$evil}""",
    ).foreach { json =>
      val result = AssertionVerifier.verify(expected, withClientData(json))
      assert(
        result.left.exists(msg => !msg.contains("evil") && !msg.contains("65 76 69 6c")),
        result,
      )
    }
  }

  test("rejects non-object clientDataJSON instead of throwing") {
    List("null", "[]", "\"x\"", "").foreach { json =>
      assert(AssertionVerifier.verify(expected, withClientData(json)).isLeft, json)
    }
  }

  private val crossOriginClientData: String =
    """{"type":"webauthn.get","challenge":"AQIDBAUGBwgJCgsMDQ4PEA","origin":"https://signal.example","crossOrigin":true}"""

  test("rejects a cross-origin assertion by default") {
    assertEquals(
      AssertionVerifier.verify(expected, withClientData(crossOriginClientData)),
      Left("cross-origin assertion not allowed"),
    )
  }

  test("lets a cross-origin assertion through when allowed") {
    // The body was edited, so the signature no longer matches — but the cross-origin check passed.
    assertEquals(
      AssertionVerifier.verify(
        expected.copy(allowCrossOrigin = true),
        withClientData(crossOriginClientData),
      ),
      Left("signature verification failed"),
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
