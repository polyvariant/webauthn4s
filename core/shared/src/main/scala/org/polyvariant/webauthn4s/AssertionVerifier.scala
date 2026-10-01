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

import fs2.Chunk
import fs2.hashing.Hashing
import scodec.bits.ByteVector

/** Verifies a single WebAuthn *assertion* (the `navigator.credentials.get()` login flow). No
  * credential DB, no enrollment — the expected public key and RP context are passed in, and this is
  * the only auth check performed.
  *
  * Pure and total: all inputs in, a `Right(())` / `Left(reason)` out. Cross-compiles JVM + Native —
  * the only platform-specific call is `Es256.verifySig`.
  */
object AssertionVerifier {

  /** The expected relying-party context.
    *
    * @param requireUserVerification
    *   whether the authenticator must have verified the user (PIN, biometric, device unlock) — the
    *   UV flag. Without it an assertion only proves possession: anyone holding an unlocked security
    *   key can touch it and log in. Defaults to `true`, matching `userVerification: "required"` in
    *   the `navigator.credentials.get()` options; set to `false` only for authenticators that can't
    *   verify users (e.g. U2F-only keys) or when this is a second factor.
    */
  final case class Expectations(
    rpId: String,
    origin: String,
    publicKeySpki: ByteVector,
    requireUserVerification: Boolean = true,
  )

  /** Raw assertion fields as received from the browser (already base64url-decoded into bytes;
    * `challenge` is the server-issued value we handed out).
    */
  final case class Assertion(
    authenticatorData: ByteVector,
    clientDataJson: ByteVector,
    signature: ByteVector,
    challenge: ByteVector,
  )

  /** @return
    *   `Right(())` if every WebAuthn assertion check passes, else a `Left` naming the first
    *   failure. Never throws.
    */
  def verify(expected: Expectations, assertion: Assertion): Either[String, Unit] =
    for {
      clientData <- ClientData.parse(assertion.clientDataJson.toArray)
      _ <- check(clientData.`type` == "webauthn.get", s"unexpected type: ${clientData.`type`}")
      _ <- check(clientData.origin == expected.origin, s"origin mismatch: ${clientData.origin}")
      challengeB64 = base64UrlNoPad(assertion.challenge)
      _ <- check(
        constantTimeEquals(clientData.challenge, challengeB64),
        "challenge mismatch",
      )
      authData <- AuthenticatorData.parse(assertion.authenticatorData)
      _ <- check(
        authData.rpIdHash == sha256(ByteVector(expected.rpId.getBytes("UTF-8"))),
        "rpIdHash mismatch",
      )
      _ <- check(authData.userPresent, "user-present flag not set")
      _ <- check(
        authData.userVerified || !expected.requireUserVerification,
        "user-verified flag not set",
      )
      signedMessage = assertion.authenticatorData ++ sha256(assertion.clientDataJson)
      _ <- check(
        Es256.verifySig(
          expected.publicKeySpki.toArray,
          signedMessage.toArray,
          assertion.signature.toArray,
        ),
        "signature verification failed",
      )
    } yield ()

  private def check(cond: Boolean, ifFalse: => String): Either[String, Unit] =
    if (cond)
      Right(())
    else
      Left(ifFalse)

  private def sha256(data: ByteVector): ByteVector =
    ByteVector(Hashing.hashChunk(Sha256Platform.algorithm, Chunk.byteVector(data)).bytes.toArray)

  private def base64UrlNoPad(bytes: ByteVector): String =
    bytes.toBase64(scodec.bits.Bases.Alphabets.Base64UrlNoPad)

  /** Length-aware constant-time compare, to avoid timing leaks on the challenge. Folds an XOR
    * accumulator over equal-length byte arrays; differing lengths short-circuit (length is not
    * secret).
    */
  private def constantTimeEquals(a: String, b: String): Boolean = {
    val ab = a.getBytes("UTF-8")
    val bb = b.getBytes("UTF-8")
    if (ab.length != bb.length)
      false
    else
      ab.indices.foldLeft(0)((acc, i) => acc | (ab(i) ^ bb(i))) == 0
  }

}
