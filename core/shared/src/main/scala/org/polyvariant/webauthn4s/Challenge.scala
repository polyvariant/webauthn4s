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

import cats.effect.MonadCancelThrow
import cats.effect.std.SecureRandom
import cats.syntax.all.*
import fs2.hashing.Hashing
import scodec.bits.ByteVector

import scala.concurrent.duration.FiniteDuration

/** Stateless WebAuthn challenge.
  *
  * No server-side challenge store: the issued token is `challenge ‖ exp` plus an HMAC binding them
  * under a session secret. Anyone can read the challenge, but only the server can forge a valid
  * `mac`, and the `exp` bounds replay. This survives serverless container churn for free — there's
  * nothing to persist.
  *
  * Polymorphic in `F`; the caller supplies the `SecureRandom[F]` and the wall-clock reading (`now`,
  * as time since the epoch), so this stays referentially transparent and easy to test.
  */
object Challenge {

  /** A challenge handed to the client, echoed back verbatim on verify. The base64url (no padding)
    * encodings match what a JSON API typically carries. `exp` is time since the epoch.
    */
  final case class Token(challenge: String, exp: FiniteDuration, mac: String)

  /** Bytes the mac is computed over: `challenge ‖ ascii(expMillis)`. Encoding `exp` as its decimal
    * ASCII milliseconds keeps issue/validate trivially in sync.
    */
  private def macMessage(challenge: ByteVector, exp: FiniteDuration): ByteVector =
    challenge ++ ByteVector(exp.toMillis.toString.getBytes("UTF-8"))

  private def b64(bytes: ByteVector): String =
    bytes.toBase64(scodec.bits.Bases.Alphabets.Base64UrlNoPad)

  /** Issue a fresh challenge valid until `now + ttl`.
    *
    * @param random
    *   source of the 32 random challenge bytes, supplied by the caller.
    * @param now
    *   current time since the epoch.
    * @param ttl
    *   how long the browser has to complete `navigator.credentials.get()` and round-trip to the
    *   verify endpoint.
    */
  def issue[F[_]: Hashing: MonadCancelThrow](
    random: SecureRandom[F],
    secret: ByteVector,
    now: FiniteDuration,
    ttl: FiniteDuration,
  ): F[Token] =
    for {
      raw <- random.nextBytes(32).map(ByteVector(_))
      exp = now + ttl
      macBytes <- Hmac.sha256(secret, macMessage(raw, exp))
    } yield Token(challenge = b64(raw), exp = exp, mac = b64(macBytes))

  /** Recompute the mac, constant-time compare it, and check expiry.
    *
    * @param now
    *   current time since the epoch.
    * @return
    *   the raw challenge bytes (for the assertion check) on success, else a `Left` naming the
    *   failure.
    */
  def validate[F[_]: Hashing: MonadCancelThrow](
    secret: ByteVector,
    token: Token,
    now: FiniteDuration,
  ): F[Either[String, ByteVector]] =
    ByteVector.fromBase64(token.challenge, scodec.bits.Bases.Alphabets.Base64UrlNoPad) match {
      case None      => Left("challenge not base64url").pure[F].widen
      case Some(raw) =>
        ByteVector.fromBase64(token.mac, scodec.bits.Bases.Alphabets.Base64UrlNoPad) match {
          case None               => Left("mac not base64url").pure[F].widen
          case Some(presentedMac) =>
            Hmac.sha256(secret, macMessage(raw, token.exp)).map { expectedMac =>
              if (!Hmac.constantTimeEquals(expectedMac, presentedMac))
                Left("challenge mac mismatch")
              else if (now >= token.exp)
                Left("challenge expired")
              else
                Right(raw)
            }
        }
    }

}
