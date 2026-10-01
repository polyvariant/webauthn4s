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

/** Stateless WebAuthn challenge issuer/validator.
  *
  * No server-side challenge store: an issued token is `challenge ‖ exp` plus an HMAC binding them
  * under a session secret. Anyone can read the challenge, but only the holder of `secret` can forge
  * a valid `mac`, and `exp` bounds its lifetime. Single use within that lifetime is enforced by the
  * ambient [[ReplayGuard]] — the only state involved, and bounded by issue rate × TTL.
  *
  * Construct one with [[Challenge.apply]] and pass it around, rather than threading the secret,
  * random source, and TTL through call sites. The caller still supplies each `now` reading (time
  * since the epoch), keeping this referentially transparent and easy to test.
  */
trait Challenge[F[_]] {

  /** Issue a fresh challenge valid until `now + ttl`. Hand the returned token to the client. */
  def issue(now: FiniteDuration): F[Challenge.Token]

  /** Recompute the mac, constant-time compare it, check expiry against `now`, and consume the
    * challenge via the [[ReplayGuard]] so the same token can't be validated twice.
    *
    * @return
    *   the validated challenge (for [[AssertionVerifier.Assertion]]) on success, else a `Left`
    *   naming the failure.
    */
  def validate(token: Challenge.Token, now: FiniteDuration): F[Either[String, Challenge.Validated]]

}

object Challenge {

  /** A challenge handed to the client, echoed back verbatim on verify. The base64url (no padding)
    * encodings match what a JSON API typically carries. `exp` is time since the epoch.
    */
  final case class Token(challenge: String, exp: FiniteDuration, mac: String)

  /** Challenge bytes that passed [[Challenge.validate]] — the only form
    * [[AssertionVerifier.Assertion]] accepts, so a challenge echoed by the client (e.g. lifted from
    * its own `clientDataJSON`) can't be passed to `verify` by mistake, which would make the
    * challenge check vacuous.
    */
  final case class Validated private[webauthn4s] (bytes: ByteVector)

  object Validated {

    /** Escape hatch for challenges issued and consumed by your own mechanism (e.g. a server-side
      * store) instead of [[Challenge]]. Only wrap bytes that came from your server's own state —
      * never bytes taken from the request.
      */
    def trusted(bytes: ByteVector): Validated = new Validated(bytes)

  }

  /** Build a [[Challenge]] over a fixed secret and TTL, using an ambient `SecureRandom[F]` as the
    * source of challenge bytes and an ambient [[ReplayGuard]] to enforce single use.
    *
    * @param secret
    *   the HMAC key; only its holder can forge a valid token. Must be at least 32 bytes from a
    *   CSPRNG (e.g. `openssl rand -base64 32`), otherwise this fails with an
    *   `IllegalArgumentException`.
    * @param ttl
    *   how long the browser has to complete `navigator.credentials.get()` and round-trip to the
    *   verify endpoint.
    */
  def apply[F[_]: Hashing: MonadCancelThrow: SecureRandom: ReplayGuard](
    secret: ByteVector,
    ttl: FiniteDuration,
  ): F[Challenge[F]] =
    MonadCancelThrow[F]
      .raiseError[Challenge[F]](
        new IllegalArgumentException(
          s"Challenge secret must be at least $MinSecretLength bytes, got ${secret.size}"
        )
      )
      .whenA(secret.size < MinSecretLength)
      .as(instance(secret, ttl))

  private def instance[F[_]: Hashing: MonadCancelThrow: SecureRandom: ReplayGuard](
    secret: ByteVector,
    ttl: FiniteDuration,
  ): Challenge[F] =
    new Challenge[F] {

      def issue(now: FiniteDuration): F[Token] =
        for {
          raw <- SecureRandom[F].nextBytes(ChallengeLength).map(ByteVector(_))
          exp = now + ttl
          macBytes <- Hmac.sha256(secret, macMessage(raw, exp))
        } yield Token(challenge = b64(raw), exp = exp, mac = b64(macBytes))

      def validate(token: Token, now: FiniteDuration): F[Either[String, Validated]] =
        ByteVector.fromBase64(token.challenge, Alphabet) match {
          case None => Left("challenge not base64url").pure[F].widen
          case Some(raw) if raw.size != ChallengeLength =>
            Left("challenge has wrong length").pure[F].widen
          case Some(raw) =>
            ByteVector.fromBase64(token.mac, Alphabet) match {
              case None               => Left("mac not base64url").pure[F].widen
              case Some(presentedMac) =>
                Hmac.sha256(secret, macMessage(raw, token.exp)).flatMap { expectedMac =>
                  if (!Hmac.constantTimeEquals(expectedMac, presentedMac))
                    Left("challenge mac mismatch").pure[F].widen
                  else if (now >= token.exp)
                    Left("challenge expired").pure[F].widen
                  else
                    ReplayGuard[F].claim(raw, token.exp, now).map { fresh =>
                      if (fresh)
                        Right(Validated(raw))
                      else
                        Left("challenge already used")
                    }
                }
            }
        }

    }

  private val Alphabet = scodec.bits.Bases.Alphabets.Base64UrlNoPad

  /** HMAC-SHA256 key floor: shorter keys reduce the forgery bound below the hash's 256 bits. */
  private val MinSecretLength: Int = 32

  /** Size of an issued challenge; `validate` rejects anything else. */
  private val ChallengeLength: Int = 32

  /** Domain separation, so a mac over this layout can't be confused with any other use of the same
    * secret. Bump the version if the layout ever changes.
    */
  private val MacDomain: ByteVector = ByteVector("webauthn4s/challenge/v1".getBytes("UTF-8"))

  /** Bytes the mac is computed over: `domain ‖ challenge(32) ‖ int64be(expMillis)`. Every field is
    * fixed-length, so no two distinct (challenge, exp) pairs share an encoding — a variable-length
    * layout would let bytes shift between the challenge and `exp` under the same mac.
    */
  private def macMessage(challenge: ByteVector, exp: FiniteDuration): ByteVector =
    MacDomain ++ challenge ++ ByteVector.fromLong(exp.toMillis)

  private def b64(bytes: ByteVector): String =
    bytes.toBase64(Alphabet)

}
