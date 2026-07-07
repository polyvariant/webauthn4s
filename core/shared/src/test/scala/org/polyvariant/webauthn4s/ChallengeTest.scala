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

import cats.effect.IO
import cats.effect.std.SecureRandom
import scodec.bits.ByteVector

import scala.concurrent.duration.*

/** Cross-platform (JVM + Native) test for the stateless HMAC challenge.
  */
class ChallengeTest extends munit.CatsEffectSuite {

  private val defaultSecret: ByteVector = ByteVector("super-secret-key".getBytes("UTF-8"))
  private val now: FiniteDuration = 1_700_000_000_000L.millis
  private val ttl: FiniteDuration = 60.seconds

  private def challenge(secret: ByteVector = defaultSecret): IO[Challenge[IO]] =
    SecureRandom.javaSecuritySecureRandom[IO].map(Challenge[IO](_, secret, ttl))

  test("issue then validate round-trips, returning the raw challenge bytes") {
    for {
      c <- challenge()
      token <- c.issue(now)
      result <- c.validate(token, now + 1.second)
      raw = ByteVector.fromValidBase64(token.challenge, scodec.bits.Bases.Alphabets.Base64UrlNoPad)
    } yield assertEquals(result, Right(raw))
  }

  test("rejects a tampered mac") {
    for {
      c <- challenge()
      token <- c.issue(now)
      bad = token.copy(mac = flipLastB64(token.mac))
      result <- c.validate(bad, now + 1.second)
    } yield assertEquals(result, Left("challenge mac mismatch"))
  }

  test("rejects a wrong secret") {
    for {
      token <- challenge().flatMap(_.issue(now))
      other <- challenge(ByteVector("other".getBytes("UTF-8")))
      result <- other.validate(token, now + 1.second)
    } yield assertEquals(result, Left("challenge mac mismatch"))
  }

  test("rejects an expired challenge") {
    for {
      c <- challenge()
      token <- c.issue(now)
      result <- c.validate(token, token.exp)
    } yield assertEquals(result, Left("challenge expired"))
  }

  /** Flip a bit in the last byte of a base64url value, preserving validity. */
  private def flipLastB64(b64: String): String = {
    val bytes = ByteVector.fromValidBase64(b64, scodec.bits.Bases.Alphabets.Base64UrlNoPad)
    val flipped = bytes.init :+ (bytes.last ^ 0x01).toByte
    flipped.toBase64(scodec.bits.Bases.Alphabets.Base64UrlNoPad)
  }

}
