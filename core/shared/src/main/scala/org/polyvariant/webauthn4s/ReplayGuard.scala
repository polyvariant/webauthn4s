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

import cats.Applicative
import cats.Functor
import cats.effect.kernel.Ref
import cats.syntax.all.*
import scodec.bits.ByteVector

import scala.concurrent.duration.FiniteDuration

/** Single-use enforcement for [[Challenge]] tokens.
  *
  * A stateless token is valid for its whole TTL, so without a guard the same token (and an
  * assertion signed over it) can be replayed until it expires. WebAuthn expects each challenge to
  * be consumed once; a `ReplayGuard` remembers consumed challenges until their expiry, after which
  * the token's own `exp` rejects them anyway — so storage is bounded by issue rate × TTL.
  */
trait ReplayGuard[F[_]] {

  /** Atomically mark `challenge` as consumed until `exp`.
    *
    * @return
    *   `true` if this is the first use, `false` if it was already consumed.
    */
  def claim(challenge: ByteVector, exp: FiniteDuration, now: FiniteDuration): F[Boolean]

}

object ReplayGuard {

  def apply[F[_]](
    using ev: ReplayGuard[F]
  ): ReplayGuard[F] = ev

  /** An in-process guard. Only sufficient when every verify request hits the same process — with
    * several instances (or serverless), back [[ReplayGuard]] with a shared store instead (e.g. a
    * Redis `SET NX PX` or a DB unique constraint with a TTL).
    */
  def inMemory[F[_]: Ref.Make: Functor]: F[ReplayGuard[F]] =
    Ref[F].of(Map.empty[ByteVector, FiniteDuration]).map { ref =>
      new ReplayGuard[F] {
        def claim(challenge: ByteVector, exp: FiniteDuration, now: FiniteDuration): F[Boolean] =
          ref.modify { used =>
            val live = used.filter((_, e) => e > now)
            if (live.contains(challenge))
              (live, false)
            else
              (live.updated(challenge, exp), true)
          }
      }
    }

  /** Accepts every claim: tokens can be replayed until they expire. Only use this if you accept
    * that risk (e.g. a very short TTL) or enforce single use elsewhere.
    */
  def disabled[F[_]: Applicative]: ReplayGuard[F] =
    new ReplayGuard[F] {
      def claim(challenge: ByteVector, exp: FiniteDuration, now: FiniteDuration): F[Boolean] =
        true.pure[F]
    }

}
