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
import cats.syntax.all.*
import fs2.Chunk
import fs2.hashing.HashAlgorithm
import fs2.hashing.Hashing
import scodec.bits.ByteVector

/** HMAC-SHA256 helper backing [[Challenge]].
  *
  * Wraps fs2's pure `Hashing[F].hmac`, which works on both JVM and Scala Native (no FFI shim),
  * keeping the stateless-token machinery cross-platform. Polymorphic in `F`: any effect with a
  * `Hashing` instance works.
  */
object Hmac {

  /** HMAC-SHA256 of `message` under `secret`. */
  def sha256[F[_]: Hashing: MonadCancelThrow](
    secret: ByteVector,
    message: ByteVector,
  ): F[ByteVector] =
    Hashing[F]
      .hmac(HashAlgorithm.SHA256, Chunk.byteVector(secret))
      .use(hasher => hasher.update(Chunk.byteVector(message)) *> hasher.hash)
      .map(hash => ByteVector(hash.bytes.toArray))

  /** Length-aware constant-time compare — folds an XOR accumulator over the bytes; differing
    * lengths short-circuit (length is not secret).
    */
  def constantTimeEquals(a: ByteVector, b: ByteVector): Boolean =
    if (a.length != b.length)
      false
    else
      a.toArray.indices.foldLeft(0)((acc, i) => acc | (a(i.toLong) ^ b(i.toLong))) == 0

}
