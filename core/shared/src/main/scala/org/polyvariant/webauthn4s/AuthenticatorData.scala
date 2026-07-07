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

import scodec.Codec
import scodec.bits.ByteVector
import scodec.codecs.*

/** The parsed prefix of a WebAuthn `authenticatorData` blob.
  *
  * For an *assertion* we only need the fixed 37-byte header — `rpIdHash`, the `flags` byte, and the
  * signature `counter`. Any trailing bytes (attested credential data / extensions) are retained
  * verbatim so the original blob can be reconstructed for the signature, but are not interpreted
  * here.
  *
  * @see
  *   https://www.w3.org/TR/webauthn-2/#authenticator-data
  */
final case class AuthenticatorData(
  rpIdHash: ByteVector,
  flags: Byte,
  counter: Long,
  rest: ByteVector,
) {

  /** User Present (UP) — bit 0. Required for a valid assertion. */
  def userPresent: Boolean = (flags & 0x01) != 0

  /** User Verified (UV) — bit 2. */
  def userVerified: Boolean = (flags & 0x04) != 0

}

object AuthenticatorData {

  /** rpIdHash(32) ‖ flags(1) ‖ counter(4, big-endian) ‖ rest. */
  val codec: Codec[AuthenticatorData] =
    (bytes(32) :: byte :: uint32 :: bytes)
      .as[AuthenticatorData]

  /** Parse the full blob, returning a decode error message on the left. */
  def parse(bytes: ByteVector): Either[String, AuthenticatorData] =
    codec.decodeValue(bytes.bits).toEither.left.map(_.messageWithContext)

}
