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

import com.github.plokhotnyuk.jsoniter_scala.core.*

/** The relevant fields of WebAuthn `clientDataJSON`. The browser serialises this; we re-parse the
  * raw bytes (the signature commits to those exact bytes, so we never re-serialise).
  *
  * @param `type`
  *   must be `"webauthn.get"` for an assertion.
  * @param challenge
  *   base64url (no padding) of the server-issued challenge.
  * @param origin
  *   the requesting origin, e.g. `"https://example.com"`.
  * @param crossOrigin
  *   whether the ceremony ran in an iframe whose origin differs from its ancestors'. `false` when
  *   absent.
  */
final case class ClientData(
  `type`: String,
  challenge: String,
  origin: String,
  crossOrigin: Boolean,
)

object ClientData {

  /** Hand-written reader (no macros): tolerant of unknown/extra fields, which WebAuthn explicitly
    * allows and requires us to ignore. `type`, `challenge` and `origin` are required.
    */
  given JsonValueCodec[ClientData] =
    new JsonValueCodec[ClientData] {
      def decodeValue(in: JsonReader, default: ClientData): ClientData = {
        var typ: String = null
        var challenge: String = null
        var origin: String = null
        var crossOrigin: Boolean = false
        if (in.isNextToken('{')) {
          if (!in.isNextToken('}')) {
            in.rollbackToken()
            while ({
              in.readKeyAsString() match {
                case "type"        => typ = in.readString(null)
                case "challenge"   => challenge = in.readString(null)
                case "origin"      => origin = in.readString(null)
                case "crossOrigin" => crossOrigin = in.readBoolean()
                case _             => in.skip()
              }
              in.isNextToken(',')
            })
              ()
            if (!in.isCurrentToken('}'))
              in.objectEndOrCommaError()
          }
        } else
          in.readNullOrTokenError(default, '{')
        // Absent fields would otherwise surface as nulls and blow up downstream checks.
        if (typ == null)
          in.decodeError("missing required field: type")
        if (challenge == null)
          in.decodeError("missing required field: challenge")
        if (origin == null)
          in.decodeError("missing required field: origin")
        ClientData(typ, challenge, origin, crossOrigin)
      }

      def encodeValue(x: ClientData, out: JsonWriter): Unit =
        sys.error("ClientData is parse-only")

      def nullValue: ClientData = null
    }

  def parse(jsonBytes: Array[Byte]): Either[String, ClientData] =
    // No hex dump: the message would otherwise echo attacker-controlled bytes into logs.
    try Right(
        readFromArray[ClientData](jsonBytes, ReaderConfig.withAppendHexDumpToParseException(false))
      )
    catch { case e: JsonReaderException => Left(s"clientDataJSON parse error: ${e.getMessage}") }

}
