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

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*

/** OpenSSL bindings for ES256 verify. Opaque handles (`EVP_MD_CTX*`, `EVP_PKEY*`, `EVP_MD*`,
  * `ENGINE*`) are represented as `Ptr[Byte]` — we only pass them back, never dereference.
  *
  * Consumers must link OpenSSL's libcrypto into the final Native binary (`-lcrypto`); this library
  * only declares the `@extern` bindings.
  */
@link("crypto")
@extern
private object openssl {
  // EVP_MD_CTX *EVP_MD_CTX_new(void);
  def EVP_MD_CTX_new(): Ptr[Byte] = extern
  // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
  def EVP_MD_CTX_free(ctx: Ptr[Byte]): Unit = extern
  // const EVP_MD *EVP_sha256(void);
  def EVP_sha256(): Ptr[Byte] = extern

  // int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
  //                          const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
  def EVP_DigestVerifyInit(
    ctx: Ptr[Byte],
    pctx: Ptr[Ptr[Byte]],
    md: Ptr[Byte],
    e: Ptr[Byte],
    pkey: Ptr[Byte],
  ): CInt = extern

  // int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
  //                      const unsigned char *tbs, size_t tbslen);
  def EVP_DigestVerify(
    ctx: Ptr[Byte],
    sig: Ptr[Byte],
    siglen: CSize,
    tbs: Ptr[Byte],
    tbslen: CSize,
  ): CInt = extern

  // EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length);
  def d2i_PUBKEY(a: Ptr[Ptr[Byte]], pp: Ptr[Ptr[Byte]], length: CLong): Ptr[Byte] = extern
  // void EVP_PKEY_free(EVP_PKEY *pkey);
  def EVP_PKEY_free(pkey: Ptr[Byte]): Unit = extern
}

/** Native ES256 verify via OpenSSL `EVP_DigestVerify`. `EVP_sha256()` hashes `message` internally
  * and the signature is the DER ECDSA form, matching the JVM JCA branch.
  *
  * The whole verify is a self-contained call into C (allocations, FFI), so the worker is named
  * `verifyUnsafe`; `Es256.verifySig` is the pure, total boundary over it.
  */
private[webauthn4s] object Es256Platform {

  def verify(publicKeySpki: Array[Byte], message: Array[Byte], signature: Array[Byte]): Boolean =
    Zone {
      verifyUnsafe(publicKeySpki, message, signature)
    }

  private def verifyUnsafe(
    publicKeySpki: Array[Byte],
    message: Array[Byte],
    signature: Array[Byte],
  )(
    using Zone
  ): Boolean = {
    val spkiPtr: Ptr[Byte] = bytesToNative(publicKeySpki)
    val msgPtr: Ptr[Byte] = bytesToNative(message)
    val sigPtr: Ptr[Byte] = bytesToNative(signature)

    // d2i_PUBKEY advances *pp, so hand it a separate pointer-to-pointer.
    val ppIn: Ptr[Ptr[Byte]] = alloc[Ptr[Byte]]()
    !ppIn = spkiPtr
    val pkey = openssl.d2i_PUBKEY(null, ppIn, publicKeySpki.length.toCSSize)
    if (pkey == null)
      false
    else
      try {
        val ctx = openssl.EVP_MD_CTX_new()
        if (ctx == null)
          false
        else
          try {
            val initRc = openssl.EVP_DigestVerifyInit(ctx, null, openssl.EVP_sha256(), null, pkey)
            if (initRc != 1)
              false
            else
              // 1 = valid, 0 = invalid, <0 = error — only 1 is a pass.
              openssl.EVP_DigestVerify(
                ctx,
                sigPtr,
                signature.length.toCSize,
                msgPtr,
                message.length.toCSize,
              ) == 1
          } finally openssl.EVP_MD_CTX_free(ctx)
      } finally openssl.EVP_PKEY_free(pkey)
  }

  /** Copy a (possibly empty) byte array into the enclosing Zone. Plain mutation is fine here — it's
    * a private, scoped native buffer fill, not logic.
    */
  private def bytesToNative(
    bytes: Array[Byte]
  )(
    using Zone
  ): Ptr[Byte] = {
    val p: Ptr[Byte] = alloc[Byte](bytes.length.max(1))
    var i = 0
    while (i < bytes.length) {
      p(i) = bytes(i)
      i += 1
    }
    p
  }

}
