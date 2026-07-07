# webauthn4s

A small, cross-platform (JVM + Scala Native) [WebAuthn](https://www.w3.org/TR/webauthn-2/)
**assertion verifier** for Scala 3 — the server side of a passkey login.

Given the fields a browser returns from `navigator.credentials.get()` and the expected
relying-party context, it tells you whether the assertion is valid. It's pure and total:
inputs in, `Either[String, Unit]` out, never throws. The only platform-specific piece is the
ES256 signature check, which uses JCA on the JVM and OpenSSL (via FFI) on Native.

It also ships a **stateless HMAC challenge** helper so you don't need a server-side challenge
store.

## Scope

- ✅ Assertion (authentication) verification: origin, rpId hash, user-present flag,
  challenge match, ES256 signature.
- ✅ Stateless challenge issue/validate (HMAC-SHA256, TTL-bounded, no storage).
- ❌ Attestation (registration) verification — out of scope. Registration is expected to
  happen out-of-band: capture the credential's public key (SPKI) once and hand it to this
  library as an expectation.

## Usage

```scala
libraryDependencies += "org.polyvariant" %%% "webauthn4s" % "<version>"
```

```scala
import org.polyvariant.webauthn4s.AssertionVerifier
import org.polyvariant.webauthn4s.AssertionVerifier.{Assertion, Expectations}
import scodec.bits.ByteVector

val expected = Expectations(
  rpId = "example.com",
  origin = "https://example.com",
  publicKeySpki = ByteVector(/* the credential's DER SPKI public key */),
)

val assertion = Assertion(
  authenticatorData = /* bytes from the browser */,
  clientDataJson    = /* bytes from the browser */,
  signature         = /* bytes from the browser */,
  challenge         = /* the raw challenge bytes you issued */,
)

AssertionVerifier.verify(expected, assertion) match {
  case Right(())    => // authenticated
  case Left(reason) => // reject; `reason` names the first failing check
}
```

Stateless challenges. The library is `F[_]`-polymorphic: you supply the `SecureRandom[F]`
and the current time (as a `FiniteDuration` since the epoch), so it stays referentially
transparent.

```scala
import cats.effect.IO
import cats.effect.std.SecureRandom
import org.polyvariant.webauthn4s.Challenge
import scala.concurrent.duration.*

for {
  random <- SecureRandom.javaSecuritySecureRandom[IO]
  now    <- IO.realTime                                          // FiniteDuration since epoch
  token  <- Challenge.issue(random, secret, now, ttl = 60.seconds) // hand `token` to the client
  // ...later, on verify:
  raw    <- Challenge.validate[IO](secret, token, now)          // Either[String, ByteVector]
} yield raw
```

## Scala Native linking

The Native `Es256Platform` binds OpenSSL's `libcrypto`. Consuming Native builds must link it
into the final binary, e.g. in your `project.scala` / build:

```
//> using nativeLinking -lcrypto
```

libcrypto must be available at link time (it usually already is via OpenSSL).

## Dependencies

scodec, jsoniter-scala-core, fs2 (pure hashing — no FFI), and cats-effect-std (for the
`Hashing`/`MonadCancelThrow`/`SecureRandom` typeclasses — the library itself is
`F[_]`-polymorphic). No CBOR or COSE parsing (assertions don't need it).

## License

Apache 2.0.
