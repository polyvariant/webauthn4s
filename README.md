# webauthn4s

A small, cross-platform (JVM + Scala Native) [WebAuthn](https://www.w3.org/TR/webauthn-2/)
**assertion verifier** for Scala 3 — the server side of a passkey login.

Given the fields a browser returns from `navigator.credentials.get()` and the expected
relying-party context, it tells you whether the assertion is valid. It's pure and total:
inputs in, `Either[String, Unit]` out, never throws. The only platform-specific piece is the
ES256 signature check, which uses JCA on the JVM and OpenSSL (via FFI) on Native.

It also ships an **HMAC challenge** helper: tokens are self-validating, so the only server-side
state is a short-lived set of already-used challenges (see [Replay protection](#replay-protection)).

## Scope

- ✅ Assertion (authentication) verification: origin, rpId hash, user-present flag,
  challenge match, ES256 signature.
- ✅ Challenge issue/validate (HMAC-SHA256, TTL-bounded, single-use via a pluggable `ReplayGuard`).
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

Challenges. The library is `F[_]`-polymorphic: you build a `Challenge[F]` over a fixed secret
and TTL (with an ambient `SecureRandom[F]` and `ReplayGuard[F]`), then pass it around. You supply the
current time (as a `FiniteDuration` since the epoch) per call, so it stays referentially
transparent.

```scala
import cats.effect.IO
import cats.effect.std.SecureRandom
import org.polyvariant.webauthn4s.Challenge
import org.polyvariant.webauthn4s.ReplayGuard
import scala.concurrent.duration.*

for {
  given SecureRandom[IO] <- SecureRandom.javaSecuritySecureRandom[IO]
  given ReplayGuard[IO]  <- ReplayGuard.inMemory[IO]  // single process only, see below
  challenge = Challenge[IO](secret, ttl = 60.seconds)  // hold & pass this around
  now      <- IO.realTime                              // FiniteDuration since epoch
  token    <- challenge.issue(now)                     // hand `token` to the client
  // ...later, on verify:
  raw      <- challenge.validate(token, now)            // Either[String, ByteVector]
} yield raw
```

### Replay protection

An HMAC token is valid until its `exp`, so on its own nothing stops the same token — together
with an assertion signed over it — from being submitted twice. `Challenge.validate` therefore
consumes each challenge through a `ReplayGuard[F]`, and rejects a second use with
`"challenge already used"`.

- `ReplayGuard.inMemory` is enough when every verify request reaches the same process.
- With several instances (or serverless), implement `ReplayGuard` over a shared store — e.g.
  Redis `SET challenge 1 NX PXAT exp`, or an insert into a table with a unique key. Entries can
  be dropped after `exp`, since the token itself is rejected from then on.
- `ReplayGuard.disabled` turns the check off. Only use it if you accept replay within the TTL.

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
