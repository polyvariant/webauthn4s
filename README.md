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

- ✅ Assertion (authentication) verification: type, origin, cross-origin flag, challenge match,
  rpId hash, user-present and user-verified flags, ES256 signature, signature counter.
- ✅ Challenge issue/validate (HMAC-SHA256, TTL-bounded, single-use via a pluggable `ReplayGuard`).
- ❌ Attestation (registration) verification — out of scope. Registration is expected to
  happen out-of-band: capture the credential's public key (SPKI) once and hand it to this
  library as an expectation (see [Registration](#registration)).
- ❌ Algorithms other than ES256 (e.g. EdDSA, RS256).

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
  challenge         = /* the Challenge.Validated returned by challenge.validate(token, now) */,
)

AssertionVerifier.verify(expected, assertion) match {
  case Right(authData) => // authenticated; persist authData.counter as the next `signCount`
  case Left(reason)    => // reject; `reason` names the first failing check
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
  given ReplayGuard[IO]  <- ReplayGuard.inMemory[IO]              // single process only, see below
  challenge              <- Challenge[IO](secret, ttl = 60.seconds) // hold & pass this around
  now                    <- IO.realTime                             // FiniteDuration since epoch
  token                  <- challenge.issue(now)                    // hand `token` to the client
  // ...later, on verify:
  validated              <- challenge.validate(token, now)          // Either[String, Challenge.Validated]
} yield validated
```

`secret` must be at least 32 random bytes (e.g. `openssl rand -base64 32`, loaded from your
secret store); `Challenge.apply` fails with an `IllegalArgumentException` otherwise.

`Assertion.challenge` only accepts a `Challenge.Validated`, so a challenge taken from the
request can't be passed to `verify` by accident. If you issue and consume challenges with your
own server-side store instead, wrap them with `Challenge.Validated.trusted(bytes)`.

### Registration

Only ES256 credentials on P-256 can be verified; any other public key makes `verify` fail.
When creating credentials, restrict the algorithm so authenticators that also support others
(e.g. YubiKey 5's Ed25519) don't pick one this library can't check:

```js
navigator.credentials.create({ publicKey: { pubKeyCredParams: [{ type: "public-key", alg: -7 }], ... } })
```

Store the key as a DER SubjectPublicKeyInfo with an uncompressed point — what
`AuthenticatorAttestationResponse.getPublicKey()` returns for ES256.

### User verification

By default `verify` requires the authenticator's **user-verified (UV)** flag, not just
user-present. UP alone is a touch: anyone holding a security key (or an unlocked phone) passes.
UV means the authenticator checked a PIN, biometric or device unlock. Request it from the
browser too, with `userVerification: "required"` in the `navigator.credentials.get()` options —
the flags are signed, so the server-side check is what actually enforces it.

Physical security keys: FIDO2 keys verify users via a PIN (or a fingerprint on biometric
models); a key without a PIN set will usually make the browser prompt to create one. Legacy
U2F-only keys can't verify users at all — if you must accept them, or this login is a second
factor, set `requireUserVerification = false`.

### Signature counter

Pass the credential's stored counter as `Expectations.signCount`, and store
`authData.counter` after each successful `verify`. If either value is nonzero, the new counter
must be strictly greater, otherwise `verify` rejects with a possible-clone error. Hardware
security keys typically keep a real counter, so this is how a cloned key gets noticed; many
synced passkeys always report `0`, which passes.

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

Because Native links the system libcrypto rather than bundling one, signature verification is
only as up to date as the OpenSSL installed where you build and run — keep it patched alongside
your other OS packages. (On the JVM, the JDK's own crypto provider is used.)

## Dependencies

scodec, jsoniter-scala-core, fs2 (pure hashing — no FFI), and cats-effect-std (for the
`Hashing`/`MonadCancelThrow`/`SecureRandom` typeclasses — the library itself is
`F[_]`-polymorphic). No CBOR or COSE parsing (assertions don't need it).

## License

Apache 2.0.
