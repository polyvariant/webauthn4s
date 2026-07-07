ThisBuild / tlBaseVersion := "0.1"
ThisBuild / organization := "org.polyvariant"
ThisBuild / organizationName := "Polyvariant"
ThisBuild / startYear := Some(2026)
ThisBuild / licenses := Seq(License.Apache2)
ThisBuild / developers := List(tlGitHubDev("kubukoz", "Jakub Kozłowski"))

ThisBuild / githubWorkflowPublishTargetBranches := Seq(
  RefPredicate.Equals(Ref.Branch("main")),
  RefPredicate.StartsWith(Ref.Tag("v")),
)

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / tlJdkRelease := Some(11)
ThisBuild / tlFatalWarnings := false
ThisBuild / resolvers += Resolver.sonatypeCentralSnapshots

ThisBuild / mergifyStewardConfig ~= (_.map(_.withMergeMinors(true)))

// The Native ES256/HMAC bindings link OpenSSL's libcrypto, and fs2's Native
// HMAC goes through OpenSSL's legacy `EVP_get_digestbyname`, which returns null
// on Ubuntu's OpenSSL 3 unless the default provider is activated — so every
// hashing test fails with "EVP_get_digestbyname: null". We stay on the system
// OpenSSL (matching the system glibc — brew's is built against a newer glibc and
// won't link/run here) and instead install its headers and point OPENSSL_CONF at
// a config that activates the default provider.
ThisBuild / githubWorkflowBuildPreamble += WorkflowStep.Run(
  name = Some("Set up system OpenSSL for Native"),
  cond = Some("matrix.project == 'rootNative'"),
  commands = List(
    "sudo apt-get update && sudo apt-get install -y libssl-dev",
    "printf '%s\\n' " +
      "'openssl_conf = openssl_init' " +
      "'[openssl_init]' " +
      "'providers = provider_sect' " +
      "'[provider_sect]' " +
      "'default = default_sect' " +
      "'[default_sect]' " +
      "'activate = 1' > \"$RUNNER_TEMP/openssl.cnf\"",
    "echo \"OPENSSL_CONF=$RUNNER_TEMP/openssl.cnf\" >> \"$GITHUB_ENV\"",
  ),
)

val commonSettings = Seq(
  scalacOptions ++= Seq(
    "-no-indent",
    "-Wunused:all",
  ),
  libraryDependencies ++= Seq(
    "org.scodec" %%% "scodec-core" % "2.3.3",
    "com.github.plokhotnyuk.jsoniter-scala" %%% "jsoniter-scala-core" % "2.38.17",
    "org.typelevel" %%% "cats-effect-std" % "3.7.0",
    "co.fs2" %%% "fs2-core" % "3.13.0",
    "org.scalameta" %%% "munit" % "1.2.0" % Test,
    "org.typelevel" %%% "munit-cats-effect" % "2.2.0" % Test,
  ),
)

lazy val webauthn4s = crossProject(JVMPlatform, NativePlatform)
  .crossType(CrossType.Full)
  .in(file("core"))
  .settings(
    name := "webauthn4s",
    commonSettings,
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
