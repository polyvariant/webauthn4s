ThisBuild / tlBaseVersion := "0.2"
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

// The Native ES256 FFI and fs2's Native hashing link the system OpenSSL
// (`-lcrypto`); the runner only lacks the dev headers/symlink. The old
// "EVP_get_digestbyname: null" failure was a digest-name issue (see
// Sha256Platform on Native), not a broken system OpenSSL — no brew needed.
ThisBuild / githubWorkflowBuildPreamble += WorkflowStep.Run(
  name = Some("Install OpenSSL headers for Native"),
  cond = Some("matrix.project == 'rootNative'"),
  commands = List("sudo apt-get update && sudo apt-get install -y libssl-dev"),
)

val commonSettings = Seq(
  scalacOptions ++= Seq(
    "-no-indent",
    "-Wunused:all",
  ),
  libraryDependencies ++= Seq(
    "org.scodec" %%% "scodec-core" % "2.3.3",
    "com.github.plokhotnyuk.jsoniter-scala" %%% "jsoniter-scala-core" % "2.41.0",
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
  .nativeSettings(
    // macOS ships no libcrypto to link against. Locally, either the toolchain
    // provides one (nix devshell via clang's NIX_LDFLAGS, or LIBRARY_PATH), or
    // we fall back to brew's OpenSSL if installed. On Linux, `-lcrypto`
    // resolves against the system OpenSSL (libssl-dev) directly.
    nativeConfig := {
      val prev = nativeConfig.value
      val brewOpenssl =
        if (scala.util.Properties.isMac)
          scala
            .util
            .Try(scala.sys.process.Process(List("brew", "--prefix", "openssl")).!!.trim)
            .toOption
            .filter(prefix => java.nio.file.Files.isDirectory(java.nio.file.Paths.get(prefix)))
        else
          None
      brewOpenssl
        .fold(prev)(prefix => prev.withLinkingOptions(prev.linkingOptions :+ s"-L$prefix/lib"))
    }
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
