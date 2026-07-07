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
// HMAC goes through OpenSSL's `EVP_get_digestbyname`, which returns null on the
// runner's system OpenSSL 3 (every hashing test then fails). Install a working
// OpenSSL via brew before the Native build and export its prefix; the Native
// project links libcrypto statically from there (see the nativeConfig below).
ThisBuild / githubWorkflowBuildPreamble += WorkflowStep.Run(
  name = Some("Install OpenSSL for Native"),
  cond = Some("matrix.project == 'rootNative'"),
  commands = List(
    "/home/linuxbrew/.linuxbrew/bin/brew install openssl",
    "echo \"WEBAUTHN4S_OPENSSL_PREFIX=$(/home/linuxbrew/.linuxbrew/bin/brew --prefix openssl)\" >> \"$GITHUB_ENV\"",
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
  .nativeSettings(
    // Ubuntu's system libcrypto returns null from EVP_get_digestbyname (fs2's
    // Native HMAC path), so on CI we install a working OpenSSL via brew (see the
    // preamble step in `nativeCiBrewOpensslStep`). We must NOT use brew's broad
    // `-L<brew>/lib` on the link line, though: that also links brew's glibc 2.39,
    // and the binary then won't run against the runner's system glibc 2.35
    // ("GLIBC_2.38 not found"). Instead point only at OpenSSL's own keg and link
    // libcrypto *statically* by absolute path, so nothing from brew (glibc
    // included) is needed at runtime.
    nativeConfig := {
      val prev = nativeConfig.value
      sys.env.get("WEBAUTHN4S_OPENSSL_PREFIX") match {
        case Some(prefix) =>
          prev
            .withCompileOptions(prev.compileOptions :+ s"-I$prefix/include")
            .withLinkingOptions(
              prev.linkingOptions.filterNot(_ == "-lcrypto") :+ s"$prefix/lib/libcrypto.a"
            )
        case None => prev
      }
    }
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
