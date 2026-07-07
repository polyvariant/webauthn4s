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

// The Native ES256/HMAC bindings link OpenSSL's libcrypto, and fs2's Native HMAC
// goes through OpenSSL's legacy `EVP_get_digestbyname`, which returns null on
// Ubuntu's system OpenSSL 3 — so we install a working OpenSSL from brew instead.
// brew's OpenSSL is built against brew's newer glibc, so we install brew's glibc
// alongside it and let the binary both LINK and RUN against brew's glibc (the
// brew config plugin sets -L<brew>/lib and LD_LIBRARY_PATH consistently). The
// earlier failures came from mixing brew OpenSSL with the *system* glibc; keeping
// everything on brew's glibc avoids the version skew.
ThisBuild / githubWorkflowBuildPreamble ++= nativeBrewInstallWorkflowSteps.value
ThisBuild / nativeBrewInstallCond := Some("matrix.project == 'rootNative'")

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
  .nativeConfigure(_.enablePlugins(ScalaNativeBrewedConfigPlugin))
  .nativeSettings(
    // Install brew's OpenSSL and its glibc; the binary links and runs against
    // brew's glibc consistently (see the preamble note above).
    nativeBrewFormulas ++= Set("openssl", "glibc")
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
