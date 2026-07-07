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
// runner's system OpenSSL 3 (every hashing test fails). Install a compatible
// OpenSSL via brew before the Native build — the same approach fs2 uses.
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
    nativeBrewFormulas += "openssl"
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
