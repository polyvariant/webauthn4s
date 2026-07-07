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

// True on the Linux CI runners, where we fetch OpenSSL from brew and have to
// work around its glibc (see the Native settings below).
lazy val isCiLinux: Boolean =
  sys.env.contains("CI") && sys.props.getOrElse("os.name", "").toLowerCase.contains("linux")

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
    nativeBrewFormulas += "openssl",
    // On CI we install OpenSSL via brew (Ubuntu's system libcrypto returns null
    // from EVP_get_digestbyname). Two problems follow, both fixed here for the
    // CI/Linux case:
    //
    //  1. The brew config plugin sets LD_LIBRARY_PATH to brew's lib dir for the
    //     test run, which drags in brew's glibc 2.39 and segfaults the binary at
    //     startup (SIGSEGV before any test runs). We strip LD_LIBRARY_PATH from
    //     the test env so the executable runs against the system glibc.
    //  2. Without LD_LIBRARY_PATH the dynamic -lcrypto can't be found at runtime,
    //     so we link libcrypto statically instead.
    nativeConfig := {
      val prev = nativeConfig.value
      if (isCiLinux)
        prev.withLinkingOptions(
          prev.linkingOptions.filterNot(_ == "-lcrypto") ++
            Seq("-Wl,-Bstatic", "-lcrypto", "-Wl,-Bdynamic")
        )
      else
        prev
    },
    Test / envVars := {
      val prev = (Test / envVars).value
      if (isCiLinux)
        prev - "LD_LIBRARY_PATH"
      else
        prev
    },
  )

lazy val root = tlCrossRootProject.aggregate(webauthn4s)
