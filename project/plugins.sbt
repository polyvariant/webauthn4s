addSbtPlugin("org.typelevel" % "sbt-typelevel" % "0.8.6")
addSbtPlugin("org.typelevel" % "sbt-typelevel-mergify" % "0.8.6")
addSbtPlugin("org.scala-native" % "sbt-scala-native" % "0.5.12")
addSbtPlugin("org.portable-scala" % "sbt-scala-native-crossproject" % "1.3.2")
addSbtPlugin("com.armanbilge" % "sbt-scala-native-config-brew-github-actions" % "0.3.0")

// The brew plugin depends on sbt-typelevel-github-actions 0.7.0, but
// sbt-typelevel 0.8.6 pulls 0.8.6. They're compatible (early-semver); demote the
// eviction conflict from a fatal error to a warning so the newer 0.8.6 loads and
// the brew plugin's settings actually register.
ThisBuild / libraryDependencySchemes +=
  "org.typelevel" % "sbt-typelevel-github-actions" % "early-semver"
ThisBuild / evictionErrorLevel := Level.Warn
