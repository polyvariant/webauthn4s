addSbtPlugin("org.typelevel" % "sbt-typelevel" % "0.8.6")
addSbtPlugin("org.typelevel" % "sbt-typelevel-mergify" % "0.8.6")
// sbt-scala-native-crossproject is pulled in transitively by sbt-typelevel.
addSbtPlugin("org.scala-native" % "sbt-scala-native" % "0.5.12")
// 0.4.0 depends on sbt-typelevel-github-actions 0.8.0, matching sbt-typelevel
// 0.8.6 — no eviction override needed. The plugin is enabled explicitly on the
// Native project in build.sbt (its auto-trigger doesn't fire here).
addSbtPlugin("com.armanbilge" % "sbt-scala-native-config-brew-github-actions" % "0.4.0")
