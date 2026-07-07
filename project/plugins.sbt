addSbtPlugin("org.typelevel" % "sbt-typelevel" % "0.8.6")
addSbtPlugin("org.typelevel" % "sbt-typelevel-mergify" % "0.8.6")
addSbtPlugin("org.scala-native" % "sbt-scala-native" % "0.5.12")
addSbtPlugin("org.portable-scala" % "sbt-scala-native-crossproject" % "1.3.2")
// 0.4.0 depends on sbt-typelevel-github-actions 0.8.0, matching sbt-typelevel
// 0.8.6 — no eviction override needed. The plugin is enabled explicitly on the
// Native project in build.sbt (its auto-trigger doesn't fire here).
addSbtPlugin("com.armanbilge" % "sbt-scala-native-config-brew-github-actions" % "0.4.0")
