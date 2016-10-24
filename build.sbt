name := "ec-encryption-voodoo"
scalaVersion := "2.11.8"

libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.0" % "test"

// note, these jars are signed and cannot be feed into a fat jar
libraryDependencies += "org.bouncycastle" % "bcprov-debug-jdk15on" % "1.55" // % "provided"
libraryDependencies += "org.bouncycastle" % "bcpkix-jdk15on" % "1.55" // % "provided"
