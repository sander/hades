name := "hades"
version := "0.1.0-SNAPSHOT"
scalaVersion := "2.13.4"

scalacOptions += "-Ymacro-annotations"

val bouncyCastleVersion = "1.68"

libraryDependencies ++= Seq(
  "javax.xml.bind" % "jaxb-api" % "2.3.1",
  "javax.activation" % "activation" % "1.1",
  "org.glassfish.jaxb" % "jaxb-runtime" % "2.3.1",
  "org.apache.santuario" % "xmlsec" % "2.1.5",
  "org.bouncycastle" % "bcprov-jdk15on" % bouncyCastleVersion,
  "org.bouncycastle" % "bcpkix-jdk15on" % bouncyCastleVersion,
  "org.scala-lang.modules" %% "scala-xml" % "1.3.0",
  "org.scalatest" %% "scalatest" % "3.2.2" % "test"
)
