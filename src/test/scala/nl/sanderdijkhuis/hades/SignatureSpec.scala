package nl.sanderdijkhuis.hades

import nl.sanderdijkhuis.hades.Signature.SignatureId
import org.scalatest._
import org.scalatest.featurespec.AnyFeatureSpec

import java.util.UUID
import scala.xml.PrettyPrinter

class SignatureSpec extends AnyFeatureSpec with GivenWhenThen {
  Feature("Signatures") {
    Scenario("Creating an enveloped signature") {
      Given("an XML document")
      val doc =
        <foo:document xmlns:foo="http://example.com/foo">
  <foo:greeting>Hello, world!</foo:greeting>
</foo:document>;

      When("I prepare the document for signing")
      val dataToBeSigned = Signature.prepareDataToBeSigned(doc)

//      val p = new PrettyPrinter(120, 2)
//
//      println(p.format(dataToBeSigned))

      println()
      println(dataToBeSigned.toString())
    }
  }
}
