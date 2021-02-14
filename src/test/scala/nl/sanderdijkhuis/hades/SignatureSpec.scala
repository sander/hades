package nl.sanderdijkhuis.hades

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{
  AlgorithmIdentifier,
  BasicConstraints,
  Extension,
  SubjectPublicKeyInfo
}
import org.bouncycastle.cert.X509ExtensionUtils
import org.bouncycastle.cert.jcajce.{
  JcaX509CertificateConverter,
  JcaX509v3CertificateBuilder
}
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest._
import org.scalatest.featurespec.AnyFeatureSpec
import org.scalatest.matchers.should.Matchers.convertToAnyShouldWrapper
import org.w3c.dom.ls.{DOMImplementationLS, LSInput, LSResourceResolver}
import org.xml.sax.{ErrorHandler, InputSource, SAXParseException}

import java.io.StringReader
import java.math.BigInteger
import java.net.URI
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.RSAPublicKeySpec
import java.security.{Key, KeyFactory, SecureRandom}
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.xml.XMLConstants
import javax.xml.crypto._
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.{KeyInfo, X509Data}
import javax.xml.crypto.dsig.{SignatureMethod, XMLSignatureFactory}
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.validation.SchemaFactory
import scala.jdk.CollectionConverters._
import scala.xml.{Elem, Text}

class SignatureSpec extends AnyFeatureSpec with GivenWhenThen {
  Feature("Signatures") {
    Scenario("Creating an enveloped signature") {
      Given("an XML document")
      val doc =
        <foo:document xmlns:foo="http://example.com/foo">
  <foo:greeting>Hello, world!</foo:greeting>
</foo:document>

      And("a private key and an X.509 certificate")
      val (privateKey, certificate) = generateTestKeyAndCertificate()
      val chain = Signature.X509CertificateChain(List(certificate))

      When("I prepare the document for an enveloped signature")
      val signingTime = Signature.SigningTime(Instant.now())
      val docs = List(Signature.OriginalDocument("foo.xml", doc))
      val commitment = Signature.Commitment[Signature.Enveloped](
        docs,
        chain,
        signingTime,
        Signature.CommitmentTypeId("http://example.com/test#commitment-id"),
        None,
        None
      )

      And("I sign the document")
      val sig = java.security.Signature.getInstance("SHA256withRSA")
      sig.initSign(privateKey)
      sig.update(commitment.challenge.value)
      val signatureValue = Signature.SignatureValue(sig.sign())
      val signature =
        SignatureMarshalling.marshall(commitment.prove(signatureValue).get)

      println(signature)

      Then("the results contains a ds:Signature")
      (signature \ "Signature")
        .filter(_.namespace == "http://www.w3.org/2000/09/xmldsig#")
        .length shouldBe 1
    }

    Scenario("Creating a detached signature") {
      Given("an XML document")
      val doc =
        <foo:document xmlns:foo="http://example.com/foo">
          <foo:greeting>Hello, world!</foo:greeting>
        </foo:document>

      And("a private key and an X.509 certificate")
      val (privateKey, certificate) = generateTestKeyAndCertificate()
      val chain = Signature.X509CertificateChain(List(certificate))

      When("I prepare the document for a detached signature")
      val signingTime = Signature.SigningTime(Instant.now())
      val name = "foo.xml"
      val docs = List(Signature.OriginalDocument(name, doc))
      val commitment = Signature.Commitment[Signature.Detached](
        docs,
        chain,
        signingTime,
        Signature.CommitmentTypeId("http://example.com/test#commitment-id"),
        Some(
          Signature.SignaturePolicy(URI.create("http://example.com/policy"),
                                    <policy/>)),
        Some(
          Signature.SignerRole(
            List(Signature.ClaimedRole(Text("foo"))),
            List(Signature.SignedAssertion(
              <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer/>
</saml:Assertion>))
          ))
      )

      And("I sign the document")
      val sig = java.security.Signature.getInstance("SHA256withRSA")
      sig.initSign(privateKey)
      sig.update(commitment.challenge.value)
      val signatureValue = Signature.SignatureValue(sig.sign())
      val signature =
        SignatureMarshalling.marshall(commitment.prove(signatureValue).get)

      println(signature)

      Then("the results is a ds:Signature")
      signature.namespace shouldBe "http://www.w3.org/2000/09/xmldsig#"
      signature.label shouldBe "Signature"

      And("it refers to the original document by URI")
      (signature \\ "Reference").head \@ "URI" shouldBe name

      And("the reference has only a single transform")
      ((signature \\ "Reference").head \\ "Transform").length shouldBe 1
    }
  }

  private def generateTestKeyAndCertificate()
    : (RSAPrivateKey, X509Certificate) = {
    import java.security.KeyPairGenerator
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val spki = SubjectPublicKeyInfo.getInstance(kp.getPublic.getEncoded)
    val signer =
      new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate)
    val sr = new SecureRandom() // TODO
    val serial = BigInteger.valueOf(sr.nextInt()) // TODO
    val notBefore = new Date()
    val notAfter = Date.from(notBefore.toInstant.plus(10, ChronoUnit.MINUTES))
    val calc = new BcDigestCalculatorProvider()
      .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
    val utils = new X509ExtensionUtils(calc)
    val subjectKeyIdentifier = utils.createSubjectKeyIdentifier(spki)
    val authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(spki)
    val basicConstraints = new BasicConstraints(false)
    val name = new X500Name("CN=Test")
    val params =
      PublicKeyFactory.createKey(spki).asInstanceOf[RSAKeyParameters]
    val publicKey = KeyFactory
      .getInstance("RSA")
      .generatePublic(
        new RSAPublicKeySpec(params.getModulus, params.getExponent))
    val builder = new JcaX509v3CertificateBuilder(name,
                                                  serial,
                                                  notBefore,
                                                  notAfter,
                                                  name,
                                                  publicKey)
      .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
      .addExtension(Extension.authorityKeyIdentifier,
                    false,
                    authorityKeyIdentifier)
      .addExtension(Extension.basicConstraints, true, basicConstraints)
    val converter =
      new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider)
    val certificate = converter.getCertificate(builder.build(signer))
    (kp.getPrivate.asInstanceOf[RSAPrivateKey], certificate)
  }

  // See https://www.oracle.com/technical-resources/articles/java/dig-signature-api.html
  def validateSignature(signature: Elem): Boolean = {
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setNamespaceAware(true)
    val is = new InputSource(new StringReader(signature.toString()))

    val schemaFactory =
      SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
    println(
      "Old resolver, could be used for default behavior: " + schemaFactory.getResourceResolver)
    schemaFactory.setResourceResolver(new LSResourceResolver {
      override def resolveResource(`type`: String,
                                   namespaceURI: String,
                                   publicId: String,
                                   systemId: String,
                                   baseURI: String): LSInput = systemId match {
        case "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd" => {
          val domImpl = DocumentBuilderFactory
            .newInstance()
            .newDocumentBuilder()
            .getDOMImplementation
            .getFeature("LS", "3.0")
            .asInstanceOf[DOMImplementationLS]
          val input = domImpl.createLSInput()
          input.setPublicId(publicId)
          input.setBaseURI(baseURI)
          input.setSystemId(systemId)
          input.setByteStream(
            getClass.getResourceAsStream("xmldsig-core-schema.xsd"))
          input
        }
        case id => {
          println("Could not find " + id)
          null
        }
      }
    })

    val schemaPath = getClass.getResource("/XAdES.xsd")
    val schema = schemaFactory.newSchema(schemaPath)
    dbf.setSchema(schema)

    val builder = dbf.newDocumentBuilder()
    builder.setErrorHandler(new ErrorHandler {
      override def warning(exception: SAXParseException): Unit = ???

      override def error(exception: SAXParseException): Unit =
        println("exception" + exception)

      override def fatalError(exception: SAXParseException): Unit = ???
    })
    val doc = builder.parse(is)

    val valContext = new DOMValidateContext(
      new KeySelector {
        override def select(keyInfo: KeyInfo,
                            purpose: KeySelector.Purpose,
                            method: AlgorithmMethod,
                            context: XMLCryptoContext): KeySelectorResult = {
          keyInfo.getContent
            .iterator()
            .asScala
            .collect {
              case d: X509Data => {
                d.getContent.iterator().asScala.collect {
                  case c: X509Certificate
                      if c.getPublicKey.getAlgorithm
                        .equalsIgnoreCase("RSA") && method.getAlgorithm
                        .equalsIgnoreCase(SignatureMethod.RSA_SHA256) => {
                    c.getPublicKey
                  }
                }
              }
            }
            .flatten
            .nextOption() match {
            case Some(key) =>
              new KeySelectorResult {
                override def getKey: Key = key
              }
            case _ => throw new KeySelectorException("No key found")
          }
        }
      },
      doc
        .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                                "Signature")
        .item(0)
    )
    val fac = XMLSignatureFactory.getInstance("DOM")
    val s = fac.unmarshalXMLSignature(valContext)
    s.validate(valContext)
  }
}
