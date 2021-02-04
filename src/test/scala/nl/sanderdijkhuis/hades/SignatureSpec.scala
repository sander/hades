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
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest._
import org.scalatest.featurespec.AnyFeatureSpec
import org.w3c.dom.ls.{DOMImplementationLS, LSInput, LSResourceResolver}
import org.xml.sax.{ErrorHandler, InputSource, SAXParseException}

import java.io.StringReader
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.RSAPublicKeySpec
import java.security.{Key, KeyFactory, PrivateKey, SecureRandom}
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.xml.XMLConstants
import javax.xml.crypto._
import javax.xml.crypto.dsig.{SignatureMethod, XMLSignatureFactory}
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.{KeyInfo, X509Data}
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.validation.SchemaFactory
import scala.jdk.CollectionConverters._
import scala.xml.Elem

class SignatureSpec extends AnyFeatureSpec with GivenWhenThen {
  Feature("Signatures") {
    Scenario("Creating an enveloped signature") {
      Given("an XML document")
      val doc =
        <foo:document xmlns:foo="http://example.com/foo">
  <foo:greeting>Hello, world!</foo:greeting>
</foo:document>;

      When("I prepare the document for signing")
      val dataToBeSigned = Signature.prepareDataToBeSigned(doc, testCertificate)

      And("I sign the document")
      val privateKey = testKey._3.asInstanceOf[RSAPrivateKey]

      val sig = java.security.Signature.getInstance("SHA256withRSA")
      sig.initSign(privateKey)
      sig.update(dataToBeSigned.value)
      val signatureValue = Signature.SignatureValue(sig.sign())
      val signature =
        Signature.signDocument(doc, testCertificate, signatureValue)

      println(signature)
    }
  }

  private val testKey: (SubjectPublicKeyInfo, ContentSigner, PrivateKey) = {
    import java.security.KeyPairGenerator
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val spki = SubjectPublicKeyInfo.getInstance(kp.getPublic.getEncoded)
    val signer =
      new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate)
    (spki, signer, kp.getPrivate)
  }

  private val testCertificate: X509Certificate = {
    val sr = new SecureRandom() // TODO
    val serial = BigInteger.valueOf(sr.nextInt()) // TODO
    val notBefore = new Date()
    val notAfter = Date.from(notBefore.toInstant.plus(10, ChronoUnit.MINUTES))
    val calc = new BcDigestCalculatorProvider()
      .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
    val utils = new X509ExtensionUtils(calc)
    val subjectKeyIdentifier = utils.createSubjectKeyIdentifier(testKey._1)
    val authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(testKey._1)
    val basicConstraints = new BasicConstraints(false)
    val name = new X500Name("CN=Test")
    val params =
      PublicKeyFactory.createKey(testKey._1).asInstanceOf[RSAKeyParameters]
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
    converter.getCertificate(builder.build(testKey._2))
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
