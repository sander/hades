package nl.sanderdijkhuis.hades

import org.apache.xml.security.c14n.Canonicalizer
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
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.encoders.Hex
import org.xml.sax.{ErrorHandler, InputSource, SAXParseException}

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, StringReader}
import java.math.BigInteger
import java.net.{URI, URL}
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.RSAPublicKeySpec
import java.security.{Key, KeyFactory, MessageDigest, PrivateKey, SecureRandom}
import java.time.temporal.ChronoUnit
import java.util
import java.util.{Base64, Date, UUID}
import javax.xml.XMLConstants
import javax.xml.crypto.dsig.SignatureMethod
import javax.xml.crypto.{
  AlgorithmMethod,
  KeySelector,
  KeySelectorException,
  KeySelectorResult,
  XMLCryptoContext,
  XMLStructure
}
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.{KeyInfo, X509Data}
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.validation.SchemaFactory
import scala.language.implicitConversions
import scala.xml.{Elem, Node, NodeSeq, Text, TopScope, XML}
import scala.jdk.CollectionConverters._

case class Signature()

object Signature {
  private val key: (SubjectPublicKeyInfo, ContentSigner, PrivateKey) = {
    import java.security.KeyPairGenerator
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val kp = kpg.generateKeyPair()
    val spki = SubjectPublicKeyInfo.getInstance(kp.getPublic.getEncoded)
    val signer =
      new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate)
    (spki, signer, kp.getPrivate)
  }

  private val certificate: X509Certificate = {
    val sr = new SecureRandom() // TODO
    val serial = BigInteger.valueOf(sr.nextInt()) // TODO
    val notBefore = new Date()
    val notAfter = Date.from(notBefore.toInstant.plus(10, ChronoUnit.MINUTES))
    val calc = new BcDigestCalculatorProvider()
      .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
    val utils = new X509ExtensionUtils(calc)
    val subjectKeyIdentifier = utils.createSubjectKeyIdentifier(key._1)
    val authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(key._1)
    val basicConstraints = new BasicConstraints(false)
    val name = new X500Name("CN=Test")
    val params =
      PublicKeyFactory.createKey(key._1).asInstanceOf[RSAKeyParameters]
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
    converter.getCertificate(builder.build(key._2))
  }

  org.apache.xml.security.Init.init()

  val dsigNameSpace: String = "http://www.w3.org/2000/09/xmldsig#"
  val xadesNameSpace: String = "http://uri.etsi.org/01903/v1.3.2#"
  val canonicalizationAlgorithmIdentifier: String =
    Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS
//    Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
//    Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS // TODO make wise selection
  val envelopedSignatureTransformIdentifier: String =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  val digestMethodAlgorithmIdentifier: String =
    "http://www.w3.org/2001/04/xmlenc#sha256"
  val signatureMethodAlgorithmIdentifier: String =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

  def canonicalize(node: Node): CanonicalData = {
    val stream = new ByteArrayOutputStream()
    Canonicalizer
      .getInstance(canonicalizationAlgorithmIdentifier)
      .canonicalize(node.toString.getBytes, stream, true)
    stream.close()
    CanonicalData(stream.toByteArray)
  }

  def removeEnvelopedSignature(node: Node): Node = {
    // TODO
//    val stream = new ByteArrayOutputStream()
//    Canonicalizer
//      .getInstance(envelopedSignatureTransformIdentifier)
//      .canonicalize(node.toString.getBytes, stream, true)
//    stream.close()
//    val out = stream.toByteArray
//    XML.loadString(out.toString)
    node
  }

  def digest(input: Array[Byte]): DigestValue =
    DigestValue(MessageDigest.getInstance("SHA-256").digest(input))

  case class CanonicalData(value: Array[Byte]) {
    def digestValue: DigestValue = digest(value)
  }
  case class DigestValue(value: Array[Byte]) {
    def toBase64: String = Base64.getEncoder.encodeToString(value)
  }

  case class Transform(algorithmIdentifier: String)

  sealed trait ReferenceType {
    def identifier: String
  }
  object ReferenceType {
    case object SignedProperties extends ReferenceType {
      override def identifier: String =
        "http://uri.etsi.org/01903#SignedProperties"
    }
  }

  case class ReferenceId(value: String)

  case class Reference(referenceId: Option[ReferenceId],
                       referenceType: Option[ReferenceType],
                       uri: URI,
                       transforms: Seq[Transform],
                       digestValue: DigestValue) {
    def toXml: Elem = {
      <ds:Reference Id={referenceId.map(_.value).orNull} Type={referenceType.map(_.identifier).orNull} URI={uri.toString}>
      <ds:Transforms>
        {indentChildren(8, transforms.map(t => <ds:Transform Algorithm={t.algorithmIdentifier}/>))}
      </ds:Transforms>
      <ds:DigestMethod Algorithm={digestMethodAlgorithmIdentifier}/>
      <ds:DigestValue>{digestValue.toBase64}</ds:DigestValue>
    </ds:Reference>
    }
  }

  def generateReferenceToCurrentDocument(id: ReferenceId,
                                         node: Node): Reference = {
    val canonicalized = canonicalize(node)
    println(s"canonicalized:${new String(canonicalized.value)}")
    Reference(
      Some(id),
      None,
      URI.create(""),
      List(Transform(envelopedSignatureTransformIdentifier),
           Transform(canonicalizationAlgorithmIdentifier)),
      canonicalized.digestValue
    )
  }

  val params: RSAKeyParameters =
    PublicKeyFactory.createKey(key._1).asInstanceOf[RSAKeyParameters]

  case class DigitalSignature(id: SignatureId,
                              signedInfo: SignedInfo,
                              signatureValue: SignatureValue,
                              certificate: X509Certificate,
                              objects: Seq[DigitalSignatureObject]) {
    def toXml: Elem =
      <ds:Signature xmlns:ds={dsigNameSpace} Id={id.value}>
  {signedInfo.toXml}
  <ds:SignatureValue>
    {Base64.getEncoder.encodeToString(signatureValue.value).replaceAll(".{72}(?=.)", "$0\n    ")}
  </ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>
        {Base64.getEncoder.encodeToString(certificate.getEncoded).replaceAll(".{72}(?=.)", "$0\n        ")}
      </ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  {indentChildren(2, objects.map(_.toXml))}
</ds:Signature>
  }

  private def indentChildren(spaces: Int, children: NodeSeq): NodeSeq =
    children
      .to(LazyList)
      .zip(LazyList.continually(Text(s"\n${" " * spaces}")))
      .flatten { case (a, b) => List(a, b) }
      .dropRight(1)

  case class SignedInfo(references: Seq[Reference]) {
    def toXml: Elem =
      <ds:SignedInfo xmlns:ds={dsigNameSpace}>
    <ds:CanonicalizationMethod Algorithm={canonicalizationAlgorithmIdentifier}/>
    <ds:SignatureMethod Algorithm={signatureMethodAlgorithmIdentifier}/>
    {indentChildren(4, references.map(_.toXml))}
  </ds:SignedInfo>
  }

  /** Not yet digested */
  case class OriginalDataToBeSigned(value: Array[Byte])

  /** Not yet digested */
  def originalDataToBeSigned(
      references: Seq[Reference]): OriginalDataToBeSigned = {
    OriginalDataToBeSigned(canonicalize(SignedInfo(references).toXml).value)
  }

  def sign(signatureId: SignatureId,
           references: Seq[Reference],
           signatureValue: SignatureValue,
           certificate: X509Certificate,
           objects: Seq[DigitalSignatureObject],
  ): DigitalSignature =
    DigitalSignature(signatureId,
                     SignedInfo(references),
                     signatureValue,
                     certificate,
                     objects)

  case class XadesSignedPropertiesId(value: String) {
    def reference: URI = URI.create(s"#${value}")
  }

  case class CommitmentTypeId(value: String)

  case class XadesSignedProperties(id: XadesSignedPropertiesId,
                                   objectReference: ReferenceId,
                                   commitmentTypeId: CommitmentTypeId) {
    def toXml: Node = // TODO complete SignedSignatureProperties
      <xades:SignedProperties xmlns:xades={xadesNameSpace} Id={id.value}>
        <xades:SignedSignatureProperties>
          <xades:SigningTimef></xades:SigningTimef>
          <xades:SigningCertificateV2></xades:SigningCertificateV2>
          <xades:SignaturePolicyIdentifier></xades:SignaturePolicyIdentifier>
          <xades:SignerRoleV2></xades:SignerRoleV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference={s"#${objectReference.value}"}>
            <xades:MimeType>text/xml</xades:MimeType>
          </xades:DataObjectFormat>
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>{commitmentTypeId.value}</xades:Identifier>
            </xades:CommitmentTypeId>
          </xades:CommitmentTypeIndication>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
  }

  case class DigitalSignatureObject(value: QualifyingProperties) {
    def toXml: Node = <ds:Object>
    {value.toXml}
  </ds:Object>
  }

  case class SignatureId(value: String)

  case class QualifyingProperties(target: SignatureId,
                                  properties: XadesSignedProperties) {
    // TODO target
    def toXml: Node =
      <xades:QualifyingProperties xmlns:xades={xadesNameSpace} Target={s"#${target.value}"}>
      {properties.toXml}
    </xades:QualifyingProperties>
  }

  case class SignatureValue(value: Array[Byte])

  // TODO https://www.oracle.com/technical-resources/articles/java/dig-signature-api.html
  def validate(signature: Elem): Unit = {
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setNamespaceAware(true)
    val is = new InputSource(new StringReader(signature.toString()))

    val schemaFactory =
      SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
    val schema = schemaFactory.newSchema(
      new URL("https://uri.etsi.org/01903/v1.3.2/XAdES.xsd"))
    // import javax.xml.transform.stream.StreamSource
//    val schema: Nothing = sf.newSchema(new StreamSource(getClass.getResourceAsStream(SCHEMA_PATH)))
    dbf.setSchema(schema)

    val builder = dbf.newDocumentBuilder()
    builder.setErrorHandler(new ErrorHandler {
      override def warning(exception: SAXParseException): Unit = ???

      override def error(exception: SAXParseException): Unit =
        println("exception" + exception)

      override def fatalError(exception: SAXParseException): Unit = ???
    })
    val doc = builder.parse(is)
    println("elem" + doc.getDocumentElement)
//    doc.getDocumentElement.setIdAttribute("Id", true)

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
    import javax.xml.crypto.dsig.XMLSignatureFactory
    val fac = XMLSignatureFactory.getInstance("DOM")
    val s = fac.unmarshalXMLSignature(valContext)
    val valid = s.validate(valContext)
    println("valid?" + valid)
  }

  // TODO factor preparation out of this function, make a separate sign() function
  def prepareDataToBeSigned(document: Elem): Elem = {

//    def stripNamespaces(node: Node): Node = node match {
//      case e: Elem =>
//        e.copy(scope = TopScope, child = e.child map stripNamespaces)
//      case _ => node
//    }

    // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
    // https://www.w3.org/TR/xmldsig-core1/#sec-Processing

    // Hashing not for security but for identification
    val digest = new SHA3.Digest256()
    digest.update(document.toString().getBytes)
    // TODO add certificates

//    val id = Base64.getUrlEncoder.encodeToString(digest.digest())
    val id = new String(Hex.encode(digest.digest())).substring(0, 16)

    val signatureId = SignatureId(s"sig-id-${id}")
    val documentReferenceId = ReferenceId(s"ref-id-${id}-1")
    val xadesSignedPropertiesId = XadesSignedPropertiesId(s"xades-id-${id}")
    val xadesSignedProperties =
      XadesSignedProperties(
        xadesSignedPropertiesId,
        documentReferenceId,
        CommitmentTypeId("http://example.com/test#commitment-id"))
    val objects = List(
      DigitalSignatureObject(
        QualifyingProperties(signatureId, xadesSignedProperties))
    )

    val alteredDocument = document
      .copy(child = document.child ++ Text("\n") ++ Text("\n\n"))

    println("original" + document.child.toList)
    println("altered" + alteredDocument.child.toList)

    println(
      "xades" + new String(canonicalize(xadesSignedProperties.toXml).value))

    val references =
      List(
        generateReferenceToCurrentDocument(documentReferenceId,
                                           alteredDocument),
        Reference(
          None,
          Some(ReferenceType.SignedProperties),
          xadesSignedPropertiesId.reference,
          List(Transform(canonicalizationAlgorithmIdentifier)),
          canonicalize(xadesSignedProperties.toXml).digestValue
        )
      )

    val dataToBeSigned = originalDataToBeSigned(references)
    val privateKey = key._3.asInstanceOf[RSAPrivateKey]

    val sig = java.security.Signature.getInstance("SHA256withRSA")
    sig.initSign(privateKey)
    sig.update(dataToBeSigned.value)
    val signature = SignatureValue(sig.sign())

    val sig2 = java.security.Signature.getInstance("SHA256withRSA")
//    val params =
//      PublicKeyFactory.createKey(key._1).asInstanceOf[RSAKeyParameters]
    val publicKey = KeyFactory
      .getInstance("RSA")
      .generatePublic(
        new RSAPublicKeySpec(params.getModulus, params.getExponent))
    sig2.initVerify(publicKey)
    sig2.update(dataToBeSigned.value)
    println("result:" + sig2.verify(signature.value))
//    val x = privateKey
//
//    val signer = key._2
//    val out = signer.getOutputStream
//    println(signer.getAlgorithmIdentifier.getAlgorithm.toString)
////    out.write(dataToBeSigned.value)
//    out.write(MessageDigest.getInstance("SHA-256").digest(dataToBeSigned.value))
//    out.close()
//    val signature = SignatureValue(signer.getSignature)
    println("sign:" + new String(dataToBeSigned.value))

    val d = document.copy(
      child = document.child ++ Text("\n") ++ sign(signatureId,
                                                   references,
                                                   signature,
                                                   certificate,
                                                   objects,
      ).toXml ++ Text("\n\n"))

    println(d)

    validate(d)

    d
  }
}
