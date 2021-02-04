package nl.sanderdijkhuis.hades

import org.apache.xml.security.c14n.Canonicalizer
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.util.encoders.Hex

import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.cert.X509Certificate
import java.security.spec.RSAPublicKeySpec
import java.security.{KeyFactory, MessageDigest}
import java.util.Base64
import scala.language.implicitConversions
import scala.xml.{Elem, Node, NodeSeq, Text}

case class Signature()

object Signature {

  org.apache.xml.security.Init.init()

  val dsigNameSpace: String = "http://www.w3.org/2000/09/xmldsig#"
  val xadesNameSpace: String = "http://uri.etsi.org/01903/v1.3.2#"
  val canonicalizationAlgorithmIdentifier: String =
    Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS
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
    Reference(
      Some(id),
      None,
      URI.create(""),
      List(Transform(envelopedSignatureTransformIdentifier),
           Transform(canonicalizationAlgorithmIdentifier)),
      canonicalized.digestValue
    )
  }

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
    def toXml: Node =
      <xades:QualifyingProperties xmlns:xades={xadesNameSpace} Target={s"#${target.value}"}>
      {properties.toXml}
    </xades:QualifyingProperties>
  }

  case class SignatureValue(value: Array[Byte])

  def analyzeDocument(document: Elem)
    : (SignatureId, List[Reference], List[DigitalSignatureObject]) = {

    // Hashing not for security but for identification
    val digest = new SHA3.Digest256()
    digest.update(document.toString().getBytes)
    // TODO add certificates

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
    val references = {
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
    }
    (signatureId, references, objects)
  }

  // TODO factor preparation out of this function, make a separate sign() function
  def prepareDataToBeSigned(document: Elem): OriginalDataToBeSigned = {

    // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
    // https://www.w3.org/TR/xmldsig-core1/#sec-Processing

    val (_, references, _) = analyzeDocument(document)
    originalDataToBeSigned(references)
  }

  def signDocument(document: Elem,
                   certificate: X509Certificate,
                   params: RSAKeyParameters, // TODO get from certificate
                   signature: SignatureValue): Elem = {
    val (signatureId, references, objects) = analyzeDocument(document)
    val dataToBeSigned = prepareDataToBeSigned(document)
    val sig2 = java.security.Signature.getInstance("SHA256withRSA")
    val publicKey = KeyFactory
      .getInstance("RSA")
      .generatePublic(
        new RSAPublicKeySpec(params.getModulus, params.getExponent))
    sig2.initVerify(publicKey)
    sig2.update(dataToBeSigned.value)

    if (!sig2.verify(signature.value))
      throw new Exception("Invalid signature value")

    val d = document.copy(
      child = document.child ++ Text("\n") ++ sign(signatureId,
                                                   references,
                                                   signature,
                                                   certificate,
                                                   objects,
      ).toXml ++ Text("\n\n"))

    d
  }
}
