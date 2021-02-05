package nl.sanderdijkhuis.hades

import org.apache.xml.security.c14n.Canonicalizer
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.util.encoders.Hex

import java.net.URI
import java.security.cert.X509Certificate
import java.security.spec.RSAPublicKeySpec
import java.security.{KeyFactory, MessageDigest}
import java.time.Instant
import java.util.Base64
import scala.language.implicitConversions
import scala.xml.{Elem, Node, NodeSeq, Text}

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

  case class SigningTime(value: Instant)

  case class SigningCertificate(value: X509Certificate)

  case class SignaturePreparation private (documents: List[OriginalDocument],
                                           certificate: SigningCertificate,
                                           signingTime: SigningTime,
                                           signatureType: SignatureType) {
    def dataToBeSigned: OriginalDataToBeSigned = {
      // https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
      // https://www.w3.org/TR/xmldsig-core1/#sec-Processing

      val (_, references, _) = analyzeDocument(this)
      originalDataToBeSigned(references)
    }
  }

  sealed trait SignatureType
  object SignatureType {
    case object Enveloped extends SignatureType
    case object Detached extends SignatureType
  }

  case class OriginalDocument(name: String, content: Elem)

  def prepare(documents: List[OriginalDocument],
              certificate: SigningCertificate,
              signingTime: SigningTime,
              signatureType: SignatureType = SignatureType.Enveloped)
    : SignaturePreparation =
    SignaturePreparation(documents, certificate, signingTime, signatureType)

  def canonicalize(node: Node): CanonicalData = {
    CanonicalData(
      Canonicalizer
        .getInstance(canonicalizationAlgorithmIdentifier)
        .canonicalize(node.toString.getBytes))
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

  private def generateReferenceToDocument(id: ReferenceId,
                                          node: Node,
                                          uri: URI): Reference = {
    val canonicalized = canonicalize(node)
    Reference(
      Some(id),
      None,
      uri,
      (uri match {
        case u if u == URI.create("") =>
          List(Transform(envelopedSignatureTransformIdentifier))
        case _ => List.empty
      }) ++ List(Transform(canonicalizationAlgorithmIdentifier)),
      canonicalized.digestValue
    )
  }

  case class DigitalSignature(id: SignatureId,
                              signedInfo: SignedInfo,
                              signatureValue: SignatureValue,
                              certificate: SigningCertificate,
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
        {Base64.getEncoder.encodeToString(certificate.value.getEncoded).replaceAll(".{72}(?=.)", "$0\n        ")}
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

  private def sign(signatureId: SignatureId,
                   references: Seq[Reference],
                   signatureValue: SignatureValue,
                   certificate: SigningCertificate,
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
                                   objectReferences: List[ReferenceId],
                                   commitmentTypeId: CommitmentTypeId,
                                   signingTime: SigningTime) {
    def toXml: Node = // TODO complete SignedSignatureProperties
      // TODO should SigningTime have milliseconds?
      <xades:SignedProperties xmlns:xades={xadesNameSpace} Id={id.value}>
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{signingTime.value.toString}</xades:SigningTime>
          <xades:SigningCertificateV2></xades:SigningCertificateV2>
          <xades:SignaturePolicyIdentifier></xades:SignaturePolicyIdentifier>
          <xades:SignerRoleV2></xades:SignerRoleV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          {objectReferences.map(ref => <xades:DataObjectFormat ObjectReference={s"#${ref.value}"}>
            <xades:MimeType>text/xml</xades:MimeType>
          </xades:DataObjectFormat>)}
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

  def analyzeDocument(preparation: SignaturePreparation)
    : (SignatureId, List[Reference], List[DigitalSignatureObject]) = {

    // Hashing not for security but for identification
    val digest = new SHA3.Digest256()
    for (doc <- preparation.documents) {
      digest.update(doc.name.getBytes())
      digest.update(doc.content.toString().getBytes)
      digest.update(preparation.certificate.value.getEncoded)
    }

//    val document = preparation.document

    val id = new String(Hex.encode(digest.digest())).substring(0, 16)

    val signatureId = SignatureId(s"sig-id-${id}")
    def documentReferenceId(i: Int) = ReferenceId(s"ref-id-${id}-${i}")
    val xadesSignedPropertiesId = XadesSignedPropertiesId(s"xades-id-${id}")
    val xadesSignedProperties =
      XadesSignedProperties(
        xadesSignedPropertiesId,
        preparation.documents.zipWithIndex.map(d =>
          documentReferenceId(d._2 + 1)),
        CommitmentTypeId("http://example.com/test#commitment-id"),
        preparation.signingTime
      )
    val objects = List(
      DigitalSignatureObject(
        QualifyingProperties(signatureId, xadesSignedProperties))
    )
    val references =
      (preparation.signatureType match {
        case SignatureType.Enveloped =>
          List(
            generateReferenceToDocument(
              documentReferenceId(1),
              preparation.documents.head.content
                .copy(child = preparation.documents.head.content.child ++ Text(
                  "\n") ++ Text("\n\n")),
              URI.create("")
            ))
        case SignatureType.Detached =>
          preparation.documents.zipWithIndex
            .map(
              d =>
                generateReferenceToDocument(documentReferenceId(d._2 + 1),
                                            d._1.content,
                                            URI.create(d._1.name)))
      }) ++
        List(
          Reference(
            None,
            Some(ReferenceType.SignedProperties),
            xadesSignedPropertiesId.reference,
            List(Transform(canonicalizationAlgorithmIdentifier)),
            canonicalize(xadesSignedProperties.toXml).digestValue
          )
        )

    (signatureId, references, objects)
  }

  def sign(preparation: SignaturePreparation,
           signature: SignatureValue): Elem = {
    val certificate = preparation.certificate
    val (signatureId, references, objects) = analyzeDocument(preparation)
    val nparams = certificate.value.getPublicKey
      .asInstanceOf[BCRSAPublicKey]
    val params =
      new RSAKeyParameters(false, nparams.getModulus, nparams.getPublicExponent)
    val dataToBeSigned = preparation.dataToBeSigned
    val sig2 = java.security.Signature.getInstance("SHA256withRSA")
    val publicKey = KeyFactory
      .getInstance("RSA")
      .generatePublic(
        new RSAPublicKeySpec(params.getModulus, params.getExponent))
    sig2.initVerify(publicKey)
    sig2.update(dataToBeSigned.value)

    if (!sig2.verify(signature.value))
      throw new Exception("Invalid signature value")

    val dsSignature =
      sign(signatureId, references, signature, certificate, objects).toXml
    preparation.signatureType match {
      case SignatureType.Enveloped =>
        preparation.documents.head.content.copy(
          child = preparation.documents.head.content.child ++ Text("\n") ++ dsSignature ++ Text(
            "\n\n"))
      case SignatureType.Detached => dsSignature
    }
  }
}
