package nl.sanderdijkhuis.hades

import org.apache.xml.security.c14n.Canonicalizer
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.util.encoders.Hex

import java.net.URI
import java.security.cert.X509Certificate
import java.security.spec.RSAPublicKeySpec
import java.security.{KeyFactory, MessageDigest, PublicKey}
import java.time.Instant
import java.util.Base64
import scala.language.implicitConversions
import scala.util.chaining._
import scala.xml.{Elem, Node, Text}

// https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
// https://www.w3.org/TR/xmldsig-core1/#sec-Processing
sealed abstract class AdvancedSignature(
    val data: AdvancedSignature.SignatureData)
object AdvancedSignature {
  var unsafeSettingEnableValidation: Boolean = true

  private val canonicalizationAlgorithmIdentifier: String =
    Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS
  private val envelopedSignatureTransformIdentifier: String =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

  case class Envelope(value: Elem)

  case class SignatureData(id: SignatureId,
                           signedInfo: SignedInfo,
                           signatureValue: SignatureValue,
                           chain: X509CertificateChain,
                           objects: Seq[DigitalSignatureObject])

  case class SigningTime(value: Instant)

  case class X509CertificateChain private (value: List[X509Certificate]) {

    def head: X509Certificate = value.head
  }
  object X509CertificateChain {

    def apply(head: X509Certificate,
              tail: X509Certificate*): X509CertificateChain =
      X509CertificateChain(head :: tail.toList)
  }

  case class Commitment[S <: AdvancedSignature](
      documents: List[OriginalDocument],
      chain: X509CertificateChain,
      signingTime: SigningTime,
      commitmentTypeId: CommitmentTypeId,
      signaturePolicyIdentifier: Option[SignaturePolicy] = None,
      signerRole: Option[SignerRole] = None)(implicit wrapper: Processing[S]) {

    private def sufficientlyUniqueIdentifier(parts: Array[Byte]*): String =
      new SHA3.Digest256()
        .tap(d => parts.foreach(d.update))
        .pipe(d => new String(Hex.encode(d.digest())).substring(0, 16))

    lazy private val id: String = (documents.flatMap(doc =>
      List(doc.name.getBytes, doc.content.toString.getBytes)) ++
      chain.value
        .map(_.getEncoded))
      .pipe(sufficientlyUniqueIdentifier(_: _*))

    private def signatureId: SignatureId = SignatureId(s"sig-id-${id}")
    def documentReferenceId(i: Int): ReferenceId =
      ReferenceId(s"ref-id-${id}-${i}")
    private def signedPropertiesId =
      SignedPropertiesId(s"xades-id-${id}")

    def challenge(): OriginalDataToBeSigned = signedInfo.originalDataToBeSigned

    private def signedProperties = SignedProperties(
      signedPropertiesId,
      documents.zipWithIndex.map(d => documentReferenceId(d._2 + 1)),
      commitmentTypeId,
      signingTime,
      chain.value.head,
      signaturePolicyIdentifier,
      signerRole
    )

    private def signedInfo: SignedInfo =
      SignedInfo(
        wrapper.references(this) ++
          List(
            Reference(
              None,
              Some(ReferenceType.SignedProperties),
              signedPropertiesId.reference,
              List(Transform(canonicalizationAlgorithmIdentifier)),
              canonicalize(SignatureMarshalling.marshall(signedProperties)).digestValue
            )
          ))

    private def objects: List[DigitalSignatureObject] =
      List(
        DigitalSignatureObject(
          QualifyingProperties(signatureId, signedProperties)))

    private def publicKey: PublicKey =
      chain.value.head.getPublicKey
        .asInstanceOf[BCRSAPublicKey]
        .pipe(k => new RSAPublicKeySpec(k.getModulus, k.getPublicExponent))
        .pipe(KeyFactory.getInstance("RSA").generatePublic)

    private def verify(signatureValue: SignatureValue): Boolean =
      java.security.Signature
        .getInstance("SHA256withRSA")
        .tap(_.initVerify(publicKey))
        .tap(_.update(challenge().value))
        .verify(signatureValue.value)

    def prove(signature: SignatureValue): Option[S] =
      Option.unless(unsafeSettingEnableValidation && !verify(signature))(
        SignatureData(signatureId, signedInfo, signature, chain, objects).pipe(
          wrapper.signature(this, _)))
  }

  /** Required for e.g. SAML assertions */
  case class Enveloped(override val data: SignatureData, envelope: Envelope)
      extends AdvancedSignature(data) {

    def toXml: Node = SignatureMarshalling.marshall(this)
  }

  case class Detached(override val data: SignatureData)
      extends AdvancedSignature(data) {

    def toXml: Node = SignatureMarshalling.marshall(this)
  }

  trait Processing[S <: AdvancedSignature] {
    def references(commitment: Commitment[S]): List[Reference]
    def signature(commitment: Commitment[S], data: SignatureData): S
  }

  implicit object EnvelopedProcessing extends Processing[Enveloped] {
    override def references(
        commitment: Commitment[Enveloped]): List[Reference] =
      List(
        generateReferenceToDocument(
          commitment.documentReferenceId(1),
          commitment.documents.head.content
            .copy(
              child = commitment.documents.head.content.child ++ Text("\n") ++ Text(
                "\n\n")),
          URI.create("")
        ))

    override def signature(commitment: Commitment[Enveloped],
                           data: SignatureData): Enveloped =
      Enveloped(data, Envelope(commitment.documents.head.content))
  }

  implicit object DetachedProcessing extends Processing[Detached] {
    override def references(commitment: Commitment[Detached]): List[Reference] =
      commitment.documents.zipWithIndex
        .map(
          d =>
            generateReferenceToDocument(
              commitment.documentReferenceId(d._2 + 1),
              d._1.content,
              URI.create(d._1.name)))

    override def signature(commitment: Commitment[Detached],
                           data: SignatureData): Detached = Detached(data)
  }

  case class OriginalDocument(name: String, content: Elem)

  private def canonicalize(node: Node): CanonicalData = {
    org.apache.xml.security.Init.init()
    Canonicalizer
      .getInstance(canonicalizationAlgorithmIdentifier)
      .canonicalize(node.toString.getBytes)
      .pipe(CanonicalData)
  }

  case class CanonicalData(value: Array[Byte]) {
    def digestValue: DigestValue =
      MessageDigest.getInstance("SHA-256").digest(value).pipe(DigestValue)
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
                       digestValue: DigestValue)

  private def generateReferenceToDocument(id: ReferenceId,
                                          node: Node,
                                          uri: URI): Reference =
    Reference(
      Some(id),
      None,
      uri,
      (uri match {
        case u if u == URI.create("") =>
          List(Transform(envelopedSignatureTransformIdentifier))
        case _ => List.empty
      }) ++ List(Transform(canonicalizationAlgorithmIdentifier)),
      canonicalize(node).digestValue
    )

  case class SignedInfo(references: Seq[Reference]) {
    def originalDataToBeSigned: OriginalDataToBeSigned =
      OriginalDataToBeSigned(
        canonicalize(SignatureMarshalling.marshall(this)).value)
  }

  /** Not yet digested */
  case class OriginalDataToBeSigned private (value: Array[Byte])

  case class SignedPropertiesId(value: String) {
    def reference: URI = URI.create(s"#${value}")
  }

  case class CommitmentTypeId(value: String)

  case class SignaturePolicy(id: URI, value: Node)

  case class ClaimedRole(value: Node)

  case class SignedAssertion(value: Node)

  case class SignerRole(claimedRoles: List[ClaimedRole],
                        signedAssertions: List[SignedAssertion])

  case class SignedProperties(id: SignedPropertiesId,
                              objectReferences: List[ReferenceId],
                              commitmentTypeId: CommitmentTypeId,
                              signingTime: SigningTime,
                              signingCertificate: X509Certificate,
                              maybeSignaturePolicy: Option[SignaturePolicy],
                              signerRole: Option[SignerRole])

  case class DigitalSignatureObject(value: QualifyingProperties)

  case class SignatureId(value: String)

  case class QualifyingProperties(target: SignatureId,
                                  properties: SignedProperties)

  case class SignatureValue(value: Array[Byte])
}
