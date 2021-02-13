package nl.sanderdijkhuis.hades

import nl.sanderdijkhuis.hades.Signature._
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
import scala.reflect.{ClassManifest, ClassTag, classTag}
import scala.xml.{Elem, Node, Text}
import scala.util.chaining._

// https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
// https://www.w3.org/TR/xmldsig-core1/#sec-Processing
sealed abstract class Signature(val data: Signature.SignatureData)
object Signature {

  org.apache.xml.security.Init.init()

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

  /** Required for e.g. SAML assertions */
  case class Enveloped(override val data: SignatureData, envelope: Envelope)
      extends Signature(data)

  case class Detached(override val data: SignatureData) extends Signature(data)

  case class SigningTime(value: Instant)

  /** Head is the signing certificate */
  case class X509CertificateChain private (value: List[X509Certificate])
  object X509CertificateChain {

    /** Ensures the list is not empty */
    def apply(head: X509Certificate,
              tail: X509Certificate*): X509CertificateChain =
      X509CertificateChain(head :: tail.toList)
  }

  case class Commitment[S <: Signature: ClassTag] private (
      documents: List[OriginalDocument],
      chain: X509CertificateChain,
      signingTime: SigningTime,
      commitmentTypeId: CommitmentTypeId,
      signaturePolicyIdentifier: Option[SignaturePolicy],
      signerRole: Option[SignerRole]) {

    lazy private val id: String = (documents.flatMap(doc =>
      List(doc.name.getBytes, doc.content.toString.getBytes)) ++
      chain.value
        .map(_.getEncoded))
      .pipe(sufficientlyUniqueIdentifier(_: _*))

    private def signatureId: SignatureId = SignatureId(s"sig-id-${id}")
    private def documentReferenceId(i: Int): ReferenceId =
      ReferenceId(s"ref-id-${id}-${i}")
    private def signedPropertiesId =
      SignedPropertiesId(s"xades-id-${id}")

    def challenge(): OriginalDataToBeSigned =
      originalDataToBeSigned(signedInfo)

    private def signedProperties = SignedProperties(
      signedPropertiesId,
      documents.zipWithIndex.map(d => documentReferenceId(d._2 + 1)),
      commitmentTypeId,
      signingTime,
      chain.value.head,
      signaturePolicyIdentifier,
      signerRole
    )

    def signedInfo: SignedInfo =
      SignedInfo(
        (implicitly[ClassTag[S]] match {
          case t if t == classTag[Enveloped] =>
            List(
              generateReferenceToDocument(
                documentReferenceId(1),
                documents.head.content
                  .copy(
                    child = documents.head.content.child ++ Text("\n") ++ Text(
                      "\n\n")),
                URI.create("")
              ))
          case t if t == classTag[Detached] =>
            documents.zipWithIndex
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
              signedPropertiesId.reference,
              List(Transform(canonicalizationAlgorithmIdentifier)),
              canonicalize(SignatureMarshalling.marshall(signedProperties)).digestValue
            )
          ))

    def objects: List[DigitalSignatureObject] =
      List(
        DigitalSignatureObject(
          QualifyingProperties(signatureId, signedProperties)))

    def prove(signature: SignatureValue): S = {
      val certificate = chain.value.head
      val nparams = certificate.getPublicKey
        .asInstanceOf[BCRSAPublicKey]
      val params =
        new RSAKeyParameters(false,
                             nparams.getModulus,
                             nparams.getPublicExponent)
      val sig2 = java.security.Signature.getInstance("SHA256withRSA")
      val publicKey = KeyFactory
        .getInstance("RSA")
        .generatePublic(
          new RSAPublicKeySpec(params.getModulus, params.getExponent))
      sig2.initVerify(publicKey)
      sig2.update(challenge().value)

      if (unsafeSettingEnableValidation && !sig2.verify(signature.value))
        throw new Exception("Invalid signature value")

      val data =
        SignatureData(signatureId, signedInfo, signature, chain, objects)

      implicitly[ClassTag[S]] match {
        case t if t == classTag[Enveloped] =>
          Enveloped(data, Envelope(documents.head.content)).asInstanceOf[S]
        case t if t == classTag[Detached] =>
          Detached(data).asInstanceOf[S]
      }
    }
  }

  case class OriginalDocument(name: String, content: Elem)

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
                       digestValue: DigestValue)

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

  case class SignedInfo(references: Seq[Reference])

  /** Not yet digested */
  case class OriginalDataToBeSigned(value: Array[Byte])

  /** Not yet digested */
  def originalDataToBeSigned(signedInfo: SignedInfo): OriginalDataToBeSigned = {
    OriginalDataToBeSigned(
      canonicalize(SignatureMarshalling.marshall(signedInfo)).value)
  }

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

  /** Deterministic */
  private def sufficientlyUniqueIdentifier(parts: Array[Byte]*): String = {
    val digest = new SHA3.Digest256()
    for (part <- parts) digest.update(part)
    new String(Hex.encode(digest.digest())).substring(0, 16)
  }
}
