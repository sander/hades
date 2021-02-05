package nl.sanderdijkhuis.hades

import org.apache.xml.security.c14n.Canonicalizer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{
  GeneralName,
  GeneralNames,
  IssuerSerial,
  X509Name
}
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

  /** Issuer CA goes first, root goes last */
  case class RestOfCertificateChain(value: List[X509Certificate])

  case class SignaturePreparation private (
      documents: List[OriginalDocument],
      certificate: SigningCertificate,
      restOfCertificateChain: RestOfCertificateChain,
      signingTime: SigningTime,
      signatureType: SignatureType,
      commitmentTypeId: CommitmentTypeId,
      signaturePolicyIdentifier: Option[SignaturePolicy],
      signerRole: Option[SignerRole]) {
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
              restOfCertificateChain: RestOfCertificateChain,
              signingTime: SigningTime,
              signatureType: SignatureType,
              commitmentTypeId: CommitmentTypeId,
              signaturePolicyIdentifier: Option[SignaturePolicy],
              signerRole: Option[SignerRole]): SignaturePreparation =
    SignaturePreparation(documents,
                         certificate,
                         restOfCertificateChain,
                         signingTime,
                         signatureType,
                         commitmentTypeId,
                         signaturePolicyIdentifier,
                         signerRole)

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
                              restOfCertificateChain: RestOfCertificateChain,
                              objects: Seq[DigitalSignatureObject]) {
    def toXml: Elem =
      <ds:Signature xmlns:ds={dsigNameSpace} Id={id.value}>
  {signedInfo.toXml}
  <ds:SignatureValue>
    {Base64.getEncoder.encodeToString(signatureValue.value).replaceAll(".{72}(?=.)", "$0\n    ")}
  </ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      {(List(certificate.value) ++ restOfCertificateChain.value).map(cert => <ds:X509Certificate>
        {Base64.getEncoder.encodeToString(cert.getEncoded).replaceAll(".{72}(?=.)", "$0\n        ")}
      </ds:X509Certificate>)}
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
                   restOfCertificateChain: RestOfCertificateChain,
                   objects: Seq[DigitalSignatureObject],
  ): DigitalSignature =
    DigitalSignature(signatureId,
                     SignedInfo(references),
                     signatureValue,
                     certificate,
                     restOfCertificateChain,
                     objects)

  case class XadesSignedPropertiesId(value: String) {
    def reference: URI = URI.create(s"#${value}")
  }

  case class CommitmentTypeId(value: String)

  case class SignaturePolicy(id: URI, value: Node)

  case class ClaimedRole(value: Node)

  case class SignedAssertion(value: Node)

  case class SignerRole(claimedRoles: List[ClaimedRole],
                        signedAssertions: List[SignedAssertion])

  case class XadesSignedProperties(
      id: XadesSignedPropertiesId,
      objectReferences: List[ReferenceId],
      commitmentTypeId: CommitmentTypeId,
      signingTime: SigningTime,
      signingCertificate: SigningCertificate,
      maybeSignaturePolicy: Option[SignaturePolicy],
      signerRole: Option[SignerRole]) {
    def toXml: Node = {
      val issuer = new GeneralNames(
        new GeneralName(
          new X500Name(signingCertificate.value.getIssuerDN.getName)))
      val issuerSerial =
        new IssuerSerial(issuer, signingCertificate.value.getSerialNumber)

      // TODO complete SignedSignatureProperties
      // TODO should SigningTime have milliseconds?
      <xades:SignedProperties xmlns:xades={xadesNameSpace} xmlns:ds={dsigNameSpace} Id={id.value}>
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{signingTime.value.toString}</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>{Base64.getEncoder.encodeToString(MessageDigest.getInstance("SHA-512").digest(signingCertificate.value.getEncoded))}</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerialV2>{Base64.getEncoder.encodeToString(issuerSerial.getEncoded)}</xades:IssuerSerialV2>
            </xades:Cert>
          </xades:SigningCertificateV2>
          {maybeSignaturePolicy.map(id => <xades:SignaturePolicyIdentifier>
            <xades:SigPolicyId>
              <xades:Identifier>{id.id.toString}</xades:Identifier>
            </xades:SigPolicyId>
            <xades:SigPolicyHash>
              <ds:DigestMethod Algorithm={digestMethodAlgorithmIdentifier}/>
              <ds:DigestValue>{Base64.getEncoder.encodeToString(MessageDigest.getInstance("SHA-256").digest(id.value.toString.getBytes))}</ds:DigestValue>
            </xades:SigPolicyHash>
          </xades:SignaturePolicyIdentifier>).orNull}
          {signerRole.map(role => <xades:SignerRoleV2>
            {role.claimedRoles.length match {
            case 0 => null
            case _ => <xades:ClaimedRoles>
              {role.claimedRoles.map(role => <xades:ClaimedRole>{role.value}</xades:ClaimedRole>)}
            </xades:ClaimedRoles>
            }}
            {role.signedAssertions.length match {
              case 0 => null
              case _ => <xades:SignedAssertions>
              {role.signedAssertions.map(assertion => <xades:SignedAssertion>
{assertion.value}
              </xades:SignedAssertion>)}
            </xades:SignedAssertions>
            }}
          </xades:SignerRoleV2>).orNull}
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          {objectReferences.map(ref => <xades:DataObjectFormat ObjectReference={s"#${ref.value}"}>
            <xades:MimeType>text/xml</xades:MimeType>
          </xades:DataObjectFormat>)}
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>{commitmentTypeId.value}</xades:Identifier>
            </xades:CommitmentTypeId>
            <xades:AllSignedDataObjects/>
          </xades:CommitmentTypeIndication>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
    }
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
        preparation.commitmentTypeId,
        preparation.signingTime,
        preparation.certificate,
        preparation.signaturePolicyIdentifier,
        preparation.signerRole
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
      sign(signatureId,
           references,
           signature,
           certificate,
           preparation.restOfCertificateChain,
           objects).toXml
    preparation.signatureType match {
      case SignatureType.Enveloped =>
        preparation.documents.head.content.copy(
          child = preparation.documents.head.content.child ++ Text("\n") ++ dsSignature ++ Text(
            "\n\n"))
      case SignatureType.Detached => dsSignature
    }
  }
}
