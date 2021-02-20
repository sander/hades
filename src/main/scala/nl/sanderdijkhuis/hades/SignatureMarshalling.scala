package nl.sanderdijkhuis.hades

import nl.sanderdijkhuis.hades.AdvancedSignature._
import org.apache.xml.security.c14n.Canonicalizer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{GeneralName, GeneralNames, IssuerSerial}

import java.security.MessageDigest
import java.util.Base64
import scala.xml.{Elem, NodeSeq, Text}

object SignatureMarshalling {

  private val dsigNameSpace: String = "http://www.w3.org/2000/09/xmldsig#"
  private val xadesNameSpace: String = "http://uri.etsi.org/01903/v1.3.2#"
  private val canonicalizationAlgorithmIdentifier: String =
    Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS
  private val envelopedSignatureTransformIdentifier: String =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  private val digestMethodAlgorithmIdentifier: String =
    "http://www.w3.org/2001/04/xmlenc#sha256"
  private val signatureMethodAlgorithmIdentifier: String =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

  private def indentChildren(spaces: Int, children: NodeSeq): NodeSeq =
    children
      .to(LazyList)
      .zip(LazyList.continually(Text(s"\n${" " * spaces}")))
      .flatten { case (a, b) => List(a, b) }
      .dropRight(1)

  def marshall(signature: SignatureData): Elem =
    <ds:Signature xmlns:ds={dsigNameSpace} Id={signature.id.value}>
  {marshall(signature.signedInfo)}
  <ds:SignatureValue>
    {Base64.getEncoder.encodeToString(signature.signatureValue.value).replaceAll(".{72}(?=.)", "$0\n    ")}
  </ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      {signature.chain.value.map(cert => <ds:X509Certificate>
        {Base64.getEncoder.encodeToString(cert.getEncoded).replaceAll(".{72}(?=.)", "$0\n        ")}
      </ds:X509Certificate>)}
    </ds:X509Data>
  </ds:KeyInfo>
  {indentChildren(2, signature.objects.map(marshall))}
</ds:Signature>

  def marshall(signedInfo: SignedInfo): Elem =
    <ds:SignedInfo xmlns:ds={dsigNameSpace}>
    <ds:CanonicalizationMethod Algorithm={canonicalizationAlgorithmIdentifier}/>
    <ds:SignatureMethod Algorithm={signatureMethodAlgorithmIdentifier}/>
    {indentChildren(4, signedInfo.references.map(marshall))}
  </ds:SignedInfo>

  def marshall(reference: Reference): Elem =
    <ds:Reference Id={reference.referenceId.map(_.value).orNull} Type={reference.referenceType.map(_.identifier).orNull} URI={reference.uri.toString}>
      <ds:Transforms>
        {indentChildren(8, reference.transforms.map(t => <ds:Transform Algorithm={t.algorithmIdentifier}/>))}
      </ds:Transforms>
      <ds:DigestMethod Algorithm={digestMethodAlgorithmIdentifier}/>
      <ds:DigestValue>{reference.digestValue.toBase64}</ds:DigestValue>
    </ds:Reference>

  def marshall(enveloped: Enveloped): Elem =
    enveloped.envelope.value.copy(
      child = enveloped.envelope.value.child ++ Text("\n") ++ SignatureMarshalling
        .marshall(enveloped.data) ++ Text("\n\n"))

  def marshall(detached: Detached): Elem =
    marshall(detached.data)

  def marshall(properties: SignedProperties): Elem = {
    val issuer = new GeneralNames(
      new GeneralName(
        new X500Name(properties.signingCertificate.getIssuerDN.getName)))
    val issuerSerial =
      new IssuerSerial(issuer, properties.signingCertificate.getSerialNumber)

    // TODO complete SignedSignatureProperties
    // TODO should SigningTime have milliseconds?
    <xades:SignedProperties xmlns:xades={xadesNameSpace} xmlns:ds={dsigNameSpace} Id={properties.id.value}>
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{properties.signingTime.value.toString}</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <ds:DigestValue>{Base64.getEncoder.encodeToString(MessageDigest.getInstance("SHA-512").digest(properties.signingCertificate.getEncoded))}</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerialV2>{Base64.getEncoder.encodeToString(issuerSerial.getEncoded)}</xades:IssuerSerialV2>
            </xades:Cert>
          </xades:SigningCertificateV2>
          {properties.maybeSignaturePolicy.map(id => <xades:SignaturePolicyIdentifier>
            <xades:SigPolicyId>
              <xades:Identifier>{id.id.toString}</xades:Identifier>
            </xades:SigPolicyId>
            <xades:SigPolicyHash>
              <ds:DigestMethod Algorithm={digestMethodAlgorithmIdentifier}/>
              <ds:DigestValue>{Base64.getEncoder.encodeToString(MessageDigest.getInstance("SHA-256").digest(id.value.toString.getBytes))}</ds:DigestValue>
            </xades:SigPolicyHash>
          </xades:SignaturePolicyIdentifier>).orNull}
          {properties.signerRole.map(role => <xades:SignerRoleV2>
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
          {properties.objectReferences.map(ref => <xades:DataObjectFormat ObjectReference={s"#${ref.value}"}>
            <xades:MimeType>text/xml</xades:MimeType>
          </xades:DataObjectFormat>)}
          <xades:CommitmentTypeIndication>
            <xades:CommitmentTypeId>
              <xades:Identifier>{properties.commitmentTypeId.value}</xades:Identifier>
            </xades:CommitmentTypeId>
            <xades:AllSignedDataObjects/>
          </xades:CommitmentTypeIndication>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
  }

  def marshall(obj: DigitalSignatureObject): Elem =
    <ds:Object>
    {marshall(obj.value)}
  </ds:Object>

  def marshall(properties: QualifyingProperties): Elem =
    <xades:QualifyingProperties xmlns:xades={xadesNameSpace} Target={s"#${properties.target.value}"}>
      {marshall(properties.properties)}
    </xades:QualifyingProperties>
}
