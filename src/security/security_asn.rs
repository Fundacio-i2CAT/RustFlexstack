#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts103097_extension_module {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::*;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiOriginatingHeaderInfoExtension {
        #[rasn(value("0..=255"))]
        pub id: u8,
        pub content: Any,
    }
    impl EtsiOriginatingHeaderInfoExtension {
        pub fn new(id: u8, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941CrlRequest {
        #[rasn(identifier = "issuerId")]
        pub issuer_id: HashedId8,
        #[rasn(identifier = "lastKnownUpdate")]
        pub last_known_update: Option<Time32>,
    }
    impl EtsiTs102941CrlRequest {
        pub fn new(issuer_id: HashedId8, last_known_update: Option<Time32>) -> Self {
            Self {
                issuer_id,
                last_known_update,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941CtlRequest {
        #[rasn(identifier = "issuerId")]
        pub issuer_id: HashedId8,
        #[rasn(identifier = "lastKnownCtlSequence")]
        pub last_known_ctl_sequence: Option<Uint8>,
    }
    impl EtsiTs102941CtlRequest {
        pub fn new(issuer_id: HashedId8, last_known_ctl_sequence: Option<Uint8>) -> Self {
            Self {
                issuer_id,
                last_known_ctl_sequence,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs102941DeltaCtlRequest(pub EtsiTs102941CtlRequest);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941FullCtlRequest {
        #[rasn(identifier = "issuerId")]
        pub issuer_id: HashedId8,
        #[rasn(identifier = "lastKnownCtlSequence")]
        pub last_known_ctl_sequence: Option<Uint8>,
        #[rasn(identifier = "segmentNumber")]
        pub segment_number: Option<Uint8>,
    }
    impl EtsiTs102941FullCtlRequest {
        pub fn new(
            issuer_id: HashedId8,
            last_known_ctl_sequence: Option<Uint8>,
            segment_number: Option<Uint8>,
        ) -> Self {
            Self {
                issuer_id,
                last_known_ctl_sequence,
                segment_number,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097HeaderInfoExtensionId(pub ExtId);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("2"))]
    pub struct ExtensionModuleVersion(pub u8);
    pub const ETSI_TS102941_CRL_REQUEST_ID: EtsiTs103097HeaderInfoExtensionId =
        EtsiTs103097HeaderInfoExtensionId(ExtId(1));
    #[doc = "'01'H"]
    pub const ETSI_TS102941_DELTA_CTL_REQUEST_ID: EtsiTs103097HeaderInfoExtensionId =
        EtsiTs103097HeaderInfoExtensionId(ExtId(2));
    #[doc = "'02'H"]
    pub const ETSI_TS102941_FULL_CTL_REQUEST_ID: EtsiTs103097HeaderInfoExtensionId =
        EtsiTs103097HeaderInfoExtensionId(ExtId(3));
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts103097_module {
    extern crate alloc;
    use super::etsi_ts103097_extension_module::ExtensionModuleVersion;
    use super::ieee1609_dot2::{Certificate, Ieee1609Dot2Data};
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097Certificate(pub Certificate);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097Data(pub Ieee1609Dot2Data);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-SignedExternalPayload")]
    pub struct EtsiTs103097DataSignedExternalPayload(pub EtsiTs103097Data);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2 {
    extern crate alloc;
    use super::etsi_ts103097_extension_module::EtsiOriginatingHeaderInfoExtension;
    use super::ieee1609_dot2_base_types::*;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = "*"]
    #[doc = " * @brief This type is defined only for backwards compatibility."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Aes128CcmCiphertext(pub One28BitCcmCiphertext);
    #[doc = "*"]
    #[doc = " * @brief This structure contains an individual AppExtension. AppExtensions "]
    #[doc = " * specified in this standard are drawn from the ASN.1 Information Object Set "]
    #[doc = " * SetCertExtensions. This set, and its use in the AppExtension type, is "]
    #[doc = " * structured so that each AppExtension is associated with a "]
    #[doc = " * CertIssueExtension and a CertRequestExtension and all are identified by "]
    #[doc = " * the same id value. In this structure:"]
    #[doc = " * "]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " * "]
    #[doc = " * @param content: provides the content of the extension."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct AppExtension {
        pub id: ExtId,
        pub content: Any,
    }
    impl AppExtension {
        pub fn new(id: ExtId, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CertIssueExtensionPermissions {
        specific(Any),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This field contains an individual CertIssueExtension. "]
    #[doc = " * CertIssueExtensions specified in this standard are drawn from the ASN.1 "]
    #[doc = " * Information Object Set SetCertExtensions. This set, and its use in the "]
    #[doc = " * CertIssueExtension type, is structured so that each CertIssueExtension "]
    #[doc = " * is associated with a AppExtension and a CertRequestExtension and all are "]
    #[doc = " * identified by the same id value. In this structure:"]
    #[doc = " * "]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " * "]
    #[doc = " * @param permissions: indicates the permissions. Within this field."]
    #[doc = " *   - all indicates that the certificate is entitled to issue all values of"]
    #[doc = " * the extension."]
    #[doc = " *   - specific is used to specify which values of the extension may be "]
    #[doc = " * issued in the case where all does not apply."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CertIssueExtension {
        pub id: ExtId,
        pub permissions: CertIssueExtensionPermissions,
    }
    impl CertIssueExtension {
        pub fn new(id: ExtId, permissions: CertIssueExtensionPermissions) -> Self {
            Self { id, permissions }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CertRequestExtensionPermissions {
        content(Any),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This field contains an individual CertRequestExtension. "]
    #[doc = " * CertRequestExtensions specified in this standard are drawn from the "]
    #[doc = " * ASN.1 Information Object Set SetCertExtensions. This set, and its use in "]
    #[doc = " * the CertRequestExtension type, is structured so that each "]
    #[doc = " * CertRequestExtension is associated with a AppExtension and a "]
    #[doc = " * CertRequestExtension and all are identified by the same id value. In this "]
    #[doc = " * structure:"]
    #[doc = " * "]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " * "]
    #[doc = " * @param permissions: indicates the permissions. Within this field."]
    #[doc = " *   - all indicates that the certificate is entitled to issue all values of"]
    #[doc = " * the extension."]
    #[doc = " *   - specific is used to specify which values of the extension may be "]
    #[doc = " * issued in the case where all does not apply."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CertRequestExtension {
        pub id: ExtId,
        pub permissions: CertRequestExtensionPermissions,
    }
    impl CertRequestExtension {
        pub fn new(id: ExtId, permissions: CertRequestExtensionPermissions) -> Self {
            Self { id, permissions }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                Certificates and other Security Management                 "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is a profile of the structure CertificateBase, which"]
    #[doc = " * specifies the valid combinations of fields to transmit implicit and"]
    #[doc = " * explicit certificates."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the CertificateBase."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Certificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief The fields in this structure have the following meaning:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the version of the certificate format. In this"]
    #[doc = " * version of the data structures, this field is set to 3."]
    #[doc = " *"]
    #[doc = " * @param type: states whether the certificate is implicit or explicit. This"]
    #[doc = " * field is set to explicit for explicit certificates and to implicit for"]
    #[doc = " * implicit certificates. See ExplicitCertificate and ImplicitCertificate for"]
    #[doc = " * more details."]
    #[doc = " *"]
    #[doc = " * @param issuer: identifies the issuer of the certificate."]
    #[doc = " *"]
    #[doc = " * @param toBeSigned: is the certificate contents. This field is an input to"]
    #[doc = " * the hash when generating or verifying signatures for an explicit"]
    #[doc = " * certificate, or generating or verifying the public key from the"]
    #[doc = " * reconstruction value for an implicit certificate. The details of how this"]
    #[doc = " * field are encoded are given in the description of the"]
    #[doc = " * ToBeSignedCertificate type."]
    #[doc = " *"]
    #[doc = " * @param signature: is included in an ExplicitCertificate. It is the"]
    #[doc = " * signature, calculated by the signer identified in the issuer field, over"]
    #[doc = " * the hash of toBeSigned. The hash is calculated as specified in 5.3.1, where:"]
    #[doc = " *   - Data input is the encoding of toBeSigned, canonicalized as described"]
    #[doc = " * next."]
    #[doc = " *   - Signer identifier input depends on the verification type, which in"]
    #[doc = " * turn depends on the choice indicated by issuer. If the choice indicated by"]
    #[doc = " * issuer is self, the verification type is self-signed and the signer"]
    #[doc = " * identifier input is the empty string. If the choice indicated by issuer is"]
    #[doc = " * not self, the verification type is certificate and the signer identifier"]
    #[doc = " * input is the canonicalized COER encoding of the certificate indicated by"]
    #[doc = " * issuer. The canonicalization is carried out as specified in the "]
    #[doc = " * Canonicalization section of this subclause."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the ToBeSignedCertificate and to the Signature."]
    #[doc = " *"]
    #[doc = " * @note Whole-certificate hash: If the entirety of a certificate is hashed "]
    #[doc = " * to calculate a HashedId3, HashedId8, or HashedId10, the algorithm used for "]
    #[doc = " * this purpose is known as the whole-certificate hash. The method used to "]
    #[doc = " * determine the whole-certificate hash algorithm is specified in 5.3.9.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CertificateBase {
        #[rasn(value("3"))]
        pub version: Uint8,
        #[rasn(identifier = "type")]
        pub r_type: CertificateType,
        pub issuer: IssuerIdentifier,
        #[rasn(identifier = "toBeSigned")]
        pub to_be_signed: ToBeSignedCertificate,
        pub signature: Option<Signature>,
    }
    impl CertificateBase {
        pub fn new(
            version: Uint8,
            r_type: CertificateType,
            issuer: IssuerIdentifier,
            to_be_signed: ToBeSignedCertificate,
            signature: Option<Signature>,
        ) -> Self {
            Self {
                version,
                r_type,
                issuer,
                to_be_signed,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains information that is used to identify the"]
    #[doc = " * certificate holder if necessary."]
    #[doc = " *"]
    #[doc = " * @param linkageData: is used to identify the certificate for revocation"]
    #[doc = " * purposes in the case of certificates that appear on linked certificate"]
    #[doc = " * CRLs. See 5.1.3 and 7.3 for further discussion."]
    #[doc = " *"]
    #[doc = " * @param name: is used to identify the certificate holder in the case of"]
    #[doc = " * non-anonymous certificates. The contents of this field are a matter of"]
    #[doc = " * policy and are expected to be human-readable."]
    #[doc = " *"]
    #[doc = " * @param binaryId: supports identifiers that are not human-readable."]
    #[doc = " *"]
    #[doc = " * @param none: indicates that the certificate does not include an identifier."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the choice indicated in this"]
    #[doc = " * field shall reject a signed SPDU as invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CertificateId {
        linkageData(LinkageData),
        name(Hostname),
        #[rasn(size("1..=64"))]
        binaryId(OctetString),
        none(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This enumerated type indicates whether a certificate is explicit or"]
    #[doc = " * implicit."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, "]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be "]
    #[doc = " * established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum CertificateType {
        explicit = 0,
        implicit = 1,
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(
        delegate,
        identifier = "IOFR$IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION$&Extn"
    )]
    pub struct AnonymousContributedExtensionBlockExtns(pub Any);
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct ContributedExtensionBlockExtns(
        pub SequenceOf<AnonymousContributedExtensionBlockExtns>,
    );
    #[doc = "*"]
    #[doc = " * @brief This data structure defines the format of an extension block"]
    #[doc = " * provided by an identified contributor by using the temnplate provided"]
    #[doc = " * in the class IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION constraint"]
    #[doc = " * to the objects in the set Ieee1609Dot2HeaderInfoContributedExtensions."]
    #[doc = " *"]
    #[doc = " * @param contributorId: uniquely identifies the contributor."]
    #[doc = " *"]
    #[doc = " * @param extns: contains a list of extensions from that contributor. "]
    #[doc = " * Extensions are expected and not required to follow the format specified "]
    #[doc = " * in 6.5."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ContributedExtensionBlock {
        #[rasn(identifier = "contributorId")]
        pub contributor_id: HeaderInfoContributorId,
        pub extns: ContributedExtensionBlockExtns,
    }
    impl ContributedExtensionBlock {
        pub fn new(
            contributor_id: HeaderInfoContributorId,
            extns: ContributedExtensionBlockExtns,
        ) -> Self {
            Self {
                contributor_id,
                extns,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct ContributedExtensionBlocks(pub SequenceOf<ContributedExtensionBlock>);
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to perform a countersignature over an"]
    #[doc = " * already-signed SPDU. This is the profile of an Ieee1609Dot2Data containing"]
    #[doc = " * a signedData. The tbsData within content is composed of a payload"]
    #[doc = " * containing the hash (extDataHash) of the externally generated, pre-signed"]
    #[doc = " * SPDU over which the countersignature is performed."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Countersignature(pub Ieee1609Dot2Data);
    #[doc = "***************************************************************************"]
    #[doc = "                              Encrypted Data                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This data structure encodes data that has been encrypted to one or "]
    #[doc = " * more recipients using the recipients� public or symmetric keys as "]
    #[doc = " * specified in 5.3.4."]
    #[doc = " *"]
    #[doc = " * @param recipients: contains one or more RecipientInfos. These entries may"]
    #[doc = " * be more than one RecipientInfo, and more than one type of RecipientInfo,"]
    #[doc = " * as long as all entries are indicating or containing the same data encryption"]
    #[doc = " * key."]
    #[doc = " *"]
    #[doc = " * @param ciphertext: contains the encrypted data. This is the encryption of"]
    #[doc = " * an encoded Ieee1609Dot2Data structure as specified in 5.3.4.2."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, recipients is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of RecipientInfo"]
    #[doc = " * in recipients when decrypted shall indicate that the encrypted SPDU could"]
    #[doc = " * not be decrypted due to unsupported critical information fields. A"]
    #[doc = " * compliant implementation shall support recipients fields containing at"]
    #[doc = " * least eight entries."]
    #[doc = " *"]
    #[doc = " * @note If the plaintext is raw data, i.e., it has not been output from a "]
    #[doc = " * previous operation of the SDS, then it is trivial to encapsulate it in an"]
    #[doc = " * Ieee1609Dot2Data of type unsecuredData as noted in 4.2.2.2.2. For example,"]
    #[doc = " * '03 80 08 01 23 45 67 89 AB CD EF' is the C-OER encoding of '01 23 45 67 "]
    #[doc = " * 89 AB CD EF' encapsulated in an Ieee1609Dot2Data of type unsecuredData. "]
    #[doc = " * The first byte of the encoding 03 is the protocolVersion, the second byte "]
    #[doc = " * 80 indicates the choice unsecuredData, and the third byte 08 is the length "]
    #[doc = " * of the raw data '01 23 45 67 89 AB CD EF'."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EncryptedData {
        pub recipients: SequenceOfRecipientInfo,
        pub ciphertext: SymmetricCiphertext,
    }
    impl EncryptedData {
        pub fn new(recipients: SequenceOfRecipientInfo, ciphertext: SymmetricCiphertext) -> Self {
            Self {
                recipients,
                ciphertext,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure contains an encrypted data encryption key, "]
    #[doc = " * where the data encryption key is input to the data encryption key "]
    #[doc = " * encryption process with no headers, encapsulation, or length indication."]
    #[doc = " *"]
    #[doc = " * Critical information fields: If present and applicable to"]
    #[doc = " * the receiving SDEE, this is a critical information field as defined in"]
    #[doc = " * 5.2.6. If an implementation receives an encrypted SPDU and determines that"]
    #[doc = " * one or more RecipientInfo fields are relevant to it, and if all of those"]
    #[doc = " * RecipientInfos contain an EncryptedDataEncryptionKey such that the"]
    #[doc = " * implementation does not recognize the indicated CHOICE, the implementation"]
    #[doc = " * shall indicate that the encrypted SPDU is not decryptable."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EncryptedDataEncryptionKey {
        eciesNistP256(EciesP256EncryptedKey),
        eciesBrainpoolP256r1(EciesP256EncryptedKey),
        #[rasn(extension_addition)]
        ecencSm2256(EcencP256EncryptedKey),
    }
    #[doc = "*"]
    #[doc = " * @brief This type indicates which type of permissions may appear in"]
    #[doc = " * end-entity certificates the chain of whose permissions passes through the"]
    #[doc = " * PsidGroupPermissions field containing this value. If app is indicated, the"]
    #[doc = " * end-entity certificate may contain an appPermissions field. If enroll is"]
    #[doc = " * indicated, the end-entity certificate may contain a certRequestPermissions"]
    #[doc = " * field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EndEntityType(pub FixedBitString<8usize>);
    #[doc = "*"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an explicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ExplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief This structure contains the hash of some data with a specified hash"]
    #[doc = " * algorithm. See 5.3.3 for specification of the permitted hash algorithms."]
    #[doc = " *"]
    #[doc = " * @param sha256HashedData: indicates data hashed with SHA-256."]
    #[doc = " *"]
    #[doc = " * @param sha384HashedData: indicates data hashed with SHA-384."]
    #[doc = " * "]
    #[doc = " * @param sm3HashedData: indicates data hashed with SM3."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical "]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not "]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU "]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, "]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum HashedData {
        sha256HashedData(HashedId32),
        #[rasn(extension_addition)]
        sha384HashedData(HashedId48),
        #[rasn(extension_addition)]
        sm3HashedData(HashedId32),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the following information that is used to establish"]
    #[doc = " * validity by the criteria of 5.2."]
    #[doc = " *"]
    #[doc = " * @param psid: indicates the application area with which the sender is"]
    #[doc = " * claiming the payload is to be associated."]
    #[doc = " *"]
    #[doc = " * @param generationTime: indicates the time at which the structure was"]
    #[doc = " * generated. See 5.2.5.2.2 and 5.2.5.2.3 for discussion of the use of this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param expiryTime: if present, contains the time after which the data"]
    #[doc = " * is no longer considered relevant. If both generationTime and"]
    #[doc = " * expiryTime are present, the signed SPDU is invalid if generationTime is"]
    #[doc = " * not strictly earlier than expiryTime."]
    #[doc = " *"]
    #[doc = " * @param generationLocation: if present, contains the location at which the"]
    #[doc = " * signature was generated."]
    #[doc = " *"]
    #[doc = " * @param p2pcdLearningRequest: if present, is used by the SDS to request "]
    #[doc = " * certificates for which it has seen identifiers and does not know the "]
    #[doc = " * entire certificate. A specification of this peer-to-peer certificate "]
    #[doc = " * distribution (P2PCD) mechanism is given in Clause 8. This field is used "]
    #[doc = " * for the separate-certificate-pdu flavor of P2PCD and shall only be present "]
    #[doc = " * if inlineP2pcdRequest is not present. The HashedId3 is calculated with the "]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3, "]
    #[doc = " * applied to the COER-encoded certificate, canonicalized as defined in the "]
    #[doc = " * definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param missingCrlIdentifier: if present, is used by the SDS to request"]
    #[doc = " * CRLs which it knows to have been issued and have not received. This is"]
    #[doc = " * provided for future use and the associated mechanism is not defined in"]
    #[doc = " * this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: if present, is used to provide a key that is to "]
    #[doc = " * be used to encrypt at least one response to this SPDU. The SDEE "]
    #[doc = " * specification is expected to specify which response SPDUs are to be "]
    #[doc = " * encrypted with this key. One possible use of this key to encrypt a "]
    #[doc = " * response is specified in 6.3.35, 6.3.37, and 6.3.34. An encryptionKey "]
    #[doc = " * field of type symmetric should only be used if the SignedData containing "]
    #[doc = " * this field is securely encrypted by some means."]
    #[doc = " *"]
    #[doc = " * @param inlineP2pcdRequest: if present, is used by the SDS to request"]
    #[doc = " * unknown certificates per the inline peer-to-peer certificate distribution"]
    #[doc = " * mechanism is given in Clause 8. This field shall only be present if"]
    #[doc = " * p2pcdLearningRequest is not present. The HashedId3 is calculated with the"]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3, applied"]
    #[doc = " * to the COER-encoded certificate, canonicalized as defined in the definition"]
    #[doc = " * of Certificate."]
    #[doc = " *"]
    #[doc = " * @param requestedCertificate: if present, is used by the SDS to provide"]
    #[doc = " * certificates per the \"inline\" version of the peer-to-peer certificate"]
    #[doc = " * distribution mechanism given in Clause 8."]
    #[doc = " *"]
    #[doc = " * @param pduFunctionalType: if present, is used to indicate that the SPDU is"]
    #[doc = " * to be consumed by a process other than an application process as defined"]
    #[doc = " * in ISO 21177 [B14a]. See 6.3.23b for more details."]
    #[doc = " *"]
    #[doc = " * @param contributedExtensions: if present, is used to contain additional "]
    #[doc = " * extensions defined using the ContributedExtensionBlocks structure."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the EncryptionKey. If encryptionKey is present, and indicates"]
    #[doc = " * the choice public, and contains a BasePublicEncryptionKey that is an"]
    #[doc = " * elliptic curve point (i.e., of type EccP256CurvePoint or "]
    #[doc = " * EccP384CurvePoint), then the elliptic curve point is encoded in compressed"]
    #[doc = " * form, i.e., such that the choice indicated within the Ecc*CurvePoint is"]
    #[doc = " * compressed-y-0 or compressed-y-1."]
    #[doc = " * The canonicalization does not apply to any fields after the extension "]
    #[doc = " * marker, including any fields in contributedExtensions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct HeaderInfo {
        pub psid: Psid,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Option<Time64>,
        #[rasn(identifier = "expiryTime")]
        pub expiry_time: Option<Time64>,
        #[rasn(identifier = "generationLocation")]
        pub generation_location: Option<ThreeDLocation>,
        #[rasn(identifier = "p2pcdLearningRequest")]
        pub p2pcd_learning_request: Option<HashedId3>,
        #[rasn(identifier = "missingCrlIdentifier")]
        pub missing_crl_identifier: Option<MissingCrlIdentifier>,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<EncryptionKey>,
        #[rasn(extension_addition, identifier = "inlineP2pcdRequest")]
        pub inline_p2pcd_request: Option<SequenceOfHashedId3>,
        #[rasn(extension_addition, identifier = "requestedCertificate")]
        pub requested_certificate: Option<Certificate>,
        #[rasn(extension_addition, identifier = "pduFunctionalType")]
        pub pdu_functional_type: Option<PduFunctionalType>,
        #[rasn(extension_addition, identifier = "contributedExtensions")]
        pub contributed_extensions: Option<ContributedExtensionBlocks>,
    }
    impl HeaderInfo {
        pub fn new(
            psid: Psid,
            generation_time: Option<Time64>,
            expiry_time: Option<Time64>,
            generation_location: Option<ThreeDLocation>,
            p2pcd_learning_request: Option<HashedId3>,
            missing_crl_identifier: Option<MissingCrlIdentifier>,
            encryption_key: Option<EncryptionKey>,
            inline_p2pcd_request: Option<SequenceOfHashedId3>,
            requested_certificate: Option<Certificate>,
            pdu_functional_type: Option<PduFunctionalType>,
            contributed_extensions: Option<ContributedExtensionBlocks>,
        ) -> Self {
            Self {
                psid,
                generation_time,
                expiry_time,
                generation_location,
                p2pcd_learning_request,
                missing_crl_identifier,
                encryption_key,
                inline_p2pcd_request,
                requested_certificate,
                pdu_functional_type,
                contributed_extensions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is an integer used to identify a HeaderInfo extension"]
    #[doc = " * contributing organization. In this version of this standard two values are"]
    #[doc = " * defined: "]
    #[doc = " *   - ieee1609OriginatingExtensionId indicating extensions originating with "]
    #[doc = " * IEEE Std 1609."]
    #[doc = " *   - etsiOriginatingExtensionId indicating extensions originating with "]
    #[doc = " * ETSI TC ITS."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct HeaderInfoContributorId(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This structure uses the parameterized type Extension to define an "]
    #[doc = " * Ieee1609ContributedHeaderInfoExtension as an open Extension Content field "]
    #[doc = " * identified by an extension identifier. The extension identifier value is "]
    #[doc = " * unique to extensions defined by ETSI and need not be unique among all "]
    #[doc = " * extension identifier values defined by all contributing organizations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct Ieee1609ContributedHeaderInfoExtension {
        pub id: ExtId,
        pub content: Any,
    }
    impl Ieee1609ContributedHeaderInfoExtension {
        pub fn new(id: ExtId, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param unsecuredData: indicates that the content is an OCTET STRING to be"]
    #[doc = " * consumed outside the SDS."]
    #[doc = " *"]
    #[doc = " * @param signedData: indicates that the content has been signed according to"]
    #[doc = " * this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptedData: indicates that the content has been encrypted"]
    #[doc = " * according to this standard."]
    #[doc = " *"]
    #[doc = " * @param signedCertificateRequest: indicates that the content is a "]
    #[doc = " * certificate request signed by an IEEE 1609.2 certificate or self-signed."]
    #[doc = " *"]
    #[doc = " * @param signedX509CertificateRequest: indicates that the content is a "]
    #[doc = " * certificate request signed by an ITU-T X.509 certificate."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2 if it is of type signedData."]
    #[doc = " * The canonicalization applies to the SignedData."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum Ieee1609Dot2Content {
        unsecuredData(Opaque),
        signedData(SignedData),
        encryptedData(EncryptedData),
        signedCertificateRequest(Opaque),
        #[rasn(extension_addition)]
        signedX509CertificateRequest(Opaque),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                               Secured Data                                "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This data type is used to contain the other data types in this"]
    #[doc = " * clause. The fields in the Ieee1609Dot2Data have the following meanings:"]
    #[doc = " *"]
    #[doc = " * @param protocolVersion: contains the current version of the protocol. The"]
    #[doc = " * version specified in this standard is version 3, represented by the"]
    #[doc = " * integer 3. There are no major or minor version numbers."]
    #[doc = " *"]
    #[doc = " * @param content: contains the content in the form of an Ieee1609Dot2Content."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the Ieee1609Dot2Content."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct Ieee1609Dot2Data {
        #[rasn(value("3"), identifier = "protocolVersion")]
        pub protocol_version: Uint8,
        pub content: Ieee1609Dot2Content,
    }
    impl Ieee1609Dot2Data {
        pub fn new(protocol_version: Uint8, content: Ieee1609Dot2Content) -> Self {
            Self {
                protocol_version,
                content,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is an integer used to identify an "]
    #[doc = " * Ieee1609ContributedHeaderInfoExtension."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Ieee1609HeaderInfoExtensionId(pub ExtId);
    #[doc = "*"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an implicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ImplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief This structure allows the recipient of a certificate to determine"]
    #[doc = " * which keying material to use to authenticate the certificate."]
    #[doc = " *"]
    #[doc = " * If the choice indicated is sha256AndDigest, sha384AndDigest, or "]
    #[doc = " * sm3AndDigest:"]
    #[doc = " *   - The structure contains the HashedId8 of the issuing certificate. The "]
    #[doc = " * HashedId8 is calculated with the whole-certificate hash algorithm, "]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate, "]
    #[doc = " * canonicalized as defined in the definition of Certificate. "]
    #[doc = " *   - The hash algorithm to be used to generate the hash of the certificate "]
    #[doc = " * for verification is SHA-256 (in the case of sha256AndDigest), SM3 (in the "]
    #[doc = " * case of sm3AndDigest) or SHA-384 (in the case of sha384AndDigest)."]
    #[doc = " *   - The certificate is to be verified with the public key of the"]
    #[doc = " * indicated issuing certificate."]
    #[doc = " *"]
    #[doc = " * If the choice indicated is self:"]
    #[doc = " *   - The structure indicates what hash algorithm is to be used to generate"]
    #[doc = " * the hash of the certificate for verification."]
    #[doc = " *   - The certificate is to be verified with the public key indicated by"]
    #[doc = " * the verifyKeyIndicator field in theToBeSignedCertificate."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, "]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be "]
    #[doc = " * established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IssuerIdentifier {
        sha256AndDigest(HashedId8),
        #[rasn(identifier = "self")]
        R_self(HashAlgorithm),
        #[rasn(extension_addition)]
        sha384AndDigest(HashedId8),
        #[rasn(extension_addition)]
        sm3AndDigest(HashedId8),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains information that is matched against"]
    #[doc = " * information obtained from a linkage ID-based CRL to determine whether the"]
    #[doc = " * containing certificate has been revoked. See 5.1.3.4 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct LinkageData {
        #[rasn(identifier = "iCert")]
        pub i_cert: IValue,
        #[rasn(identifier = "linkage-value")]
        pub linkage_value: LinkageValue,
        #[rasn(identifier = "group-linkage-value")]
        pub group_linkage_value: Option<GroupLinkageValue>,
    }
    impl LinkageData {
        pub fn new(
            i_cert: IValue,
            linkage_value: LinkageValue,
            group_linkage_value: Option<GroupLinkageValue>,
        ) -> Self {
            Self {
                i_cert,
                linkage_value,
                group_linkage_value,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure may be used to request a CRL that the SSME knows to"]
    #[doc = " * have been issued and has not yet received. It is provided for future use"]
    #[doc = " * and its use is not defined in this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param cracaId: is the HashedId3 of the CRACA, as defined in 5.1.3. The "]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm, "]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: is the requested CRL Series value. See 5.1.3 for more"]
    #[doc = " * information."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct MissingCrlIdentifier {
        #[rasn(identifier = "cracaId")]
        pub craca_id: HashedId3,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
    }
    impl MissingCrlIdentifier {
        pub fn new(craca_id: HashedId3, crl_series: CrlSeries) -> Self {
            Self {
                craca_id,
                crl_series,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure encapsulates an encrypted ciphertext for any "]
    #[doc = " * symmetric algorithm with 128-bit blocks in CCM mode. The ciphertext is "]
    #[doc = " * 16 bytes longer than the corresponding plaintext due to the inclusion of "]
    #[doc = " * the message authentication code (MAC). The plaintext resulting from a "]
    #[doc = " * correct decryption of the ciphertext is either a COER-encoded "]
    #[doc = " * Ieee1609Dot2Data structure (see 6.3.41), or a 16-byte symmetric key "]
    #[doc = " * (see 6.3.44)."]
    #[doc = " *"]
    #[doc = " * The ciphertext is 16 bytes longer than the corresponding plaintext."]
    #[doc = " *"]
    #[doc = " * The plaintext resulting from a correct decryption of the"]
    #[doc = " * ciphertext is a COER-encoded Ieee1609Dot2Data structure."]
    #[doc = " *"]
    #[doc = " * @param nonce: contains the nonce N as specified in 5.3.8."]
    #[doc = " *"]
    #[doc = " * @param ccmCiphertext: contains the ciphertext C as specified in 5.3.8."]
    #[doc = " *"]
    #[doc = " * @note In the name of this structure, \"One28\" indicates that the "]
    #[doc = " * symmetric cipher block size is 128 bits. It happens to also be the case "]
    #[doc = " * that the keys used for both AES-128-CCM and SM4-CCM are also 128 bits long. "]
    #[doc = " * This is, however, not what �One28� refers to. Since the cipher is used in "]
    #[doc = " * counter mode, i.e., as a stream cipher, the fact that that block size is 128"]
    #[doc = " * bits affects only the size of the MAC and does not affect the size of the"]
    #[doc = " * raw ciphertext."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct One28BitCcmCiphertext {
        #[rasn(size("12"))]
        pub nonce: OctetString,
        #[rasn(identifier = "ccmCiphertext")]
        pub ccm_ciphertext: Opaque,
    }
    impl One28BitCcmCiphertext {
        pub fn new(nonce: OctetString, ccm_ciphertext: Opaque) -> Self {
            Self {
                nonce,
                ccm_ciphertext,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is the AppExtension used to identify an operating "]
    #[doc = " * organization. See 5.2.6.6.7.2 for discussion of how the"]
    #[doc = " * OperatingOrganizationId can be integrated into the SPDU payload by an"]
    #[doc = " * SDEE specifier."]
    #[doc = " *"]
    #[doc = " * A certificate may have an OperatingOrganizationId associated with it even if"]
    #[doc = " * the certificate does not contain an OperatingOrganizationId field. If the"]
    #[doc = " * certificate does not contain an OperatingOrganizationId field, the"]
    #[doc = " * associated OperatingOrganizationId is determined as follows:"]
    #[doc = " *"]
    #[doc = " *   - If the certificate is self-signed, that is, the choice indicated by the"]
    #[doc = " * issuer field in the enclosing certificate structure is self, the"]
    #[doc = " * certificate has no OperatingOrganizationId associated with it."]
    #[doc = " *"]
    #[doc = " *   -  Otherwise, the certificate has the same OperatingOrganizationId as"]
    #[doc = " * the certificate that issued it."]
    #[doc = " *"]
    #[doc = " * The above algorithm is applied recursively, i.e. if"]
    #[doc = " * OperatingOrganizationId is omitted from the issuing certificate, then"]
    #[doc = " * the issuing certificate of that certificate is inspected to determine if"]
    #[doc = " * OperatingOrganizationId is present, and so on."]
    #[doc = " *"]
    #[doc = " * Consistency with SPDU payload. As discussed in 5.2.6.6.7.2, the SPDU payload"]
    #[doc = " * design might or might not include OperatingOrganizationId material. "]
    #[doc = " *"]
    #[doc = " * If OperatingOrganizationId material appears in the SPDU payload, then the"]
    #[doc = " * SDEE specification is expected to state that consistency is required between"]
    #[doc = " * the payload and the certificate (although, as discussed in 5.2.6.6.7.2, this"]
    #[doc = " * approach is not recommended)."]
    #[doc = " *"]
    #[doc = " * If consistency is required between the OperatingOrganizationID"]
    #[doc = " * and operating organization information represented by an OBJECT"]
    #[doc = " * IDENTIFIER in the SPDU payload, then the SDEE specification for that SPDU is"]
    #[doc = " * required to specify how the SPDU can be used to determine an OBJECT"]
    #[doc = " * IDENTIFIER of the same length as the OperatingOrganizationId in the"]
    #[doc = " * certificate (e.g., by including the full OBJECT IDENTIFIER in the SPDU, or"]
    #[doc = " * by including a RELATIVE-OID with clear instructions about how a full OBJECT"]
    #[doc = " * IDENTIFIER can be obtained from the RELATIVE-OID, or by truncating an"]
    #[doc = " * OBJECT IDENTIFIER from the message to be the same length as the OBJECT"]
    #[doc = " * IDENTIFIER in the certificate). The SPDU is then consistent with this type"]
    #[doc = " * if the OBJECT IDENTIFIER determined from the SPDU is identical to the OBJECT"]
    #[doc = " * IDENTIFIER contained in this field."]
    #[doc = " *"]
    #[doc = " * Consistency with issuing certificate. This AppExtension does not have"]
    #[doc = " * consistency conditions with a corresponding CertIssueExtension. It can"]
    #[doc = " * appear in a certificate issued by any CA."]
    #[doc = " *"]
    #[doc = " * Consistency with certificate request signing certificate. This AppExtension"]
    #[doc = " * does not have consistency conditions with a corresponding"]
    #[doc = " * CertRequestExtension. It can appear in a certificate request signed by any"]
    #[doc = " * certificate containing certRequestPermissions, i.e. by any enrollment"]
    #[doc = " * certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct OperatingOrganizationId(pub ObjectIdentifier);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId: contains the hash of the container for the encryption"]
    #[doc = " * public key as specified in the definition of RecipientInfo. Specifically,"]
    #[doc = " * depending on the choice indicated by the containing RecipientInfo structure:"]
    #[doc = " *   - If the containing RecipientInfo structure indicates certRecipInfo,"]
    #[doc = " * this field contains the HashedId8 of the certificate. The HashedId8 is"]
    #[doc = " * calculated with the whole-certificate hash algorithm, determined as"]
    #[doc = " * described in 6.4.3, applied to the COER-encoded certificate, canonicalized"]
    #[doc = " * as defined in the definition of Certificate."]
    #[doc = " *   - If the containing RecipientInfo structure indicates "]
    #[doc = " * signedDataRecipInfo, this field contains the HashedId8 of the "]
    #[doc = " * Ieee1609Dot2Data of type signedData that contained the encryption key, "]
    #[doc = " * with that Ieee��1609�Dot2��Data canonicalized per 6.3.4. The HashedId8 is "]
    #[doc = " * calculated with the hash algorithm determined as specified in 5.3.9.5."]
    #[doc = " *   - If the containing RecipientInfo structure indicates rekRecipInfo, this "]
    #[doc = " * field contains the HashedId8 of the COER encoding of a PublicEncryptionKey "]
    #[doc = " * structure containing the response encryption key. The HashedId8 is "]
    #[doc = " * calculated with the hash algorithm determined as specified in 5.3.9.5."]
    #[doc = " *"]
    #[doc = " * @param encKey: contains the encrypted data encryption key, where the data "]
    #[doc = " * encryption key is input to the data encryption key encryption process with "]
    #[doc = " * no headers, encapsulation, or length indication. "]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PKRecipientInfo {
        #[rasn(identifier = "recipientId")]
        pub recipient_id: HashedId8,
        #[rasn(identifier = "encKey")]
        pub enc_key: EncryptedDataEncryptionKey,
    }
    impl PKRecipientInfo {
        pub fn new(recipient_id: HashedId8, enc_key: EncryptedDataEncryptionKey) -> Self {
            Self {
                recipient_id,
                enc_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure identifies the functional entity that is "]
    #[doc = " * intended to consume an SPDU, for the case where that functional entity is "]
    #[doc = " * not an application process, and are instead security support services for an"]
    #[doc = " * application process. Further details and the intended use of this field are "]
    #[doc = " * defined in ISO 21177 [B20]."]
    #[doc = " *"]
    #[doc = " * @param tlsHandshake: indicates that the Signed SPDU is not to be directly "]
    #[doc = " * consumed as an application PDU and is to be used to provide information "]
    #[doc = " * about the holder�s permissions to a Transport Layer Security (TLS) "]
    #[doc = " * (IETF 5246 [B15], IETF 8446 [B16]) handshake process operating to secure "]
    #[doc = " * communications to an application process. See IETF [B15] and ISO 21177 "]
    #[doc = " * [B20] for further information."]
    #[doc = " *"]
    #[doc = " * @param iso21177ExtendedAuth: indicates that the Signed SPDU is not to be "]
    #[doc = " * directly consumed as an application PDU and is to be used to provide "]
    #[doc = " * additional information about the holder�s permissions to the ISO 21177 "]
    #[doc = " * Security Subsystem for an application process. See ISO 21177 [B20] for "]
    #[doc = " * further information."]
    #[doc = " *"]
    #[doc = " * @param iso21177SessionExtension: indicates that the Signed SPDU is not to "]
    #[doc = " * be directly consumed as an application PDU and is to be used to extend an "]
    #[doc = " * existing ISO 21177 secure session. This enables a secure session to "]
    #[doc = " * persist beyond the lifetime of the certificates used to establish that "]
    #[doc = " * session."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct PduFunctionalType(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to indicate a symmetric key that may "]
    #[doc = " * be used directly to decrypt a SymmetricCiphertext. It consists of the "]
    #[doc = " * low-order 8 bytes of the hash of the COER encoding of a "]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question. "]
    #[doc = " * The HashedId8 is calculated with the hash algorithm determined as "]
    #[doc = " * specified in 5.3.9.3. The symmetric key may be established by any "]
    #[doc = " * appropriate means agreed by the two parties to the exchange."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct PreSharedKeyRecipientInfo(pub HashedId8);
    #[doc = "*"]
    #[doc = " * @brief This structure states the permissions that a certificate holder has"]
    #[doc = " * with respect to issuing and requesting certificates for a particular set"]
    #[doc = " * of PSIDs. For examples, see D.5.3 and D.5.4."]
    #[doc = " *"]
    #[doc = " * @param subjectPermissions: indicates PSIDs and SSP Ranges covered by this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param minChainLength: and chainLengthRange indicate how long the"]
    #[doc = " * certificate chain from this certificate to the end-entity certificate is"]
    #[doc = " * permitted to be. As specified in 5.1.2.1, the length of the certificate"]
    #[doc = " * chain is the number of certificates \"below\" this certificate in the chain,"]
    #[doc = " * down to and including the end-entity certificate. The length is permitted"]
    #[doc = " * to be (a) greater than or equal to minChainLength certificates and (b)"]
    #[doc = " * less than or equal to minChainLength + chainLengthRange certificates. A"]
    #[doc = " * value of 0 for minChainLength is not permitted when this type appears in"]
    #[doc = " * the certIssuePermissions field of a ToBeSignedCertificate; a certificate"]
    #[doc = " * that has a value of 0 for this field is invalid. The value -1 for"]
    #[doc = " * chainLengthRange is a special case: if the value of chainLengthRange is -1"]
    #[doc = " * it indicates that the certificate chain may be any length equal to or"]
    #[doc = " * greater than minChainLength. See the examples below for further discussion."]
    #[doc = " *"]
    #[doc = " * @param eeType: takes one or more of the values app and enroll and indicates"]
    #[doc = " * the type of certificates or requests that this instance of"]
    #[doc = " * PsidGroupPermissions in the certificate is entitled to authorize. "]
    #[doc = " * Different instances of PsidGroupPermissions within a ToBeSignedCertificate"]
    #[doc = " * may have different values for eeType."]
    #[doc = " *   - If this field indicates app, the chain is allowed to end in an "]
    #[doc = " * authorization certificate, i.e., a certificate in which these permissions "]
    #[doc = " * appear in an appPermissions field (in other words, if the field does not "]
    #[doc = " * indicate app and the chain ends in an authorization certificate, the "]
    #[doc = " * chain shall be considered invalid)."]
    #[doc = " *   - If this field indicates enroll, the chain is allowed to end in an "]
    #[doc = " * enrollment certificate, i.e., a certificate in which these permissions "]
    #[doc = " * appear in a certRequestPermissions permissions field (in other words, if the "]
    #[doc = " * field does not indicate enroll and the chain ends in an enrollment "]
    #[doc = " * certificate, the chain shall be considered invalid)."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidGroupPermissions {
        #[rasn(identifier = "subjectPermissions")]
        pub subject_permissions: SubjectPermissions,
        #[rasn(
            default = "psid_group_permissions_min_chain_length_default",
            identifier = "minChainLength"
        )]
        pub min_chain_length: Integer,
        #[rasn(
            default = "psid_group_permissions_chain_length_range_default",
            identifier = "chainLengthRange"
        )]
        pub chain_length_range: Integer,
        #[rasn(
            default = "psid_group_permissions_ee_type_default",
            identifier = "eeType"
        )]
        pub ee_type: EndEntityType,
    }
    impl PsidGroupPermissions {
        pub fn new(
            subject_permissions: SubjectPermissions,
            min_chain_length: Integer,
            chain_length_range: Integer,
            ee_type: EndEntityType,
        ) -> Self {
            Self {
                subject_permissions,
                min_chain_length,
                chain_length_range,
                ee_type,
            }
        }
    }
    fn psid_group_permissions_min_chain_length_default() -> Integer {
        Integer::from(1i128)
    }
    fn psid_group_permissions_chain_length_range_default() -> Integer {
        Integer::from(0i128)
    }
    fn psid_group_permissions_ee_type_default() -> EndEntityType {
        let mut bits = FixedBitString::<8usize>::default();
        bits.set(0, true);
        EndEntityType(bits)
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to transfer the data encryption key to"]
    #[doc = " * an individual recipient of an EncryptedData. The option pskRecipInfo is"]
    #[doc = " * selected if the EncryptedData was encrypted using the static encryption"]
    #[doc = " * key approach specified in 5.3.4. The other options are selected if the"]
    #[doc = " * EncryptedData was encrypted using the ephemeral encryption key approach"]
    #[doc = " * specified in 5.3.4. The meanings of the choices are as follows:"]
    #[doc = " *"]
    #[doc = " * @param pskRecipInfo: The data was encrypted directly using a pre-shared "]
    #[doc = " * symmetric key."]
    #[doc = " *"]
    #[doc = " * @param symmRecipInfo: The data was encrypted with a data encryption key,"]
    #[doc = " * and the data encryption key was encrypted using a symmetric key."]
    #[doc = " *"]
    #[doc = " * @param certRecipInfo: The data was encrypted with a data encryption key, "]
    #[doc = " * the data encryption key was encrypted using a public key encryption scheme,"]
    #[doc = " * where the public encryption key was obtained from a certificate. In this "]
    #[doc = " * case, the parameter P1 to ECIES as defined in 5.3.5 is the hash of the "]
    #[doc = " * certificate, calculated with the whole-certificate hash algorithm, "]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate, "]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the "]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash"]
    #[doc = " * of the certificate."]
    #[doc = " *"]
    #[doc = " * @param signedDataRecipInfo: The data was encrypted with a data encryption "]
    #[doc = " * key, the data encryption key was encrypted using a public key encryption "]
    #[doc = " * scheme, where the public encryption key was obtained as the public response "]
    #[doc = " * encryption key from a SignedData. In this case, if ECIES is the encryption "]
    #[doc = " * algorithm, then the parameter P1 to ECIES as defined in 5.3.5 is the "]
    #[doc = " * SHA-256 hash of the Ieee1609Dot2Data of type signedData containing the "]
    #[doc = " * response encryption key, canonicalized as defined in the definition of "]
    #[doc = " * Ieee1609Dot2Data."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the "]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash"]
    #[doc = " * of the Ieee1609Dot2Data."]
    #[doc = " *"]
    #[doc = " * @param rekRecipInfo: The data was encrypted with a data encryption key, "]
    #[doc = " * the data encryption key was encrypted using a public key encryption scheme,"]
    #[doc = " * where the public encryption key was not obtained from a Signed-Data or a "]
    #[doc = " * certificate. In this case, the SDEE specification is expected to specify "]
    #[doc = " * how the public key is obtained, and if ECIES is the encryption algorithm, "]
    #[doc = " * then the parameter P1 to ECIES as defined in 5.3.5 is the hash of the "]
    #[doc = " * empty string."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the "]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash "]
    #[doc = " * of the empty string."]
    #[doc = " *"]
    #[doc = " * See C.8 for guidance on when it may be appropriate to use each of these"]
    #[doc = " * approaches."]
    #[doc = " *"]
    #[doc = " * @note The material input to encryption is the bytes of the encryption key "]
    #[doc = " * with no headers, encapsulation, or length indication. Contrast this to "]
    #[doc = " * encryption of data, where the data is encapsulated in an Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum RecipientInfo {
        pskRecipInfo(PreSharedKeyRecipientInfo),
        symmRecipInfo(SymmRecipientInfo),
        certRecipInfo(PKRecipientInfo),
        signedDataRecipInfo(PKRecipientInfo),
        rekRecipInfo(PKRecipientInfo),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains any AppExtensions that apply to the "]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual "]
    #[doc = " * AppExtension type is associated with consistency conditions, specific to "]
    #[doc = " * that extension, that govern its consistency with SPDUs signed by the "]
    #[doc = " * certificate holder and with the CertIssueExtensions in the CA certificates "]
    #[doc = " * in that certificate holder�s chain. Those consistency conditions are "]
    #[doc = " * specified for each individual AppExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfAppExtensions(pub SequenceOf<AppExtension>);
    #[doc = "*"]
    #[doc = " * @brief This field contains any CertIssueExtensions that apply to the "]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual "]
    #[doc = " * CertIssueExtension type is associated with consistency conditions, "]
    #[doc = " * specific to that extension, that govern its consistency with "]
    #[doc = " * AppExtensions in certificates issued by the certificate holder and with "]
    #[doc = " * the CertIssueExtensions in the CA certificates in that certificate "]
    #[doc = " * holder�s chain. Those consistency conditions are specified for each "]
    #[doc = " * individual CertIssueExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfCertIssueExtensions(pub SequenceOf<CertIssueExtension>);
    #[doc = "*"]
    #[doc = " * @brief This field contains any CertRequestExtensions that apply to the "]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual "]
    #[doc = " * CertRequestExtension type is associated with consistency conditions, "]
    #[doc = " * specific to that extension, that govern its consistency with "]
    #[doc = " * AppExtensions in certificates issued by the certificate holder and with "]
    #[doc = " * the CertRequestExtensions in the CA certificates in that certificate "]
    #[doc = " * holder�s chain. Those consistency conditions are specified for each "]
    #[doc = " * individual CertRequestExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfCertRequestExtensions(pub SequenceOf<CertRequestExtension>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfCertificate(pub SequenceOf<Certificate>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidGroupPermissions(pub SequenceOf<PsidGroupPermissions>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRecipientInfo(pub SequenceOf<RecipientInfo>);
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param hashId: indicates the hash algorithm to be used to generate the hash"]
    #[doc = " * of the message for signing and verification."]
    #[doc = " *"]
    #[doc = " * @param tbsData: contains the data that is hashed as input to the signature."]
    #[doc = " *"]
    #[doc = " * @param signer: determines the keying material and hash algorithm used to"]
    #[doc = " * sign the data."]
    #[doc = " *"]
    #[doc = " * @param signature: contains the digital signature itself, calculated as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " *   - If signer indicates the choice self, then the signature calculation"]
    #[doc = " * is parameterized as follows:"]
    #[doc = " *     - Data input is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6."]
    #[doc = " *     - Verification type is equal to self."]
    #[doc = " *     - Signer identifier input is equal to the empty string."]
    #[doc = " *   - If signer indicates certificate or digest, then the signature"]
    #[doc = " * calculation is parameterized as follows:"]
    #[doc = " *     - Data input is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6."]
    #[doc = " *     - Verification type is equal to certificate."]
    #[doc = " *     - Signer identifier input equal to the COER-encoding of the"]
    #[doc = " * Certificate that is to be used to verify the SPDU, canonicalized according"]
    #[doc = " * to the encoding considerations given in 6.4.3."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the ToBeSignedData and the Signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct SignedData {
        #[rasn(identifier = "hashId")]
        pub hash_id: HashAlgorithm,
        #[rasn(identifier = "tbsData")]
        pub tbs_data: ToBeSignedData,
        pub signer: SignerIdentifier,
        pub signature: Signature,
    }
    impl SignedData {
        pub fn new(
            hash_id: HashAlgorithm,
            tbs_data: ToBeSignedData,
            signer: SignerIdentifier,
            signature: Signature,
        ) -> Self {
            Self {
                hash_id,
                tbs_data,
                signer,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the data payload of a ToBeSignedData. This "]
    #[doc = " * structure contains at least one of the optional elements, and may contain "]
    #[doc = " * more than one. See 5.2.4.3.4 for more details."]
    #[doc = " * The security profile in Annex C allows an implementation of this standard "]
    #[doc = " * to state which forms of SignedDataPayload are supported by that "]
    #[doc = " * implementation, and also how the signer and verifier are intended to obtain"]
    #[doc = " * the external data for hashing. The specification of an SDEE that uses "]
    #[doc = " * external data is expected to be explicit and unambiguous about how this "]
    #[doc = " * data is obtained and how it is formatted prior to processing by the hash "]
    #[doc = " * function."]
    #[doc = " *"]
    #[doc = " * @param data: contains data that is explicitly transported within the"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param extDataHash: contains the hash of data that is not explicitly "]
    #[doc = " * transported within the structure, and which the creator of the structure "]
    #[doc = " * wishes to cryptographically bind to the signature. "]
    #[doc = " *"]
    #[doc = " * @param omitted: indicates that there is data to be included in the hash"]
    #[doc = " * calculation for the signature that is not included in the SPDU, either in"]
    #[doc = " * data or by use of the extDataHash. The mechanism for including the omitted"]
    #[doc = " * data in the hash calculation is specified in 6.3.6."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SignedDataPayload {
        pub data: Option<Ieee1609Dot2Data>,
        #[rasn(identifier = "extDataHash")]
        pub ext_data_hash: Option<HashedData>,
        #[rasn(extension_addition)]
        pub omitted: Option<()>,
    }
    impl SignedDataPayload {
        pub fn new(
            data: Option<Ieee1609Dot2Data>,
            ext_data_hash: Option<HashedData>,
            omitted: Option<()>,
        ) -> Self {
            Self {
                data,
                ext_data_hash,
                omitted,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure allows the recipient of data to determine which"]
    #[doc = " * keying material to use to authenticate the data. It also indicates the"]
    #[doc = " * verification type to be used to generate the hash for verification, as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * @param digest: If the choice indicated is digest:"]
    #[doc = " *   - The structure contains the HashedId8 of the relevant certificate. The"]
    #[doc = " * HashedId8 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3."]
    #[doc = " *   - The verification type is certificate and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param certificate: If the choice indicated is certificate:"]
    #[doc = " *   - The structure contains one or more Certificate structures, in order"]
    #[doc = " * such that the first certificate is the authorization certificate and each"]
    #[doc = " * subsequent certificate is the issuer of the one before it. The certificate"]
    #[doc = " * chain may be of any length. It should not include the root CA certificate"]
    #[doc = " * (as the receiving SDS is assumed to know all valid root CAs already)."]
    #[doc = " *   - The verification type is certificate and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param self: If the choice indicated is self:"]
    #[doc = " *   - The structure does not contain any data beyond the indication that"]
    #[doc = " * the choice value is self."]
    #[doc = " *   - The verification type is self-signed."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the CHOICE value for this type"]
    #[doc = " * when verifying a signed SPDU shall indicate that the signed SPDU is invalid."]
    #[doc = " *   - If present, certificate is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of certificates"]
    #[doc = " * in certificate when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid. A compliant implementation shall support certificate"]
    #[doc = " * fields containing at least one certificate."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to every Certificate in the certificate field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SignerIdentifier {
        digest(HashedId8),
        certificate(SequenceOfCertificate),
        #[rasn(identifier = "self")]
        R_self(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This indicates the PSIDs and associated SSPs for which certificate"]
    #[doc = " * issuance or request permissions are granted by a PsidGroupPermissions"]
    #[doc = " * structure. If this takes the value explicit, the enclosing"]
    #[doc = " * PsidGroupPermissions structure grants certificate issuance or request"]
    #[doc = " * permissions for the indicated PSIDs and SSP Ranges. If this takes the"]
    #[doc = " * value all, the enclosing PsidGroupPermissions structure grants certificate"]
    #[doc = " * issuance or request permissions for all PSIDs not indicated by other"]
    #[doc = " * PsidGroupPermissions in the same certIssuePermissions or"]
    #[doc = " * certRequestPermissions field."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is"]
    #[doc = " * invalidin the sense of 4.2.2.3.2, that is, it is invalid in the sense that"]
    #[doc = " * its validity cannot be established."]
    #[doc = " *   - If present, explicit is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of PsidSspRange"]
    #[doc = " * in explicit when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the "]
    #[doc = " * sense that its validity cannot be established. A conformant implementation"]
    #[doc = " * shall support explicit fields containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SubjectPermissions {
        explicit(SequenceOfPsidSspRange),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId: contains the hash of the symmetric key encryption key "]
    #[doc = " * that may be used to decrypt the data encryption key. It consists of the "]
    #[doc = " * low-order 8 bytes of the hash of the COER encoding of a "]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question. "]
    #[doc = " * The HashedId8 is calculated with the hash algorithm determined as "]
    #[doc = " * specified in 5.3.9.4. The symmetric key may be established by any "]
    #[doc = " * appropriate means agreed by the two parties to the exchange."]
    #[doc = " *"]
    #[doc = " * @param encKey: contains the encrypted data encryption key within a "]
    #[doc = " * SymmetricCiphertext, where the data encryption key is input to the data "]
    #[doc = " * encryption key encryption process with no headers, encapsulation, or "]
    #[doc = " * length indication."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct SymmRecipientInfo {
        #[rasn(identifier = "recipientId")]
        pub recipient_id: HashedId8,
        #[rasn(identifier = "encKey")]
        pub enc_key: SymmetricCiphertext,
    }
    impl SymmRecipientInfo {
        pub fn new(recipient_id: HashedId8, enc_key: SymmetricCiphertext) -> Self {
            Self {
                recipient_id,
                enc_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure encapsulates a ciphertext generated with an"]
    #[doc = " * approved symmetric algorithm."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE value for this type in an encrypted SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, "]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricCiphertext {
        aes128ccm(One28BitCcmCiphertext),
        #[rasn(extension_addition)]
        sm4Ccm(One28BitCcmCiphertext),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct TestCertificate(pub Certificate);
    #[doc = "*"]
    #[doc = " * @brief The fields in the ToBeSignedCertificate structure have the"]
    #[doc = " * following meaning:"]
    #[doc = " *"]
    #[doc = " * In other words, for implicit certificates, the value H (CertU) in SEC 4,"]
    #[doc = " * section 3, is for purposes of this standard taken to be H [H"]
    #[doc = " * (canonicalized ToBeSignedCertificate from the subordinate certificate) ||"]
    #[doc = " * H (entirety of issuer Certificate)]. See 5.3.2 for further discussion,"]
    #[doc = " * including material differences between this standard and SEC 4 regarding"]
    #[doc = " * how the hash function output is converted from a bit string to an integer."]
    #[doc = " *"]
    #[doc = " * @param id: contains information that is used to identify the certificate"]
    #[doc = " * holder if necessary."]
    #[doc = " *"]
    #[doc = " * @param cracaId: identifies the Certificate Revocation Authorization CA"]
    #[doc = " * (CRACA) responsible for certificate revocation lists (CRLs) on which this"]
    #[doc = " * certificate might appear. Use of the cracaId is specified in 5.1.3. The"]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate, "]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: represents the CRL series relevant to a particular"]
    #[doc = " * Certificate Revocation Authorization CA (CRACA) on which the certificate"]
    #[doc = " * might appear. Use of this field is specified in 5.1.3."]
    #[doc = " *"]
    #[doc = " * @param validityPeriod: contains the validity period of the certificate."]
    #[doc = " *"]
    #[doc = " * @param region: if present, indicates the validity region of the"]
    #[doc = " * certificate. If it is omitted the validity region is determined as follows:"]
    #[doc = " *   - If the enclosing certificate is self-signed, i.e., the choice indicated"]
    #[doc = " * by the issuer field in the enclosing certificate structure is self, the"]
    #[doc = " * certificate is valid worldwide."]
    #[doc = " *   - Otherwise, the certificate has the same validity region as the"]
    #[doc = " * certificate that issued it."]
    #[doc = " *"]
    #[doc = " * The above algorithm is applied recursively, i.e. if region is omitted from"]
    #[doc = " * the issuing certificate, then the issuing certificate of that certificate is"]
    #[doc = " * inspected to determine if region is present, and so on. A certificate,"]
    #[doc = " * therefore, has global geographic validity as defined in 5.2.6.6.3.1 if"]
    #[doc = " * region is not present in the certificate or in any certificate in its chain."]
    #[doc = " * Otherwise, i.e., if region is present in the certificate or in at least one"]
    #[doc = " * certificate in its chain, the certificate has area validity as defined in"]
    #[doc = " * 5.2.6.6.3.1."]
    #[doc = " *"]
    #[doc = " * The use of the validity region to determine geographic consistency of an"]
    #[doc = " * SPDU is specified in 5.2.6.6.3.1. The use of the validity region to"]
    #[doc = " * determine geographic consistency of a subordinate certificate with an"]
    #[doc = " * issuing certificate is specified in 5.1.2.4."]
    #[doc = " *"]
    #[doc = " * @param assuranceLevel: indicates the assurance level of the certificate"]
    #[doc = " * holder."]
    #[doc = " *"]
    #[doc = " * @param appPermissions: indicates the permissions that the certificate"]
    #[doc = " * holder has to sign application data with this certificate. A valid"]
    #[doc = " * instance of appPermissions contains any particular Psid value in at most"]
    #[doc = " * one entry."]
    #[doc = " *"]
    #[doc = " * @param certIssuePermissions: indicates the permissions that the certificate"]
    #[doc = " * holder has to sign certificates with this certificate. A valid instance of"]
    #[doc = " * this array contains no more than one entry whose psidSspRange field"]
    #[doc = " * indicates all. If the array has multiple entries and one entry has its"]
    #[doc = " * psidSspRange field indicate all, then the entry indicating all specifies"]
    #[doc = " * the permissions for all PSIDs other than the ones explicitly specified in"]
    #[doc = " * the other entries. See the description of PsidGroupPermissions for further"]
    #[doc = " * discussion."]
    #[doc = " *"]
    #[doc = " * @param certRequestPermissions: indicates the permissions that the "]
    #[doc = " * certificate holder can request in its certificate. A valid instance of this"]
    #[doc = " * array contains no more than one entry whose psidSspRange field indicates "]
    #[doc = " * all. If the array has multiple entries and one entry has its psidSspRange "]
    #[doc = " * field indicate all, then the entry indicating all specifies the permissions "]
    #[doc = " * for all PSIDs other than the ones explicitly specified in the other entries."]
    #[doc = " * See the description of PsidGroupPermissions for further discussion."]
    #[doc = " *"]
    #[doc = " * @param canRequestRollover: indicates that the certificate may be used to"]
    #[doc = " * sign a request for another certificate with the same permissions. This"]
    #[doc = " * field is provided for future use and its use is not defined in this"]
    #[doc = " * version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: contains a public key for encryption for which the"]
    #[doc = " * certificate holder holds the corresponding private key."]
    #[doc = " *"]
    #[doc = " * @param verifyKeyIndicator: contains material that may be used to recover"]
    #[doc = " * the public key that may be used to verify data signed by this certificate."]
    #[doc = " *"]
    #[doc = " * @param flags: indicates additional yes/no properties of the certificate "]
    #[doc = " * holder. The only bit with defined semantics in this string in this version "]
    #[doc = " * of this standard is usesCubk. If set, the usesCubk bit indicates that the "]
    #[doc = " * certificate holder supports the compact unified butterfly key response. "]
    #[doc = " * Further material about the compact unified butterfly key response can be "]
    #[doc = " * found in IEEE Std 1609.2.1."]
    #[doc = " *"]
    #[doc = " * If this field is present, at least one of the bits in the field shall be"]
    #[doc = " * non-zero."]
    #[doc = " *"]
    #[doc = " * @note usesCubk is only relevant for CA certificates, and the only "]
    #[doc = " * functionality defined associated with this field is associated with "]
    #[doc = " * consistency checks on received certificate responses. No functionality "]
    #[doc = " * associated with communications between peer SDEEs is defined associated "]
    #[doc = " * with this field."]
    #[doc = " *"]
    #[doc = " * @param appExtensions: indicates additional permissions that may be applied"]
    #[doc = " * to application activities that the certificate holder is carrying out. "]
    #[doc = " *"]
    #[doc = " * @param certIssueExtensions: indicates additional permissions to issue "]
    #[doc = " * certificates containing appExtensions. "]
    #[doc = " *"]
    #[doc = " * @param certRequestExtensions: indicates additional permissions to request "]
    #[doc = " * certificates containing endEntityExtensions."]
    #[doc = " *"]
    #[doc = " * @note In IEEE Std 1609.2-2022 these were not marked optional; they are in"]
    #[doc = " * this version of the standard; this is technically not backwards compatible"]
    #[doc = " * but in practice there are no scenarios in which a legacy system will break"]
    #[doc = " * (because it would have to be the case that Issue or Request was included and"]
    #[doc = " * App wasn't, but no issue or request extension values are currently defined)."]
    #[doc = " * "]
    #[doc = " * @note Issue and Request extensions are specified in this version of this"]
    #[doc = " * standard for future use but do not currently have any values defined. The"]
    #[doc = " * only certificate extension defined is OperatingOrganizationId and that can"]
    #[doc = " * be issued by any CA. It can be taken as likely that future appExtensions"]
    #[doc = " * will also be issuable by any CA, as otherwise consistency rules will differ"]
    #[doc = " * between appExtensions, and so in practice these certIssueExtensions and"]
    #[doc = " * certRequestExtensions fields will never be use. See Annex G for discussion"]
    #[doc = " * of how the standard could in principle be extended to include extensions"]
    #[doc = " * that do have a need to be validated up the chain."]
    #[doc = " *"]
    #[doc = " * @note Calculating the hash of a certificate:"]
    #[doc = " * For both implicit and explicit certificates, when the certificate"]
    #[doc = " * is hashed to create or recover the public key (in the case of an implicit"]
    #[doc = " * certificate) or to generate or verify the signature (in the case of an"]
    #[doc = " * explicit certificate), the hash is Hash (Data input) || Hash ("]
    #[doc = " * Signer identifier input), where:"]
    #[doc = " *   - Data input is the COER encoding of toBeSigned, canonicalized"]
    #[doc = " * as described above."]
    #[doc = " *   - Signer identifier input depends on the verification type,"]
    #[doc = " * which in turn depends on the choice indicated by issuer. If the choice"]
    #[doc = " * indicated by issuer is self, the verification type is self-signed and the"]
    #[doc = " * signer identifier input is the empty string. If the choice indicated by"]
    #[doc = " * issuer is not self, the verification type is certificate and the signer"]
    #[doc = " * identifier input is the COER encoding of the canonicalization per 6.4.3 of"]
    #[doc = " * the certificate indicated by issuer."]
    #[doc = " *"]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the PublicEncryptionKey and to the VerificationKeyIndicator."]
    #[doc = " *"]
    #[doc = " * If the PublicEncryptionKey contains a BasePublicEncryptionKey that is an "]
    #[doc = " * elliptic curve point (i.e., of type EccP256CurvePoint or EccP384CurvePoint),"]
    #[doc = " * then the elliptic curve point is encoded in compressed form, i.e., such "]
    #[doc = " * that the choice indicated within the Ecc*CurvePoint is compressed-y-0 or "]
    #[doc = " * compressed-y-1."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, appPermissions is a critical information field as defined "]
    #[doc = " * in 5.2.6. If an implementation of verification does not support the number "]
    #[doc = " * of PsidSsp in the appPermissions field of a certificate that signed a "]
    #[doc = " * signed SPDU, that implementation shall indicate that the signed SPDU is "]
    #[doc = " * invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense "]
    #[doc = " * that its validity cannot be established.. A conformant implementation "]
    #[doc = " * shall support appPermissions fields containing at least eight entries. "]
    #[doc = " * It may be the case that an implementation of verification does not support "]
    #[doc = " * the number of entries in  the appPermissions field and the appPermissions "]
    #[doc = " * field is not relevant to the verification: this will occur, for example, "]
    #[doc = " * if the certificate in question is a CA certificate and so the "]
    #[doc = " * certIssuePermissions field is relevant to the verification and the "]
    #[doc = " * appPermissions field is not. In this case, whether the implementation "]
    #[doc = " * indicates that the signed SPDU is valid (because it could validate all "]
    #[doc = " * relevant fields) or invalid (because it could not parse the entire "]
    #[doc = " * certificate) is implementation-specific."]
    #[doc = " *   - If present, certIssuePermissions is a critical information field as "]
    #[doc = " * defined in 5.2.6. If an implementation of verification does not support "]
    #[doc = " * the number of PsidGroupPermissions in the certIssuePermissions field of a "]
    #[doc = " * CA certificate in the chain of a signed SPDU, the implementation shall "]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that "]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established. "]
    #[doc = " * A conformant implementation shall support certIssuePermissions fields "]
    #[doc = " * containing at least eight entries."]
    #[doc = " * It may be the case that an implementation of verification does not support"]
    #[doc = " * the number of entries in  the certIssuePermissions field and the "]
    #[doc = " * certIssuePermissions field is not relevant to the verification: this will "]
    #[doc = " * occur, for example, if the certificate in question is the signing "]
    #[doc = " * certificate for the SPDU and so the appPermissions field is relevant to "]
    #[doc = " * the verification and the certIssuePermissions field is not. In this case, "]
    #[doc = " * whether the implementation indicates that the signed SPDU is valid "]
    #[doc = " * (because it could validate all relevant fields) or invalid (because it "]
    #[doc = " * could not parse the entire certificate) is implementation-specific."]
    #[doc = " *   - If present, certRequestPermissions is a critical information field as "]
    #[doc = " * defined in 5.2.6. If an implementaiton of verification of a certificate "]
    #[doc = " * request does not support the number of PsidGroupPermissions in "]
    #[doc = " * certRequestPermissions, the implementation shall indicate that the signed "]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the "]
    #[doc = " * sense that its validity cannot be established. A conformant implementation "]
    #[doc = " * shall support certRequestPermissions fields containing at least eight "]
    #[doc = " * entries."]
    #[doc = " * It may be the case that an implementation of verification does not support "]
    #[doc = " * the number of entries in  the certRequestPermissions field and the "]
    #[doc = " * certRequestPermissions field is not relevant to the verification: this will "]
    #[doc = " * occur, for example, if the certificate in question is the signing "]
    #[doc = " * certificate for the SPDU and so the appPermissions field is relevant to "]
    #[doc = " * the verification and the certRequestPermissions field is not. In this "]
    #[doc = " * case, whether the implementation indicates that the signed SPDU is valid "]
    #[doc = " * (because it could validate all relevant fields) or invalid (because it "]
    #[doc = " * could not parse the entire certificate) is implementation-specific."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedCertificate {
        pub id: CertificateId,
        #[rasn(identifier = "cracaId")]
        pub craca_id: HashedId3,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
        #[rasn(identifier = "validityPeriod")]
        pub validity_period: ValidityPeriod,
        pub region: Option<GeographicRegion>,
        #[rasn(identifier = "assuranceLevel")]
        pub assurance_level: Option<SubjectAssurance>,
        #[rasn(identifier = "appPermissions")]
        pub app_permissions: Option<SequenceOfPsidSsp>,
        #[rasn(identifier = "certIssuePermissions")]
        pub cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
        #[rasn(identifier = "certRequestPermissions")]
        pub cert_request_permissions: Option<SequenceOfPsidGroupPermissions>,
        #[rasn(identifier = "canRequestRollover")]
        pub can_request_rollover: Option<()>,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<PublicEncryptionKey>,
        #[rasn(identifier = "verifyKeyIndicator")]
        pub verify_key_indicator: VerificationKeyIndicator,
        #[rasn(extension_addition, size("8"))]
        pub flags: Option<BitString>,
        #[rasn(extension_addition, identifier = "appExtensions")]
        pub app_extensions: Option<SequenceOfAppExtensions>,
        #[rasn(extension_addition, identifier = "certIssueExtensions")]
        pub cert_issue_extensions: Option<SequenceOfCertIssueExtensions>,
        #[rasn(extension_addition, identifier = "certRequestExtension")]
        pub cert_request_extension: Option<SequenceOfCertRequestExtensions>,
    }
    impl ToBeSignedCertificate {
        pub fn new(
            id: CertificateId,
            craca_id: HashedId3,
            crl_series: CrlSeries,
            validity_period: ValidityPeriod,
            region: Option<GeographicRegion>,
            assurance_level: Option<SubjectAssurance>,
            app_permissions: Option<SequenceOfPsidSsp>,
            cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
            cert_request_permissions: Option<SequenceOfPsidGroupPermissions>,
            can_request_rollover: Option<()>,
            encryption_key: Option<PublicEncryptionKey>,
            verify_key_indicator: VerificationKeyIndicator,
            flags: Option<BitString>,
            app_extensions: Option<SequenceOfAppExtensions>,
            cert_issue_extensions: Option<SequenceOfCertIssueExtensions>,
            cert_request_extension: Option<SequenceOfCertRequestExtensions>,
        ) -> Self {
            Self {
                id,
                craca_id,
                crl_series,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
                cert_request_permissions,
                can_request_rollover,
                encryption_key,
                verify_key_indicator,
                flags,
                app_extensions,
                cert_issue_extensions,
                cert_request_extension,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the data to be hashed when generating or"]
    #[doc = " * verifying a signature. See 6.3.4 for the specification of the input to the"]
    #[doc = " * hash."]
    #[doc = " *"]
    #[doc = " * @param payload: contains data that is provided by the entity that invokes"]
    #[doc = " * the SDS."]
    #[doc = " *"]
    #[doc = " * @param headerInfo: contains additional data that is inserted by the SDS."]
    #[doc = " * This structure is used as follows to determine the \"data input\" to the "]
    #[doc = " * hash operation for signing or verification as specified in 5.3.1.2.2 or "]
    #[doc = " * 5.3.1.3."]
    #[doc = " *   - If payload does not contain the field omitted, the data input to the "]
    #[doc = " * hash operation is the COER encoding of the ToBeSignedData. "]
    #[doc = " *   - If payload field in this ToBeSignedData instance contains the field "]
    #[doc = " * omitted, the data input to the hash operation is the COER encoding of the"]
    #[doc = " * ToBeSignedData, concatenated with the hash of the omitted payload. The hash"]
    #[doc = " * of the omitted payload is calculated with the same hash algorithm that is "]
    #[doc = " * used to calculate the hash of the data input for signing or verification. "]
    #[doc = " * The data input to the hash operation is simply the COER encoding of the "]
    #[doc = " * ToBeSignedData, concatenated with the hash of the omitted payload: there is"]
    #[doc = " * no additional wrapping or length indication. As noted in 5.2.4.3.4, the "]
    #[doc = " * means by which the signer and verifier establish the contents of the "]
    #[doc = " * omitted payload are outside the scope of this standard."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the SignedDataPayload if it is of type data, and to the "]
    #[doc = " * HeaderInfo."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ToBeSignedData {
        pub payload: Box<SignedDataPayload>,
        #[rasn(identifier = "headerInfo")]
        pub header_info: HeaderInfo,
    }
    impl ToBeSignedData {
        pub fn new(payload: Box<SignedDataPayload>, header_info: HeaderInfo) -> Self {
            Self {
                payload,
                header_info,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief The contents of this field depend on whether the certificate is an"]
    #[doc = " * implicit or an explicit certificate."]
    #[doc = " *"]
    #[doc = " * @param verificationKey: is included in explicit certificates. It contains"]
    #[doc = " * the public key to be used to verify signatures generated by the holder of"]
    #[doc = " * the Certificate."]
    #[doc = " *"]
    #[doc = " * @param reconstructionValue: is included in implicit certificates. It"]
    #[doc = " * contains the reconstruction value, which is used to recover the public key"]
    #[doc = " * as specified in SEC 4 and 5.3.2."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical "]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not "]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU "]
    #[doc = " * shall indicate that the signed SPDU is invalid indicate that the signed "]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the "]
    #[doc = " * sense that its validity cannot be established."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the PublicVerificationKey and to the EccP256CurvePoint. The "]
    #[doc = " * EccP256CurvePoint is encoded in compressed form, i.e., such that the "]
    #[doc = " * choice indicated within the EccP256CurvePoint is compressed-y-0 or "]
    #[doc = " * compressed-y-1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum VerificationKeyIndicator {
        verificationKey(PublicVerificationKey),
        reconstructionValue(EccP256CurvePoint),
    }
    pub const CERT_EXT_ID_OPERATING_ORGANIZATION: ExtId = ExtId(1);
    pub const ETSI_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId = HeaderInfoContributorId(2);
    pub const IEEE1609_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId =
        HeaderInfoContributorId(1);
    pub const ISO21177_EXTENDED_AUTH: PduFunctionalType = PduFunctionalType(2);
    pub const ISO21177_SESSION_EXTENSION: PduFunctionalType = PduFunctionalType(3);
    pub const P2PCD8_BYTE_LEARNING_REQUEST_ID: Ieee1609HeaderInfoExtensionId =
        Ieee1609HeaderInfoExtensionId(ExtId(1));
    pub const TLS_HANDSHAKE: PduFunctionalType = PduFunctionalType(1);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_base_types {
    extern crate alloc;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = "*"]
    #[doc = " * @brief This structure specifies the bytes of a public encryption key for "]
    #[doc = " * a particular algorithm. Supported public key encryption algorithms are "]
    #[doc = " * defined in 5.3.5."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a "]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum BasePublicEncryptionKey {
        eciesNistP256(EccP256CurvePoint),
        eciesBrainpoolP256r1(EccP256CurvePoint),
        #[rasn(extension_addition)]
        ecencSm2(EccP256CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * mapping of the bits of the bitmap to constraints on the signed SPDU is"]
    #[doc = " * PSID-specific."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is bitmapSsp, A is"]
    #[doc = " * consistent with the issuing certificate if the  certificate contains one"]
    #[doc = " * of the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - EITHER The sspRange field in P indicates all"]
    #[doc = " *       - OR The sspRange field in P indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in P, the bit in the identical position in"]
    #[doc = " * the sspValue in A is set equal to the bit in that position in the"]
    #[doc = " * sspValue in P."]
    #[doc = " *"]
    #[doc = " * @note To restate the final sub-bullet point immediately above: A BitmapSsp B"]
    #[doc = " * is consistent with a BitmapSspRange R if for every bit set to 1 in the"]
    #[doc = " * sspBitmask in R, the bit in the identical position in B is set equal to the"]
    #[doc = " * bit in that position in the sspValue in R. For each bit set to 0 in the"]
    #[doc = " * sspBitmask in R, the corresponding bit in the identical position in B may be"]
    #[doc = " * freely set to 0 or 1, i.e., if a bit is set to 0 in the sspBitmask in R, the"]
    #[doc = " * value of corresponding bit in the identical position in B has no bearing on"]
    #[doc = " * whether B and R are consistent."]
    #[doc = " *"]
    #[doc = " * @note Where a BitmapSsp in an authorization certificate is being compared"]
    #[doc = " * with a BitmapSspRange in an issuing certificate, the rules given above imply"]
    #[doc = " * that the BitmapSsp: (a) cannot be longer than BitmapSspRange in the issuing"]
    #[doc = " * cert; (b) Can be shorter than the BitmapSspRange but must be long enough to"]
    #[doc = " * reach the last \"1\" bit in the sspBitmask."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("0..=31"))]
    pub struct BitmapSsp(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * sspValue indicates permissions. The sspBitmask contains an octet string"]
    #[doc = " * used to permit or constrain sspValue fields in issued certificates. The"]
    #[doc = " * sspValue and sspBitmask fields shall be of the same length."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * PsidSspRange value P for which the sspRange field is bitmapSspRange,"]
    #[doc = " * P is consistent with the issuing certificate if the issuing certificate"]
    #[doc = " * contains one of the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in P;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange R for which the following holds:"]
    #[doc = " *     - The psid field in R is equal to the psid field in P and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - EITHER The sspRange field in R indicates all"]
    #[doc = " *       - OR The sspRange field in R indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in R:"]
    #[doc = " *         - The bit in the identical position in the sspBitmask in P is set"]
    #[doc = " * equal to 1, AND"]
    #[doc = " *         - The bit in the identical position in the sspValue in P is set equal"]
    #[doc = " * to the bit in that position in the sspValue in R."]
    #[doc = " *"]
    #[doc = " * Reference ETSI TS 103 097 for more information on bitmask SSPs."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct BitmapSspRange {
        #[rasn(size("1..=32"), identifier = "sspValue")]
        pub ssp_value: OctetString,
        #[rasn(size("1..=32"), identifier = "sspBitmask")]
        pub ssp_bitmask: OctetString,
    }
    impl BitmapSspRange {
        pub fn new(ssp_value: OctetString, ssp_bitmask: OctetString) -> Self {
            Self {
                ssp_value,
                ssp_bitmask,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a circle with its center at center, its"]
    #[doc = " * radius given in meters, and located tangential to the reference ellipsoid."]
    #[doc = " * The indicated region is all the points on the surface of the reference"]
    #[doc = " * ellipsoid whose distance to the center point over the reference ellipsoid"]
    #[doc = " * is less than or equal to the radius. A point which contains an elevation"]
    #[doc = " * component is considered to be within the circular region if its horizontal"]
    #[doc = " * projection onto the reference ellipsoid lies within the region."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CircularRegion {
        pub center: TwoDLocation,
        pub radius: Uint16,
    }
    impl CircularRegion {
        pub fn new(center: TwoDLocation, radius: Uint16) -> Self {
            Self { center, radius }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief A conformant implementation that supports CountryAndRegions shall "]
    #[doc = " * support a regions field containing at least eight entries."]
    #[doc = " * A conformant implementation that implements this type shall recognize "]
    #[doc = " * (in the sense of \"be able to determine whether a two dimensional location "]
    #[doc = " * lies inside or outside the borders identified by\") at least one value of "]
    #[doc = " * UnCountryId and at least one value for a region within the country "]
    #[doc = " * indicated by that recognized UnCountryId value. In this version of this "]
    #[doc = " * standard, the only means to satisfy this is for a conformant "]
    #[doc = " * implementation to recognize the value of UnCountryId indicating USA and "]
    #[doc = " * at least one of the FIPS state codes for US states. The Protocol "]
    #[doc = " * Implementation Conformance Statement (PICS) provided in Annex A allows "]
    #[doc = " * an implementation to state which UnCountryId values it recognizes and "]
    #[doc = " * which region values are recognized within that country."]
    #[doc = " * If a verifying implementation is required to check that relevant "]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate "]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted "]
    #[doc = " * to indicate that the signed SPDU is valid even if some values of country "]
    #[doc = " * or within regions are unrecognized in the sense defined above, so long "]
    #[doc = " * as the recognized instances of this type completely contain the relevant "]
    #[doc = " * geographic information. Informally, if the recognized values in the "]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it "]
    #[doc = " * can make that determination even if there are also unrecognized values "]
    #[doc = " * in the certificate. This field is therefore not a \"critical information "]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so "]
    #[doc = " * long as the validity of the SPDU can be established with the recognized "]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized "]
    #[doc = " * value in a certificate can make it impossible to determine whether the "]
    #[doc = " * certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this type:"]
    #[doc = " *"]
    #[doc = " * @param countryOnly: is a UnCountryId as defined above."]
    #[doc = " *"]
    #[doc = " * @param regions: identifies one or more regions within the country. If "]
    #[doc = " * country indicates the United States of America, the values in this field "]
    #[doc = " * identify the state or statistically equivalent entity using the integer "]
    #[doc = " * version of the 2010 FIPS codes as provided by the U.S. Census Bureau "]
    #[doc = " * (see normative references in Clause 0). For other values of country, the "]
    #[doc = " * meaning of region is not defined in this version of this standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CountryAndRegions {
        #[rasn(identifier = "countryOnly")]
        pub country_only: UnCountryId,
        pub regions: SequenceOfUint8,
    }
    impl CountryAndRegions {
        pub fn new(country_only: UnCountryId, regions: SequenceOfUint8) -> Self {
            Self {
                country_only,
                regions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief A conformant implementation that supports CountryAndSubregions "]
    #[doc = " * shall support a regionAndSubregions field containing at least eight "]
    #[doc = " * entries."]
    #[doc = " * A conformant implementation that implements this type shall recognize "]
    #[doc = " * (in the sense of �be able to determine whether a two dimensional location "]
    #[doc = " * lies inside or outside the borders identified by�) at least one value of "]
    #[doc = " * country and at least one value for a region within the country indicated "]
    #[doc = " * by that recognized country value. In this version of this standard, the "]
    #[doc = " * only means to satisfy this is for a conformant implementation to recognize "]
    #[doc = " * the value of UnCountryId indicating USA and at least one of the FIPS state "]
    #[doc = " * codes for US states. The Protocol Implementation Conformance Statement "]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which "]
    #[doc = " * UnCountryId values it recognizes and which region values are recognized "]
    #[doc = " * within that country."]
    #[doc = " * If a verifying implementation is required to check that relevant "]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate "]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted "]
    #[doc = " * to indicate that the signed SPDU is valid even if some values of country "]
    #[doc = " * or within regionAndSubregions are unrecognized in the sense defined above,"]
    #[doc = " * so long as the recognized instances of this type completely contain the "]
    #[doc = " * relevant geographic information. Informally, if the recognized values in "]
    #[doc = " * the certificate allow the SDS to determine that the SPDU is valid, then "]
    #[doc = " * it can make that determination even if there are also unrecognized values "]
    #[doc = " * in the certificate. This field is therefore not a \"critical information "]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so "]
    #[doc = " * long as the validity of the SPDU can be established with the recognized "]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized "]
    #[doc = " * value in a certificate can make it impossible to determine whether the "]
    #[doc = " * certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this structure:"]
    #[doc = " *"]
    #[doc = " * @param countryOnly: is a UnCountryId as defined above."]
    #[doc = " *"]
    #[doc = " * @param regionAndSubregions: identifies one or more subregions within "]
    #[doc = " * country."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CountryAndSubregions {
        #[rasn(identifier = "countryOnly")]
        pub country_only: UnCountryId,
        #[rasn(identifier = "regionAndSubregions")]
        pub region_and_subregions: SequenceOfRegionAndSubregions,
    }
    impl CountryAndSubregions {
        pub fn new(
            country_only: UnCountryId,
            region_and_subregions: SequenceOfRegionAndSubregions,
        ) -> Self {
            Self {
                country_only,
                region_and_subregions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is defined only for backwards compatibility."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CountryOnly(pub UnCountryId);
    #[doc = "*"]
    #[doc = " * @brief This integer identifies a series of CRLs issued under the authority"]
    #[doc = " * of a particular CRACA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CrlSeries(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure represents the duration of validity of a"]
    #[doc = " * certificate. The Uint16 value is the duration, given in the units denoted"]
    #[doc = " * by the indicated choice. A year is considered to be 31556952 seconds,"]
    #[doc = " * which is the average number of seconds in a year."]
    #[doc = " * "]
    #[doc = " * @note Years can be mapped more closely to wall-clock days using the hours "]
    #[doc = " * choice for up to 7 years and the sixtyHours choice for up to 448 years. "]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum Duration {
        microseconds(Uint16),
        milliseconds(Uint16),
        seconds(Uint16),
        minutes(Uint16),
        hours(Uint16),
        sixtyHours(Uint16),
        years(Uint16),
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EccP256CurvePointUncompressedP256 {
        #[rasn(size("32"))]
        pub x: OctetString,
        #[rasn(size("32"))]
        pub y: OctetString,
    }
    impl EccP256CurvePointUncompressedP256 {
        pub fn new(x: OctetString, y: OctetString) -> Self {
            Self { x, y }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a point on an elliptic curve in Weierstrass"]
    #[doc = " * form defined over a 256-bit prime number. The curves supported in this"]
    #[doc = " * standard are NIST p256 as defined in FIPS 186-5, Brainpool p256r1 as"]
    #[doc = " * defined in RFC 5639, and the SM2 curve as defined in GB/T 32918.5-2017."]
    #[doc = " * The fields in this structure are OCTET STRINGS produced with the elliptic"]
    #[doc = " * curve point encoding and decoding methods defined in subclause 5.5.6 of"]
    #[doc = " * IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned integer of"]
    #[doc = " * length 32 octets in network byte order for all values of the CHOICE; the"]
    #[doc = " * encoding of the y-coordinate y depends on whether the point is x-only,"]
    #[doc = " * compressed, or uncompressed. If the point is x-only, y is omitted. If the"]
    #[doc = " * point is compressed, the value of type depends on the least significant"]
    #[doc = " * bit of y: if the least significant bit of y is 0, type takes the value"]
    #[doc = " * compressed-y-0, and if the least significant bit of y is 1, type takes the"]
    #[doc = " * value compressed-y-1. If the point is uncompressed, y is encoded explicitly"]
    #[doc = " * as an unsigned integer of length 32 octets in network byte order."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a "]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization "]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EccP256CurvePoint {
        #[rasn(size("32"), identifier = "x-only")]
        x_only(OctetString),
        fill(()),
        #[rasn(size("32"), identifier = "compressed-y-0")]
        compressed_y_0(OctetString),
        #[rasn(size("32"), identifier = "compressed-y-1")]
        compressed_y_1(OctetString),
        uncompressedP256(EccP256CurvePointUncompressedP256),
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EccP384CurvePointUncompressedP384 {
        #[rasn(size("48"))]
        pub x: OctetString,
        #[rasn(size("48"))]
        pub y: OctetString,
    }
    impl EccP384CurvePointUncompressedP384 {
        pub fn new(x: OctetString, y: OctetString) -> Self {
            Self { x, y }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a point on an elliptic curve in"]
    #[doc = " * Weierstrass form defined over a 384-bit prime number. The only supported"]
    #[doc = " * such curve in this standard is Brainpool p384r1 as defined in RFC 5639."]
    #[doc = " * The fields in this structure are octet strings produced with the elliptic"]
    #[doc = " * curve point encoding and decoding methods defined in subclause 5.5.6 of"]
    #[doc = " * IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned integer of"]
    #[doc = " * length 48 octets in network byte order for all values of the CHOICE; the"]
    #[doc = " * encoding of the y-coordinate y depends on whether the point is x-only,"]
    #[doc = " * compressed, or uncompressed. If the point is x-only, y is omitted. If the"]
    #[doc = " * point is compressed, the value of type depends on the least significant"]
    #[doc = " * bit of y: if the least significant bit of y is 0, type takes the value"]
    #[doc = " * compressed-y-0, and if the least significant bit of y is 1, type takes the"]
    #[doc = " * value compressed-y-1. If the point is uncompressed, y is encoded"]
    #[doc = " * explicitly as an unsigned integer of length 48 octets in network byte order."]
    #[doc = " * "]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a "]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization "]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EccP384CurvePoint {
        #[rasn(size("48"), identifier = "x-only")]
        x_only(OctetString),
        fill(()),
        #[rasn(size("48"), identifier = "compressed-y-0")]
        compressed_y_0(OctetString),
        #[rasn(size("48"), identifier = "compressed-y-1")]
        compressed_y_1(OctetString),
        uncompressedP384(EccP384CurvePointUncompressedP384),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of FIPS 186-5"]
    #[doc = " * and output the integer r, r is represented as an EccP256CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP256CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender's discretion."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. When this data structure "]
    #[doc = " * is canonicalized, the EccP256CurvePoint in rSig is represented in the "]
    #[doc = " * form x-only."]
    #[doc = " *"]
    #[doc = " * @note When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-\\*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle, this means that to convert a"]
    #[doc = " * signature from form compressed-y-\\* to form x-only, the converter checks "]
    #[doc = " * the x-value to see if it lies between n and p and reduces it mod n if so. "]
    #[doc = " * In practice, this check is unnecessary: Haase's Theorem states that "]
    #[doc = " * difference between n and p is always less than 2*square-root(p), and so the "]
    #[doc = " * chance that an integer lies between n and p, for a 256-bit curve, is "]
    #[doc = " * bounded above by approximately square-root(p)/p or 2^(-128). For the "]
    #[doc = " * 256-bit curves in this standard, the exact values of n and p in hexadecimal "]
    #[doc = " * are:"]
    #[doc = " *"]
    #[doc = " * NISTp256:"]
    #[doc = " *   - p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"]
    #[doc = " *   - n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"]
    #[doc = " *"]
    #[doc = " * Brainpoolp256:"]
    #[doc = " *   - p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"]
    #[doc = " *   - n = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcdsaP256Signature {
        #[rasn(identifier = "rSig")]
        pub r_sig: EccP256CurvePoint,
        #[rasn(size("32"), identifier = "sSig")]
        pub s_sig: OctetString,
    }
    impl EcdsaP256Signature {
        pub fn new(r_sig: EccP256CurvePoint, s_sig: OctetString) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of FIPS 186-5"]
    #[doc = " * and output the integer r, r is represented as an EccP384CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP384CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender's discretion."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. When this data structure "]
    #[doc = " * is canonicalized, the EccP384CurvePoint in rSig is represented in the "]
    #[doc = " * form x-only."]
    #[doc = " *"]
    #[doc = " * @note When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-\\*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle, this means that to convert a "]
    #[doc = " * signature from form compressed-y-* to form x-only, the converter checks the"]
    #[doc = " * x-value to see if it lies between n and p and reduces it mod n if so. In"]
    #[doc = " * practice, this check is unnecessary: Haase's Theorem states that difference"]
    #[doc = " * between n and p is always less than 2*square-root(p), and so the chance"]
    #[doc = " * that an integer lies between n and p, for a 384-bit curve, is bounded"]
    #[doc = " * above by approximately square-root(p)/p or 2^(-192). For the 384-bit curve"]
    #[doc = " * in this standard, the exact values of n and p in hexadecimal are:"]
    #[doc = " *   - p = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"]
    #[doc = " * ACD3A729901D1A71874700133107EC53"]
    #[doc = " *   - n = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"]
    #[doc = " * CF3AB6AF6B7FC3103B883202E9046565"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcdsaP384Signature {
        #[rasn(identifier = "rSig")]
        pub r_sig: EccP384CurvePoint,
        #[rasn(size("48"), identifier = "sSig")]
        pub s_sig: OctetString,
    }
    impl EcdsaP384Signature {
        pub fn new(r_sig: EccP384CurvePoint, s_sig: OctetString) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to transfer a 16-byte symmetric key "]
    #[doc = " * encrypted using SM2 encryption as specified in 5.3.3. The symmetric key is "]
    #[doc = " * input to the key encryption process with no headers, encapsulation, or "]
    #[doc = " * length indication. Encryption and decryption are carried out as specified "]
    #[doc = " * in 5.3.5.2."]
    #[doc = " * "]
    #[doc = " * @param v: is the sender's ephemeral public key, which is the output V from"]
    #[doc = " * encryption as specified in 5.3.5.2."]
    #[doc = " *"]
    #[doc = " * @param c: is the encrypted symmetric key, which is the output C from "]
    #[doc = " * encryption as specified in 5.3.5.2. The algorithm for the symmetric key "]
    #[doc = " * is identified by the CHOICE indicated in the following SymmetricCiphertext. "]
    #[doc = " * For SM2 this algorithm shall be SM4."]
    #[doc = " *"]
    #[doc = " * @param t: is the authentication tag, which is the output tag from"]
    #[doc = " * encryption as specified in 5.3.5.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcencP256EncryptedKey {
        pub v: EccP256CurvePoint,
        #[rasn(size("16"))]
        pub c: OctetString,
        #[rasn(size("32"))]
        pub t: OctetString,
    }
    impl EcencP256EncryptedKey {
        pub fn new(v: EccP256CurvePoint, c: OctetString, t: OctetString) -> Self {
            Self { v, c, t }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to transfer a 16-byte symmetric key"]
    #[doc = " * encrypted using ECIES as specified in IEEE Std 1363a-2004. The symmetric "]
    #[doc = " * key is input to the key encryption process with no headers, encapsulation, "]
    #[doc = " * or length indication. Encryption and decryption are carried out as "]
    #[doc = " * specified in 5.3.5.1."]
    #[doc = " *"]
    #[doc = " * @param v: is the sender's ephemeral public key, which is the output V from"]
    #[doc = " * encryption as specified in 5.3.5.1."]
    #[doc = " *"]
    #[doc = " * @param c: is the encrypted symmetric key, which is the output C from "]
    #[doc = " * encryption as specified in 5.3.5.1. The algorithm for the symmetric key "]
    #[doc = " * is identified by the CHOICE indicated in the following SymmetricCiphertext. "]
    #[doc = " * For ECIES this shall be AES-128."]
    #[doc = " *"]
    #[doc = " * @param t: is the authentication tag, which is the output tag from"]
    #[doc = " * encryption as specified in 5.3.5.1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EciesP256EncryptedKey {
        pub v: EccP256CurvePoint,
        #[rasn(size("16"))]
        pub c: OctetString,
        #[rasn(size("16"))]
        pub t: OctetString,
    }
    impl EciesP256EncryptedKey {
        pub fn new(v: EccP256CurvePoint, c: OctetString, t: OctetString) -> Self {
            Self { v, c, t }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents a elliptic curve signature where the"]
    #[doc = " * component r is constrained to be an integer. This structure supports SM2 "]
    #[doc = " * signatures as specified in 5.3.1.3."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcsigP256Signature {
        #[rasn(size("32"), identifier = "rSig")]
        pub r_sig: OctetString,
        #[rasn(size("32"), identifier = "sSig")]
        pub s_sig: OctetString,
    }
    impl EcsigP256Signature {
        pub fn new(r_sig: OctetString, s_sig: OctetString) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an estimate of the geodetic altitude above"]
    #[doc = " * or below the WGS84 ellipsoid. The 16-bit value is interpreted as an"]
    #[doc = " * integer number of decimeters representing the height above a minimum"]
    #[doc = " * height of -409.5 m, with the maximum height being 6143.9 m."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Elevation(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure contains an encryption key, which may be a public or"]
    #[doc = " * a symmetric key."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a "]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. The canonicalization applies to"]
    #[doc = " * the PublicEncryptionKey. See the definitions of HeaderInfo and "]
    #[doc = " * ToBeSignedCertificate for a specification of the canonicalization "]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EncryptionKey {
        public(PublicEncryptionKey),
        symmetric(SymmetricEncryptionKey),
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used as an identifier for instances of ExtContent "]
    #[doc = " * within an EXT-TYPE. "]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct ExtId(pub u8);
    #[doc = "***************************************************************************"]
    #[doc = "                           Location Structures                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure represents a geographic region of a specified form."]
    #[doc = " * A certificate is not valid if any part of the region indicated in its"]
    #[doc = " * scope field lies outside the region indicated in the scope of its issuer."]
    #[doc = " *"]
    #[doc = " * @param circularRegion: contains a single instance of the CircularRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param rectangularRegion: is an array of RectangularRegion structures"]
    #[doc = " * containing at least one entry. This field is interpreted as a series of"]
    #[doc = " * rectangles, which may overlap or be disjoint. The permitted region is any"]
    #[doc = " * point within any of the rectangles."]
    #[doc = " *"]
    #[doc = " * @param polygonalRegion: contains a single instance of the PolygonalRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param identifiedRegion: is an array of IdentifiedRegion structures"]
    #[doc = " * containing at least one entry. The permitted region is any point within"]
    #[doc = " * any of the identified regions."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is invalid in "]
    #[doc = " * the sense of 4.2.2.3.2, that is, it is invalid in the sense that its "]
    #[doc = " * validity cannot be established."]
    #[doc = " *   - If selected, rectangularRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * RectangularRegion in rectangularRegions when verifying a signed SPDU shall"]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that "]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established. "]
    #[doc = " * A conformant implementation shall support rectangularRegions fields "]
    #[doc = " * containing at least eight entries."]
    #[doc = " *   - If selected, identifiedRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * IdentifiedRegion in identifiedRegion shall reject the signed SPDU as"]
    #[doc = " * invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense "]
    #[doc = " * that its validity cannot be established. A conformant implementation shall "]
    #[doc = " * support identifiedRegion fields containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum GeographicRegion {
        circularRegion(CircularRegion),
        rectangularRegion(SequenceOfRectangularRegion),
        polygonalRegion(PolygonalRegion),
        identifiedRegion(SequenceOfIdentifiedRegion),
    }
    #[doc = "*"]
    #[doc = " * @brief This is the group linkage value. See 5.1.3 and 7.3 for details of"]
    #[doc = " * use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct GroupLinkageValue {
        #[rasn(size("4"), identifier = "jValue")]
        pub j_value: OctetString,
        #[rasn(size("9"))]
        pub value: OctetString,
    }
    impl GroupLinkageValue {
        pub fn new(j_value: OctetString, value: OctetString) -> Self {
            Self { j_value, value }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure identifies a hash algorithm. The value sha256, "]
    #[doc = " * indicates SHA-256. The value sha384 indicates SHA-384. The value sm3 "]
    #[doc = " * indicates SM3. See 5.3.3 for more details."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: This is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not recognize the enumerated"]
    #[doc = " * value of this type in a signed SPDU when verifying a signed SPDU shall "]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that "]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum HashAlgorithm {
        sha256 = 0,
        #[rasn(extension_addition)]
        sha384 = 1,
        #[rasn(extension_addition)]
        sm3 = 2,
    }
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId10 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order ten bytes of"]
    #[doc = " * the hash output. The low-order ten bytes are the last ten bytes of the "]
    #[doc = " * hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See "]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId10 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId10 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId10 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId10 = 934ca495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId10(pub FixedOctetString<10usize>);
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId3 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order three bytes of"]
    #[doc = " * the hash output. The low-order three bytes are the last three bytes of the"]
    #[doc = " * 32-byte hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See "]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId3 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId3 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId3 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId3 = 52b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId3(pub FixedOctetString<3usize>);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the truncated hash of another data"]
    #[doc = " * structure. The HashedId32 for a given data structure is calculated by "]
    #[doc = " * calculating the hash of the encoded data structure and taking the "]
    #[doc = " * low-order 32 bytes of the hash output. The low-order 32 bytes are the last"]
    #[doc = " * 32 bytes of the hash when represented in network byte order. If the data "]
    #[doc = " * structure is subject to canonicalization it is canonicalized before "]
    #[doc = " * hashing. See Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId32 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId32 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId32 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId32 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"]
    #[doc = " * 55."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId32(pub FixedOctetString<32usize>);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the truncated hash of another data "]
    #[doc = " * structure. The HashedId48 for a given data structure is calculated by"]
    #[doc = " * calculating the hash of the encoded data structure and taking the "]
    #[doc = " * low-order 48 bytes of the hash output. The low-order 48 bytes are the last"]
    #[doc = " * 48 bytes of the hash when represented in network byte order. If the data"]
    #[doc = " * structure is subject to canonicalization it is canonicalized before"]
    #[doc = " * hashing. See Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId48 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId48 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-384 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-384(\"\") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6"]
    #[doc = " * e1da274edebfe76f65fbd51ad2f14898b95b"]
    #[doc = " *"]
    #[doc = " * The HashedId48 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId48 = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e"]
    #[doc = " * 1da274edebfe76f65fbd51ad2f14898b95b."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId48(pub FixedOctetString<48usize>);
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId8 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order eight bytes of"]
    #[doc = " * the hash output. The low-order eight bytes are the last eight bytes of the"]
    #[doc = " * hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See "]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId8 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId8 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId8 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId8 = a495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId8(pub FixedOctetString<8usize>);
    #[doc = "*"]
    #[doc = " * @brief This is a UTF-8 string as defined in IETF RFC 3629. The contents"]
    #[doc = " * are determined by policy."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("0..=255"))]
    pub struct Hostname(pub Utf8String);
    #[doc = "***************************************************************************"]
    #[doc = "                             Pseudonym Linkage                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct IValue(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure indicates the region of validity of a certificate "]
    #[doc = " * using region identifiers. "]
    #[doc = " * A conformant implementation that supports this type shall support at least "]
    #[doc = " * one of the possible CHOICE values. The Protocol Implementation Conformance "]
    #[doc = " * Statement (PICS) provided in Annex A allows an implementation to state "]
    #[doc = " * which CountryOnly values it recognizes."]
    #[doc = " *"]
    #[doc = " * @param countryOnly: indicates that only a country (or a geographic entity "]
    #[doc = " * included in a country list) is given."]
    #[doc = " *"]
    #[doc = " * @param countryAndRegions: indicates that one or more top-level regions "]
    #[doc = " * within a country (as defined by the region listing associated with that "]
    #[doc = " * country) is given."]
    #[doc = " *"]
    #[doc = " * @param countryAndSubregions: indicates that one or more regions smaller "]
    #[doc = " * than the top-level regions within a country (as defined by the region "]
    #[doc = " * listing associated with that country) is given."]
    #[doc = " *"]
    #[doc = " * Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE when verifying a signed SPDU shall indicate"]
    #[doc = " * that the signed SPDU is invalid in the sense of 4.2.2.3.2, that is, it is "]
    #[doc = " * invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IdentifiedRegion {
        countryOnly(UnCountryId),
        countryAndRegions(CountryAndRegions),
        countryAndSubregions(CountryAndSubregions),
    }
    #[doc = "*"]
    #[doc = " * @brief The known latitudes are from -900,000,000 to +900,000,000 in 0.1"]
    #[doc = " * microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-900000000..=900000000"))]
    pub struct KnownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The known longitudes are from -1,799,999,999 to +1,800,000,000 in"]
    #[doc = " * 0.1 microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-1799999999..=1800000000"))]
    pub struct KnownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a LA Identifier for use in the algorithms"]
    #[doc = " * specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LaId(pub FixedOctetString<2usize>);
    #[doc = "*"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the latitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " * The integer in the latitude field is no more than 900 000 000 and no less "]
    #[doc = " * than ?900 000 000, except that the value 900 000 001 is used to indicate "]
    #[doc = " * the latitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Latitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a linkage seed value for use in the"]
    #[doc = " * algorithms specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LinkageSeed(pub FixedOctetString<16usize>);
    #[doc = "*"]
    #[doc = " * @brief This is the individual linkage value. See 5.1.3 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LinkageValue(pub FixedOctetString<9usize>);
    #[doc = "*"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the longitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " * The integer in the longitude field is no more than 1 800 000 000 and no "]
    #[doc = " * less than ?1 799 999 999, except that the value 1 800 000 001 is used to "]
    #[doc = " * indicate that the longitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Longitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The integer in the latitude field is no more than 900,000,000 and"]
    #[doc = " * no less than -900,000,000, except that the value 900,000,001 is used to"]
    #[doc = " * indicate the latitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-900000000..=900000001"))]
    pub struct NinetyDegreeInt(pub i32);
    #[doc = "*"]
    #[doc = " * @brief The integer in the longitude field is no more than 1,800,000,000"]
    #[doc = " * and no less than -1,799,999,999, except that the value 1,800,000,001 is"]
    #[doc = " * used to indicate that the longitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-1799999999..=1800000001"))]
    pub struct OneEightyDegreeInt(pub i32);
    #[doc = "***************************************************************************"]
    #[doc = "                            OCTET STRING Types                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This is a synonym for ASN.1 OCTET STRING, and is used in the"]
    #[doc = " * definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Opaque(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a region using a series of distinct"]
    #[doc = " * geographic points, defined on the surface of the reference ellipsoid. The"]
    #[doc = " * region is specified by connecting the points in the order they appear,"]
    #[doc = " * with each pair of points connected by the geodesic on the reference"]
    #[doc = " * ellipsoid. The polygon is completed by connecting the final point to the"]
    #[doc = " * first point. The allowed region is the interior of the polygon and its"]
    #[doc = " * boundary."]
    #[doc = " *"]
    #[doc = " * A point which contains an elevation component is considered to be"]
    #[doc = " * within the polygonal region if its horizontal projection onto the"]
    #[doc = " * reference ellipsoid lies within the region."]
    #[doc = " *"]
    #[doc = " * A valid PolygonalRegion contains at least three points. In a valid"]
    #[doc = " * PolygonalRegion, the implied lines that make up the sides of the polygon"]
    #[doc = " * do not intersect."]
    #[doc = " *"]
    #[doc = " * @note This type does not support enclaves / exclaves. This might be "]
    #[doc = " * addressed in a future version of this standard."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * support the number of TwoDLocation in the PolygonalRegion when verifying a"]
    #[doc = " * signed SPDU shall indicate that the signed SPDU is invalid. A compliant"]
    #[doc = " * implementation shall support PolygonalRegions containing at least eight"]
    #[doc = " * TwoDLocation entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("3.."))]
    pub struct PolygonalRegion(pub SequenceOf<TwoDLocation>);
    #[doc = "*"]
    #[doc = " * @brief This type represents the PSID defined in IEEE Std 1609.12."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0.."))]
    pub struct Psid(pub Integer);
    #[doc = "***************************************************************************"]
    #[doc = "                              PSID / ITS-AID                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure represents the permissions that the certificate "]
    #[doc = " * holder has with respect to activities for a single application area, "]
    #[doc = " * identified by a Psid. "]
    #[doc = " *"]
    #[doc = " * @note The determination as to whether the activities are consistent with "]
    #[doc = " * the permissions indicated by the PSID and ServiceSpecificPermissions is "]
    #[doc = " * made by the SDEE and not by the SDS; the SDS provides the PSID and SSP "]
    #[doc = " * information to the SDEE to enable the SDEE to make that determination. "]
    #[doc = " * See 5.2.4.3.3 for more information."]
    #[doc = " *"]
    #[doc = " * @note The SDEE specification is expected to specify what application "]
    #[doc = " * activities are permitted by particular ServiceSpecificPermissions values."]
    #[doc = " * The SDEE specification is also expected EITHER to specify application "]
    #[doc = " * activities that are permitted if the ServiceSpecificPermissions is "]
    #[doc = " * omitted, OR to state that the ServiceSpecificPermissions need to always be "]
    #[doc = " * present."]
    #[doc = " *"]
    #[doc = " * @note Consistency with signed SPDU: As noted in 5.1.1,"]
    #[doc = " * consistency between the SSP and the signed SPDU is defined by rules"]
    #[doc = " * specific to the given PSID and is outside the scope of this standard."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is omitted, A is consistent"]
    #[doc = " * with the issuing certificate if the issuing certificate contains a"]
    #[doc = " * PsidSspRange P for which the following holds:"]
    #[doc = " *   - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *     - The sspRange field in P indicates all."]
    #[doc = " *     - The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * opaque is an OCTET STRING of length 0."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other forms of the ssp field, see the"]
    #[doc = " * following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidSsp {
        pub psid: Psid,
        pub ssp: Option<ServiceSpecificPermissions>,
    }
    impl PsidSsp {
        pub fn new(psid: Psid, ssp: Option<ServiceSpecificPermissions>) -> Self {
            Self { psid, ssp }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents the certificate issuing or requesting"]
    #[doc = " * permissions of the certificate holder with respect to one particular set"]
    #[doc = " * of application permissions."]
    #[doc = " *"]
    #[doc = " * @param psid: identifies the application area."]
    #[doc = " *"]
    #[doc = " * @param sspRange: identifies the SSPs associated with that PSID for which"]
    #[doc = " * the holder may issue or request certificates. If sspRange is omitted, the"]
    #[doc = " * holder may issue or request certificates for any SSP for that PSID."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidSspRange {
        pub psid: Psid,
        #[rasn(identifier = "sspRange")]
        pub ssp_range: Option<SspRange>,
    }
    impl PsidSspRange {
        pub fn new(psid: Psid, ssp_range: Option<SspRange>) -> Self {
            Self { psid, ssp_range }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a public encryption key and the associated"]
    #[doc = " * symmetric algorithm which is used for bulk data encryption when encrypting"]
    #[doc = " * for that public key."]
    #[doc = " * "]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a "]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. The canonicalization applies to "]
    #[doc = " * the BasePublicEncryptionKey. See the definitions of HeaderInfo and "]
    #[doc = " * ToBeSignedCertificate for a specification of the canonicalization "]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PublicEncryptionKey {
        #[rasn(identifier = "supportedSymmAlg")]
        pub supported_symm_alg: SymmAlgorithm,
        #[rasn(identifier = "publicKey")]
        pub public_key: BasePublicEncryptionKey,
    }
    impl PublicEncryptionKey {
        pub fn new(supported_symm_alg: SymmAlgorithm, public_key: BasePublicEncryptionKey) -> Self {
            Self {
                supported_symm_alg,
                public_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents a public key and states with what "]
    #[doc = " * algorithm the public key is to be used. Cryptographic mechanisms are "]
    #[doc = " * defined in 5.3."]
    #[doc = " * An EccP256CurvePoint or EccP384CurvePoint within a PublicVerificationKey "]
    #[doc = " * structure is invalid if it indicates the choice x-only. "]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical "]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not "]
    #[doc = " * recognize the indicated CHOICE when verifying a signed SPDU shall indicate "]
    #[doc = " * that the signed SPDU is invalid indicate that the signed SPDU is invalid "]
    #[doc = " * in the sense of 4.2.2.3.2, that is, it is invalid in the sense that its "]
    #[doc = " * validity cannot be established. "]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization "]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization "]
    #[doc = " * applies to the EccP256CurvePoint and the Ecc384CurvePoint. Both forms of "]
    #[doc = " * point are encoded in compressed form, i.e., such that the choice indicated "]
    #[doc = " * within the Ecc*CurvePoint is compressed-y-0 or compressed-y-1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum PublicVerificationKey {
        ecdsaNistP256(EccP256CurvePoint),
        ecdsaBrainpoolP256r1(EccP256CurvePoint),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1(EccP384CurvePoint),
        #[rasn(extension_addition)]
        ecdsaNistP384(EccP384CurvePoint),
        #[rasn(extension_addition)]
        ecsigSm2(EccP256CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a �rectangle� on the surface of the WGS84 ellipsoid where the "]
    #[doc = " * sides are given by lines of constant latitude or longitude. "]
    #[doc = " * A point which contains an elevation component is considered to be within the rectangular region "]
    #[doc = " * if its horizontal projection onto the reference ellipsoid lies within the region. "]
    #[doc = " * A RectangularRegion is invalid if the northWest value is south of the southEast value, or if the "]
    #[doc = " * latitude values in the two points are equal, or if the longitude values in the two points are "]
    #[doc = " * equal; otherwise it is valid. A certificate that contains an invalid RectangularRegion is invalid."]
    #[doc = " *"]
    #[doc = " * @param northWest: is the north-west corner of the rectangle."]
    #[doc = " *"]
    #[doc = " * @param southEast is the south-east corner of the rectangle."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct RectangularRegion {
        #[rasn(identifier = "northWest")]
        pub north_west: TwoDLocation,
        #[rasn(identifier = "southEast")]
        pub south_east: TwoDLocation,
    }
    impl RectangularRegion {
        pub fn new(north_west: TwoDLocation, south_east: TwoDLocation) -> Self {
            Self {
                north_west,
                south_east,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief The meanings of the fields in this structure are to be interpreted"]
    #[doc = " * in the context of a country within which the region is located, referred "]
    #[doc = " * to as the \"enclosing country\". If this structure is used in a "]
    #[doc = " * CountryAndSubregions structure, the enclosing country is the one indicated "]
    #[doc = " * by the country field in the CountryAndSubregions structure. If other uses "]
    #[doc = " * are defined for this structure in the future, it is anticipated (in the"]
    #[doc = " * sense of 4.4) that that definition will include a specification of how the"]
    #[doc = " * enclosing country can be determined."]
    #[doc = " * If the enclosing country is the United States of America:"]
    #[doc = " * - The region field identifies the state or statistically equivalent "]
    #[doc = " * entity using the integer version of the 2010 FIPS codes as provided by the"]
    #[doc = " * U.S. Census Bureau (see normative references in Clause 0).   "]
    #[doc = " * - The values in the subregions field identify the county or county "]
    #[doc = " * equivalent entity using the integer version of the 2010 FIPS codes as "]
    #[doc = " * provided by the U.S. Census Bureau."]
    #[doc = " * If the enclosing country is a different country from the USA, the meaning "]
    #[doc = " * of regionAndSubregions is not defined in this version of this standard."]
    #[doc = " * A conformant implementation that implements this type shall recognize (in "]
    #[doc = " * the sense of \"be able to determine whether a two-dimensional location lies "]
    #[doc = " * inside or outside the borders identified by\"), for at least one enclosing"]
    #[doc = " * country, at least one value for a region within that country and at least "]
    #[doc = " * one subregion for the indicated region. In this version of this standard, "]
    #[doc = " * the only means to satisfy this is for a conformant implementation to "]
    #[doc = " * recognize, for the USA, at least one of the FIPS state codes for US "]
    #[doc = " * states, and at least one of the county codes in at least one of the "]
    #[doc = " * recognized states. The Protocol Implementation Conformance Statement "]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which "]
    #[doc = " * UnCountryId values it recognizes and which region values are recognized "]
    #[doc = " * within that country."]
    #[doc = " * If a verifying implementation is required to check that an relevant "]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate "]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted "]
    #[doc = " * to indicate that the signed SPDU is valid even if some values within "]
    #[doc = " * subregions are unrecognized in the sense defined above, so long as the "]
    #[doc = " * recognized instances of this type completely contain the relevant "]
    #[doc = " * geographic information. Informally, if the recognized values in the "]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it "]
    #[doc = " * can make that determination even if there are also unrecognized values "]
    #[doc = " * in the certificate. This field is therefore not a \"critical "]
    #[doc = " * information field\" as defined in 5.2.6, because unrecognized values are "]
    #[doc = " * permitted so long as the validity of the SPDU can be established with the "]
    #[doc = " * recognized values. However, as discussed in 5.2.6, the presence of an "]
    #[doc = " * unrecognized value in a certificate can make it impossible to determine "]
    #[doc = " * whether the certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this structure:"]
    #[doc = " *"]
    #[doc = " * @param region: identifies a region within a country."]
    #[doc = " *"]
    #[doc = " * @param subregions: identifies one or more subregions within region. A "]
    #[doc = " * conformant implementation that supports RegionAndSubregions shall support "]
    #[doc = " * a subregions field containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct RegionAndSubregions {
        pub region: Uint8,
        pub subregions: SequenceOfUint16,
    }
    impl RegionAndSubregions {
        pub fn new(region: Uint8, subregions: SequenceOfUint16) -> Self {
            Self { region, subregions }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfHashedId3(pub SequenceOf<HashedId3>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfIdentifiedRegion(pub SequenceOf<IdentifiedRegion>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfLinkageSeed(pub SequenceOf<LinkageSeed>);
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "OCTET_STRING")]
    pub struct AnonymousSequenceOfOctetString(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfOctetString(pub SequenceOf<AnonymousSequenceOfOctetString>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsid(pub SequenceOf<Psid>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSsp(pub SequenceOf<PsidSsp>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSspRange(pub SequenceOf<PsidSspRange>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRectangularRegion(pub SequenceOf<RectangularRegion>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRegionAndSubregions(pub SequenceOf<RegionAndSubregions>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfUint16(pub SequenceOf<Uint16>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfUint8(pub SequenceOf<Uint8>);
    #[doc = "*"]
    #[doc = " * @brief This structure represents the Service Specific Permissions (SSP)"]
    #[doc = " * relevant to a given entry in a PsidSsp. The meaning of the SSP is specific"]
    #[doc = " * to the associated Psid. SSPs may be PSID-specific octet strings or"]
    #[doc = " * bitmap-based. See Annex C for further discussion of how application"]
    #[doc = " * specifiers may choose which SSP form to use."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is opaque, A is consistent"]
    #[doc = " * with the issuing certificate if the issuing certificate contains one of"]
    #[doc = " * the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - The sspRange field in P indicates all."]
    #[doc = " *       - The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * the opaque field in P is an OCTET STRING identical to the opaque field in"]
    #[doc = " * A."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of ServiceSpecificPermissions,"]
    #[doc = " * see the following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum ServiceSpecificPermissions {
        opaque(OctetString),
        #[rasn(extension_addition)]
        bitmapSsp(BitmapSsp),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                            Crypto Structures                              "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure represents a signature for a supported public key"]
    #[doc = " * algorithm. It may be contained within SignedData or Certificate."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical "]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not "]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be "]
    #[doc = " * established."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to instances of this data structure of form EcdsaP256Signature"]
    #[doc = " * and EcdsaP384Signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum Signature {
        ecdsaNistP256Signature(EcdsaP256Signature),
        ecdsaBrainpoolP256r1Signature(EcdsaP256Signature),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1Signature(EcdsaP384Signature),
        #[rasn(extension_addition)]
        ecdsaNistP384Signature(EcdsaP384Signature),
        #[rasn(extension_addition)]
        sm2Signature(EcsigP256Signature),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure identifies the SSPs associated with a PSID for"]
    #[doc = " * which the holder may issue or request certificates."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has a"]
    #[doc = " * PsidSspRange A for which the ssp field is opaque, A is consistent with"]
    #[doc = " * the issuing certificate if the issuing certificate contains one of the"]
    #[doc = " * following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - The sspRange field in P indicates all."]
    #[doc = " *       - The sspRange field in P indicates opaque, and the sspRange field in"]
    #[doc = " * A indicates opaque, and every OCTET STRING within the opaque in A is a"]
    #[doc = " * duplicate of an OCTET STRING within the opaque in P."]
    #[doc = " *"]
    #[doc = " * If a certificate has a PsidSspRange A for which the ssp field is all,"]
    #[doc = " * A is consistent with the issuing certificate if the issuing certificate"]
    #[doc = " * contains a PsidSspRange P for which the following holds:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the psid field in P is equal to"]
    #[doc = " * the psid field in A and the sspRange field in P indicates all."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of SspRange, see the following"]
    #[doc = " * subclauses."]
    #[doc = " *"]
    #[doc = " * @note The choice \"all\" may also be indicated by omitting the"]
    #[doc = " * SspRange in the enclosing PsidSspRange structure. Omitting the SspRange is"]
    #[doc = " * preferred to explicitly indicating \"all\"."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SspRange {
        opaque(SequenceOfOctetString),
        all(()),
        #[rasn(extension_addition)]
        bitmapSspRange(BitmapSspRange),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                          Certificate Components                           "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This field contains the certificate holder's assurance level, which"]
    #[doc = " * indicates the security of both the platform and storage of secret keys as"]
    #[doc = " * well as the confidence in this assessment."]
    #[doc = " *"]
    #[doc = " * This field is encoded as defined in Table 1, where \"A\" denotes bit"]
    #[doc = " * fields specifying an assurance level, \"R\" reserved bit fields, and \"C\" bit"]
    #[doc = " * fields specifying the confidence."]
    #[doc = " *"]
    #[doc = " * Table 1: Bitwise encoding of subject assurance"]
    #[doc = " *"]
    #[doc = " * | Bit number     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |"]
    #[doc = " * | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    #[doc = " * | Interpretation |  A  |  A  |  A  |  R  |  R  |  R  |  C  |  C  |"]
    #[doc = " *"]
    #[doc = " * In Table 1, bit number 0 denotes the least significant bit. Bit 7"]
    #[doc = " * to bit 5 denote the device's assurance levels, bit 4 to bit 2 are reserved"]
    #[doc = " * for future use, and bit 1 and bit 0 denote the confidence."]
    #[doc = " *"]
    #[doc = " * The specification of these assurance levels as well as the"]
    #[doc = " * encoding of the confidence levels is outside the scope of this"]
    #[doc = " * standard. It can be assumed that a higher assurance value indicates that"]
    #[doc = " * the holder is more trusted than the holder of a certificate with lower"]
    #[doc = " * assurance value and the same confidence value."]
    #[doc = " *"]
    #[doc = " * @note This field was originally specified in ETSI TS 103 097, and"]
    #[doc = " * future uses of this field are anticipated to be consistent with future"]
    #[doc = " * versions of that standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SubjectAssurance(pub FixedOctetString<1usize>);
    #[doc = "*"]
    #[doc = " * @brief This enumerated value indicates supported symmetric algorithms. The"]
    #[doc = " * algorithm identifier identifies both the algorithm itself and a specific"]
    #[doc = " * mode of operation. The symmetric algorithms supported in this version of"]
    #[doc = " * this standard are AES-128 and SM4. The only mode of operation supported is"]
    #[doc = " * Counter Mode Encryption With Cipher Block Chaining Message Authentication"]
    #[doc = " * Code (CCM). Full details are given in 5.3.8."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum SymmAlgorithm {
        aes128Ccm = 0,
        #[rasn(extension_addition)]
        sm4Ccm = 1,
    }
    #[doc = "*"]
    #[doc = " * @brief This structure provides the key bytes for use with an identified "]
    #[doc = " * symmetric algorithm. The supported symmetric algorithms are AES-128 and "]
    #[doc = " * SM4 in CCM mode as specified in 5.3.8."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricEncryptionKey {
        #[rasn(size("16"))]
        aes128Ccm(OctetString),
        #[rasn(extension_addition, size("16"))]
        sm4Ccm(OctetString),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an estimate of 3D location. "]
    #[doc = " *"]
    #[doc = " * @note The units used in this data structure are consistent with the "]
    #[doc = " * location data structures used in \tSAE J2735 [B26], though the encoding is"]
    #[doc = " * incompatible."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ThreeDLocation {
        pub latitude: Latitude,
        pub longitude: Longitude,
        pub elevation: Elevation,
    }
    impl ThreeDLocation {
        pub fn new(latitude: Latitude, longitude: Longitude, elevation: Elevation) -> Self {
            Self {
                latitude,
                longitude,
                elevation,
            }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                             Time Structures                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This type gives the number of (TAI) seconds since 00:00:00 UTC, 1"]
    #[doc = " * January 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Time32(pub Uint32);
    #[doc = "*"]
    #[doc = " * @brief This data structure is a 64-bit integer giving an estimate of the "]
    #[doc = " * number of (TAI) microseconds since 00:00:00 UTC, 1 January 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Time64(pub Uint64);
    #[doc = "*"]
    #[doc = " * @brief This structure is used to define validity regions for use in"]
    #[doc = " * certificates. The latitude and longitude fields contain the latitude and"]
    #[doc = " * longitude as defined above."]
    #[doc = " *"]
    #[doc = " * @note This data structure is consistent with the location encoding"]
    #[doc = " * used in SAE J2735, except that values 900 000 001 for latitude (used to"]
    #[doc = " * indicate that the latitude was not available) and 1 800 000 001 for"]
    #[doc = " * longitude (used to indicate that the longitude was not available) are not"]
    #[doc = " * valid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct TwoDLocation {
        pub latitude: Latitude,
        pub longitude: Longitude,
    }
    impl TwoDLocation {
        pub fn new(latitude: Latitude, longitude: Longitude) -> Self {
            Self {
                latitude,
                longitude,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 65,535, i.e., (hex)ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=65535"))]
    pub struct Uint16(pub u16);
    #[doc = "***************************************************************************"]
    #[doc = "                               Integer Types                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 7, i.e., (hex)07."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=7"))]
    pub struct Uint3(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 4,294,967,295, i.e.,"]
    #[doc = " * (hex)ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=4294967295"))]
    pub struct Uint32(pub u32);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 18,446,744,073,709,551,615, i.e.,"]
    #[doc = " * (hex)ff ff ff ff ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=18446744073709551615"))]
    pub struct Uint64(pub u64);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 255, i.e., (hex)ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct Uint8(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This type contains the integer representation of the country or "]
    #[doc = " * area identifier as defined by the United Nations Statistics Division in "]
    #[doc = " * October 2013 (see normative references in Clause 0)."]
    #[doc = " * A conformant implementation that implements IdentifiedRegion shall "]
    #[doc = " * recognize (in the sense of �be able to determine whether a two dimensional "]
    #[doc = " * location lies inside or outside the borders identified by�) at least one "]
    #[doc = " * value of UnCountryId. The Protocol Implementation Conformance Statement "]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which "]
    #[doc = " * UnCountryId values it recognizes."]
    #[doc = " * Since 2013 and before the publication of this version of this standard, "]
    #[doc = " * three changes have been made to the country code list, to define the "]
    #[doc = " * region \"sub-Saharan Africa\" and remove the \"developed regions\", and "]
    #[doc = " * \"developing regions\". A conformant implementation may recognize these "]
    #[doc = " * region identifiers in the sense defined in the previous paragraph."]
    #[doc = " * If a verifying implementation is required to check that relevant "]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate "]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted "]
    #[doc = " * to indicate that the signed SPDU is valid even if some instances of this "]
    #[doc = " * type are unrecognized in the sense defined above, so long as the "]
    #[doc = " * recognized instances of this type completely contain the relevant "]
    #[doc = " * geographic information. Informally, if the recognized values in the "]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it "]
    #[doc = " * can make that determination even if there are also unrecognized values in "]
    #[doc = " * the certificate. This field is therefore not a \"critical information "]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so "]
    #[doc = " * long as the validity of the SPDU can be established with the recognized "]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized "]
    #[doc = " * value in a certificate can make it impossible to determine whether the "]
    #[doc = " * certificate and the SPDU are valid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct UnCountryId(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief The value 900,000,001 indicates that the latitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("900000001"))]
    pub struct UnknownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The value 1,800,000,001 indicates that the longitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("1800000001"))]
    pub struct UnknownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This type gives the validity period of a certificate. The start of "]
    #[doc = " * the validity period is given by start and the end is given by "]
    #[doc = " * start + duration."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ValidityPeriod {
        pub start: Time32,
        pub duration: Duration,
    }
    impl ValidityPeriod {
        pub fn new(start: Time32, duration: Duration) -> Self {
            Self { start, duration }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_crl {
    extern crate alloc;
    use super::ieee1609_dot2::Ieee1609Dot2Data;
    use super::ieee1609_dot2_base_types::{Opaque, Psid};
    use super::ieee1609_dot2_crl_base_types::CrlContents;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = "*"]
    #[doc = " * @brief This is the PSID for the CRL application."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("256"))]
    pub struct CrlPsid(pub Psid);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to contain a signed CRL. A valid "]
    #[doc = " * signed CRL meets the validity criteria of 7.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SecuredCrl(pub Ieee1609Dot2Data);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_crl_base_types {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::{
        CrlSeries, Duration, GeographicRegion, HashedId10, HashedId8, IValue, LaId, LinkageSeed,
        Opaque, Psid, SequenceOfLinkageSeed, Signature, Time32, Uint16, Uint3, Uint32, Uint8,
        ValidityPeriod,
    };
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = "*"]
    #[doc = " * @brief The fields in this structure have the following meaning:"]
    #[doc = " *"]
    #[doc = " * @param version: is the version number of the CRL. For this version of this"]
    #[doc = " * standard it is 1."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: represents the CRL series to which this CRL belongs. This"]
    #[doc = " * is used to determine whether the revocation information in a CRL is relevant"]
    #[doc = " * to a particular certificate as specified in 5.1.3.2."]
    #[doc = " *"]
    #[doc = " * @param crlCraca: contains the low-order eight octets of the hash of the"]
    #[doc = " * certificate of the Certificate Revocation Authorization CA (CRACA) that"]
    #[doc = " * ultimately authorized the issuance of this CRL. This is used to determine"]
    #[doc = " * whether the revocation information in a CRL is relevant to a particular"]
    #[doc = " * certificate as specified in 5.1.3.2. In a valid signed CRL as specified in"]
    #[doc = " * 7.4 the crlCraca is consistent with the associatedCraca field in the"]
    #[doc = " * Service Specific Permissions as defined in 7.4.3.3. The HashedId8 is"]
    #[doc = " * calculated with the whole-certificate hash algorithm, determined as"]
    #[doc = " * described in 6.4.3, applied to the COER-encoded certificate, canonicalized "]
    #[doc = " * as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param issueDate: specifies the time when the CRL was issued."]
    #[doc = " *"]
    #[doc = " * @param nextCrl: contains the time when the next CRL with the same crlSeries"]
    #[doc = " * and cracaId is expected to be issued. The CRL is invalid unless nextCrl is"]
    #[doc = " * strictly after issueDate. This field is used to set the expected update time"]
    #[doc = " * for revocation information associated with the (crlCraca, crlSeries) pair as"]
    #[doc = " * specified in 5.1.3.6."]
    #[doc = " *"]
    #[doc = " * @param priorityInfo: contains information that assists devices with limited"]
    #[doc = " * storage space in determining which revocation information to retain and"]
    #[doc = " * which to discard."]
    #[doc = " *"]
    #[doc = " * @param\ttypeSpecific: contains the CRL body."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CrlContents {
        #[rasn(value("1"))]
        pub version: Uint8,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
        #[rasn(identifier = "crlCraca")]
        pub crl_craca: HashedId8,
        #[rasn(identifier = "issueDate")]
        pub issue_date: Time32,
        #[rasn(identifier = "nextCrl")]
        pub next_crl: Time32,
        #[rasn(identifier = "priorityInfo")]
        pub priority_info: CrlPriorityInfo,
        #[rasn(identifier = "typeSpecific")]
        pub type_specific: TypeSpecificCrlContents,
    }
    impl CrlContents {
        pub fn new(
            version: Uint8,
            crl_series: CrlSeries,
            crl_craca: HashedId8,
            issue_date: Time32,
            next_crl: Time32,
            priority_info: CrlPriorityInfo,
            type_specific: TypeSpecificCrlContents,
        ) -> Self {
            Self {
                version,
                crl_series,
                crl_craca,
                issue_date,
                next_crl,
                priority_info,
                type_specific,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure contains information that assists devices with"]
    #[doc = " * limited storage space in determining which revocation information to retain"]
    #[doc = " * and which to discard."]
    #[doc = " *"]
    #[doc = " * @param priority: indicates the priority of the revocation information"]
    #[doc = " * relative to other CRLs issued for certificates with the same cracaId and"]
    #[doc = " * crlSeries values. A higher value for this field indicates higher importance"]
    #[doc = " * of this revocation information."]
    #[doc = " *"]
    #[doc = " * @note This mechanism is for future use; details are not specified in this"]
    #[doc = " * version of the standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CrlPriorityInfo {
        pub priority: Option<Uint8>,
    }
    impl CrlPriorityInfo {
        pub fn new(priority: Option<Uint8>) -> Self {
            Self { priority }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an identifier for the algorithms specified "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum ExpansionAlgorithmIdentifier {
        #[rasn(identifier = "sha256ForI-aesForJ")]
        sha256ForI_aesForJ = 0,
        #[rasn(identifier = "sm3ForI-sm4ForJ")]
        sm3ForI_sm4ForJ = 1,
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param iMax: indicates that for these certificates, revocation information "]
    #[doc = " * need no longer be calculated once iCert > iMax as the holders are known "]
    #[doc = " * to have no more valid certs for that (crlCraca, crlSeries) at that point."]
    #[doc = " *"]
    #[doc = " * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the "]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based "]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed1: is the value LinkageSeed1 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " *"]
    #[doc = " * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the "]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based "]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed2: is the value LinkageSeed2 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct GroupCrlEntry {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        #[rasn(identifier = "la1Id")]
        pub la1_id: LaId,
        #[rasn(identifier = "linkageSeed1")]
        pub linkage_seed1: LinkageSeed,
        #[rasn(identifier = "la2Id")]
        pub la2_id: LaId,
        #[rasn(identifier = "linkageSeed2")]
        pub linkage_seed2: LinkageSeed,
    }
    impl GroupCrlEntry {
        pub fn new(
            i_max: Uint16,
            la1_id: LaId,
            linkage_seed1: LinkageSeed,
            la2_id: LaId,
            linkage_seed2: LinkageSeed,
        ) -> Self {
            Self {
                i_max,
                la1_id,
                linkage_seed1,
                la2_id,
                linkage_seed2,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the linkage seed for group revocation with "]
    #[doc = " * a single seed. The seed is used as specified in the algorithms in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct GroupSingleSeedCrlEntry {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        #[rasn(identifier = "laId")]
        pub la_id: LaId,
        #[rasn(identifier = "linkageSeed")]
        pub linkage_seed: LinkageSeed,
    }
    impl GroupSingleSeedCrlEntry {
        pub fn new(i_max: Uint16, la_id: LaId, linkage_seed: LinkageSeed) -> Self {
            Self {
                i_max,
                la_id,
                linkage_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tid: is the HashedId10 identifying the revoked certificate. The "]
    #[doc = " * HashedId10 is calculated with the whole-certificate hash algorithm, "]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param expiry: is the value computed from the validity period's start and"]
    #[doc = " * duration values in that certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct HashBasedRevocationInfo {
        pub id: HashedId10,
        pub expiry: Time32,
    }
    impl HashBasedRevocationInfo {
        pub fn new(id: HashedId10, expiry: Time32) -> Self {
            Self { id, expiry }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param iMax indicates that for the entries in contents, revocation "]
    #[doc = " * information need no longer be calculated once iCert > iMax as the holder "]
    #[doc = " * is known to have no more valid certs at that point. iMax is not directly "]
    #[doc = " * used in the calculation of the linkage values, it is used to determine "]
    #[doc = " * when revocation information can safely be deleted."]
    #[doc = " *"]
    #[doc = " * @param contents contains individual linkage data for certificates that are "]
    #[doc = " * revoked using two seeds, per the algorithm given in per the mechanisms "]
    #[doc = " * given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and "]
    #[doc = " * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3."]
    #[doc = " *"]
    #[doc = " * @param singleSeed contains individual linkage data for certificates that "]
    #[doc = " * are revoked using a single seed, per the algorithm given in per the "]
    #[doc = " * mechanisms given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and "]
    #[doc = " * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IMaxGroup {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        pub contents: SequenceOfIndividualRevocation,
        #[rasn(extension_addition, identifier = "singleSeed")]
        pub single_seed: Option<SequenceOfLinkageSeed>,
    }
    impl IMaxGroup {
        pub fn new(
            i_max: Uint16,
            contents: SequenceOfIndividualRevocation,
            single_seed: Option<SequenceOfLinkageSeed>,
        ) -> Self {
            Self {
                i_max,
                contents,
                single_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains information about when future revocation"]
    #[doc = " * time periods start. Revocation time periods are discussed in 5.1.3.4."]
    #[doc = " * Linkage value based CRLs contain linkage seeds which can be used to"]
    #[doc = " * calculate the linkage values that will appear in certificates for"]
    #[doc = " * revocation time periods that are in the future relative to the issuance"]
    #[doc = " * time of the CRL; the IPeriodInfo structure allows the CRL signer to"]
    #[doc = " * communicate the start time for future time periods, so that a CRL recipient"]
    #[doc = " * can calculate the linkage values before the relevant time period starts."]
    #[doc = " * The CRL contains a SEQUENCE of IPeriodInfo to support the case where the"]
    #[doc = " * CRL issuer knows that the duration of the time periods is going to change"]
    #[doc = " * at some point in the future; the number of IPeriodInfo in the sequence"]
    #[doc = " * should be the minimum necessary to convey the information, e.g. if the"]
    #[doc = " * duration of the time periods is not going to change, the CRL should contain"]
    #[doc = " * a single IPeriodInfo."]
    #[doc = " * "]
    #[doc = " * @note The information about the duration of future time periods can be"]
    #[doc = " * assumed to be available to the CRL signer, because pseudonym certificates"]
    #[doc = " * that use linkage values are typically issued for future time periods rather"]
    #[doc = " * than only the current time period, and so the length of future time periods"]
    #[doc = " * had to be known to the CA at the time of certificate issuance and can be"]
    #[doc = " * provided to the CRL signer. This creates a requirement that if multiple CAs"]
    #[doc = " * issue certificates that use the same CRL Series and CRACA Id values, all of"]
    #[doc = " * those CAs will be expected to implement any time period length changes in"]
    #[doc = " * synch with each other so that all certificates on the same CRL will have"]
    #[doc = " * synchronized time period starts and ends. How these CAs are synchronized"]
    #[doc = " * with each other is out of scope for this document."]
    #[doc = " * "]
    #[doc = " * An IPeriodInfo appears in a CRL that has an iRev field. The CRL contains a"]
    #[doc = " * SEQUENCE of IPeriodInfo. Each IPeriodInfo makes use of the previous iRev"]
    #[doc = " * value, prevI. For the first IPeriodInfo in the SEQUENCE, prevI is the value"]
    #[doc = " * of iRev in the CRL. For each subsequent IPeriodInfo in the SEQUENCE, prevI"]
    #[doc = " * is the value of guaranteedToIValue in the previous IPeriodInfo. "]
    #[doc = " * "]
    #[doc = " * In this structure:"]
    #[doc = " *"]
    #[doc = " * @param startOfNextIPeriod is the start time of the i-period with i = prevI +"]
    #[doc = " * 1. This is the earliest time at which certificates with i-period equal to"]
    #[doc = " * prevI + 1 will be valid, i.e. if a certificate with the cracaId and"]
    #[doc = " * crlSeries corresponding to this CRL has"]
    #[doc = " * ToBeSignedCertificate.id.linkageData.iCert = prevI + 1, then"]
    #[doc = " * ToBeSignedCertificate.validityPeriod.start will be no earlier than this"]
    #[doc = " * startOfNextIPeriod value."]
    #[doc = " *"]
    #[doc = " * @param iPeriodLength is the length of all time periods from prevI + 1 to"]
    #[doc = " * guaranteedToIValue inclusive, i.e., each time period starts exactly"]
    #[doc = " * iPeriodLength after the previous time period started."]
    #[doc = " *"]
    #[doc = " * @param guaranteedToIValue is last i-period which is guaranteed to have the"]
    #[doc = " * indicated duration, i.e., all time periods from prevI + 1 to"]
    #[doc = " * guaranteedToIValue are guaranteed to have that duration and time period"]
    #[doc = " * guaranteedToIValue +1 is not guaranteed to have that duration."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct IPeriodInfo {
        #[rasn(identifier = "startOfNextIPeriod")]
        pub start_of_next_iperiod: Time32,
        #[rasn(identifier = "iPeriodLength")]
        pub i_period_length: Duration,
        #[rasn(identifier = "guaranteedToIValue")]
        pub guaranteed_to_ivalue: IValue,
    }
    impl IPeriodInfo {
        pub fn new(
            start_of_next_iperiod: Time32,
            i_period_length: Duration,
            guaranteed_to_ivalue: IValue,
        ) -> Self {
            Self {
                start_of_next_iperiod,
                i_period_length,
                guaranteed_to_ivalue,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param linkageSeed1 is the value LinkageSeed1 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed2 is the value LinkageSeed2 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IndividualRevocation {
        #[rasn(identifier = "linkageSeed1")]
        pub linkage_seed1: LinkageSeed,
        #[rasn(identifier = "linkageSeed2")]
        pub linkage_seed2: LinkageSeed,
    }
    impl IndividualRevocation {
        pub fn new(linkage_seed1: LinkageSeed, linkage_seed2: LinkageSeed) -> Self {
            Self {
                linkage_seed1,
                linkage_seed2,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tjMax: is the value jMax used in the algorithm given in 5.1.3.4. This"]
    #[doc = " * value applies to all linkage-based revocation information included within"]
    #[doc = " * contents."]
    #[doc = " *"]
    #[doc = " * @param contents: contains individual linkage data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct JMaxGroup {
        pub jmax: Uint8,
        pub contents: SequenceOfLAGroup,
    }
    impl JMaxGroup {
        pub fn new(jmax: Uint8, contents: SequenceOfLAGroup) -> Self {
            Self { jmax, contents }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the"]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based"]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the"]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based"]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param contents: contains individual linkage data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct LAGroup {
        #[rasn(identifier = "la1Id")]
        pub la1_id: LaId,
        #[rasn(identifier = "la2Id")]
        pub la2_id: LaId,
        pub contents: SequenceOfIMaxGroup,
    }
    impl LAGroup {
        pub fn new(la1_id: LaId, la2_id: LaId, contents: SequenceOfIMaxGroup) -> Self {
            Self {
                la1_id,
                la2_id,
                contents,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the identifier for the linkage value generation function. "]
    #[doc = " * See 5.1.3 for details of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate)]
    pub struct LvGenerationFunctionIdentifier(pub ());
    #[doc = "*"]
    #[doc = " * @brief This is the identifier for the seed evolution function. See 5.1.3 "]
    #[doc = " * for details of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate)]
    pub struct SeedEvolutionFunctionIdentifier(pub ());
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfGroupCrlEntry(pub SequenceOf<GroupCrlEntry>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfGroupSingleSeedCrlEntry(pub SequenceOf<GroupSingleSeedCrlEntry>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfHashBasedRevocationInfo(pub SequenceOf<HashBasedRevocationInfo>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfIMaxGroup(pub SequenceOf<IMaxGroup>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfIPeriodInfo(pub SequenceOf<IPeriodInfo>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfIndividualRevocation(pub SequenceOf<IndividualRevocation>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfJMaxGroup(pub SequenceOf<JMaxGroup>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfLAGroup(pub SequenceOf<LAGroup>);
    #[doc = "*"]
    #[doc = " * @brief This data structure represents information about a revoked"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSerial: is a counter that increments by 1 every time a new full"]
    #[doc = " * or delta CRL is issued for the indicated crlCraca and crlSeries values.  A"]
    #[doc = " * \"new full or delta CRL\" is a CRL with a new issueDate, whether or not the"]
    #[doc = " * contents of the CRL have changed."]
    #[doc = " *"]
    #[doc = " * @param entries: contains the individual revocation information items."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a hash-based CRL contains no individual revocation "]
    #[doc = " * information items, the recommended approach is for the SEQUENCE OF in the "]
    #[doc = " * SequenceOfHashBasedRevocationInfo in this field to indicate zero entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedHashIdCrl {
        #[rasn(identifier = "crlSerial")]
        pub crl_serial: Uint32,
        pub entries: SequenceOfHashBasedRevocationInfo,
    }
    impl ToBeSignedHashIdCrl {
        pub fn new(crl_serial: Uint32, entries: SequenceOfHashBasedRevocationInfo) -> Self {
            Self {
                crl_serial,
                entries,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tiRev: is the value iRev used in the algorithm given in 5.1.3.4. This"]
    #[doc = " * value applies to all linkage-based revocation information included within"]
    #[doc = " * either indvidual or groups."]
    #[doc = " *"]
    #[doc = " * @param\tindexWithinI: is a counter that is set to 0 for the first CRL issued"]
    #[doc = " * for the indicated combination of crlCraca, crlSeries, and iRev, and"]
    #[doc = " * increments by 1 every time a new full or delta CRL is issued for the"]
    #[doc = " * indicated crlCraca and crlSeries values without changing iRev."]
    #[doc = " *"]
    #[doc = " * @param individual: contains individual linkage data."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a linkage ID-based CRL contains no individual"]
    #[doc = " * linkage data, the recommended approach is for the SEQUENCE OF in the"]
    #[doc = " * SequenceOfJMaxGroup in this field to indicate zero entries."]
    #[doc = " *"]
    #[doc = " * @param groups: contains group linkage data."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a linkage ID-based CRL contains no group linkage"]
    #[doc = " * data, the recommended approach is for the SEQUENCE OF in the"]
    #[doc = " * SequenceOfGroupCrlEntry in this field to indicate zero entries."]
    #[doc = " *"]
    #[doc = " * @param groupsSingleSeed: contains group linkage data generated with a single "]
    #[doc = " * seed."]
    #[doc = " *"]
    #[doc = " * @param iPeriodInfo contains information about the duration of the revocation"]
    #[doc = " * time periods, to allow a receiver to determine at what point it will be"]
    #[doc = " * necessary to have calculated the linkage values associated with future time"]
    #[doc = " * periods."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkageValueCrl {
        #[rasn(identifier = "iRev")]
        pub i_rev: IValue,
        #[rasn(identifier = "indexWithinI")]
        pub index_within_i: Uint8,
        pub individual: Option<SequenceOfJMaxGroup>,
        pub groups: Option<SequenceOfGroupCrlEntry>,
        #[rasn(extension_addition, identifier = "groupsSingleSeed")]
        pub groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
        #[rasn(extension_addition, identifier = "iPeriodInfo")]
        pub i_period_info: Option<SequenceOfIPeriodInfo>,
    }
    impl ToBeSignedLinkageValueCrl {
        pub fn new(
            i_rev: IValue,
            index_within_i: Uint8,
            individual: Option<SequenceOfJMaxGroup>,
            groups: Option<SequenceOfGroupCrlEntry>,
            groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
            i_period_info: Option<SequenceOfIPeriodInfo>,
        ) -> Self {
            Self {
                i_rev,
                index_within_i,
                individual,
                groups,
                groups_single_seed,
                i_period_info,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " * "]
    #[doc = " * @param iRev is the value iRev used in the algorithm given in 5.1.3.4. This "]
    #[doc = " * value applies to all linkage-based revocation information included within "]
    #[doc = " * either indvidual or groups."]
    #[doc = " * "]
    #[doc = " * @param indexWithinI is a counter that is set to 0 for the first CRL issued "]
    #[doc = " * for the indicated combination of crlCraca, crlSeries, and iRev, and increments"]
    #[doc = " * by 1 every time a new full or delta CRL is issued for the indicated crlCraca "]
    #[doc = " * and crlSeries values without changing iRev."]
    #[doc = " * "]
    #[doc = " * @param seedEvolution contains an identifier for the seed evolution "]
    #[doc = " * function, used as specified in  5.1.3.4."]
    #[doc = " * "]
    #[doc = " * @param lvGeneration contains an identifier for the linkage value "]
    #[doc = " * generation function, used as specified in  5.1.3.4."]
    #[doc = " * "]
    #[doc = " * @param individual contains individual linkage data."]
    #[doc = " * "]
    #[doc = " * @param groups contains group linkage data for linkage value generation "]
    #[doc = " * with two seeds."]
    #[doc = " * "]
    #[doc = " * @param groupsSingleSeed contains group linkage data for linkage value "]
    #[doc = " * generation with one seed."]
    #[doc = " *"]
    #[doc = " * @param iPeriodInfo contains information about the duration of the "]
    #[doc = " * revocation time periods, to allow a receiver to determine at what point"]
    #[doc = " * it will be necessary to have calculated the linkage values associated"]
    #[doc = " * with future time periods."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkageValueCrlWithAlgIdentifier {
        #[rasn(identifier = "iRev")]
        pub i_rev: IValue,
        #[rasn(identifier = "indexWithinI")]
        pub index_within_i: Uint8,
        #[rasn(identifier = "seedEvolution")]
        pub seed_evolution: SeedEvolutionFunctionIdentifier,
        #[rasn(identifier = "lvGeneration")]
        pub lv_generation: LvGenerationFunctionIdentifier,
        pub individual: Option<SequenceOfJMaxGroup>,
        pub groups: Option<SequenceOfGroupCrlEntry>,
        #[rasn(identifier = "groupsSingleSeed")]
        pub groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
    }
    impl ToBeSignedLinkageValueCrlWithAlgIdentifier {
        pub fn new(
            i_rev: IValue,
            index_within_i: Uint8,
            seed_evolution: SeedEvolutionFunctionIdentifier,
            lv_generation: LvGenerationFunctionIdentifier,
            individual: Option<SequenceOfJMaxGroup>,
            groups: Option<SequenceOfGroupCrlEntry>,
            groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
        ) -> Self {
            Self {
                i_rev,
                index_within_i,
                seed_evolution,
                lv_generation,
                individual,
                groups,
                groups_single_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains type-specific CRL contents."]
    #[doc = " *"]
    #[doc = " * @param fullHashCrl: contains a full hash-based CRL, i.e., a listing of the"]
    #[doc = " * hashes of all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by hash, and"]
    #[doc = " *  - have been revoked"]
    #[doc = " *"]
    #[doc = " * @param deltaHashCrl: contains a delta hash-based CRL, i.e., a listing of"]
    #[doc = " * the hashes of all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by hash, and"]
    #[doc = " *  - have been revoked since the previous CRL that contained the indicated"]
    #[doc = " * cracaId and crlSeries values."]
    #[doc = " *"]
    #[doc = " * A Hash-based CRL should not include any certificates that had expired at the"]
    #[doc = " * time the CRL was generated; however, the inclusion of expired certificates"]
    #[doc = " * does not make a CRL invalid, and there is no expectation that receivers of a"]
    #[doc = " * CRL will check whether any of the certificates on the CRL have expired. "]
    #[doc = " *"]
    #[doc = " * @note Since a recipient of a hash-based CRLonly receives the hash, they"]
    #[doc = " * cannot directly establish the validity period of any certificate on the CRL"]
    #[doc = " * without obtaining the certificate itself; this would render impractical any"]
    #[doc = " * validity check for CRLs based on the expiry status of the revoked"]
    #[doc = " * certificates."]
    #[doc = " *"]
    #[doc = " * @param fullLinkedCrl and fullLinkedCrlWithAlg: contain a full linkage"]
    #[doc = " * ID-based CRL, i.e., a listing of the individual and/or group linkage data"]
    #[doc = " * for all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by linkage value, and"]
    #[doc = " *  - have been revoked"]
    #[doc = " * The difference between fullLinkedCrl and fullLinkedCrlWithAlg is in how"]
    #[doc = " * the cryptographic algorithms to be used in the seed evolution function and"]
    #[doc = " * linkage value generation function of 5.1.3.4 are communicated to the"]
    #[doc = " * receiver of the CRL. See below in this subclause for details."]
    #[doc = " *"]
    #[doc = " * @param deltaLinkedCrl and deltaLinkedCrlWithAlg: contain a delta linkage"]
    #[doc = " * ID-based CRL, i.e., a listing of the individual and/or group linkage data"]
    #[doc = " * for all certificates that:"]
    #[doc = " *  - contain the specified cracaId and crlSeries values, and"]
    #[doc = " *  -\tare revoked by linkage data, and"]
    #[doc = " *  -\thave been revoked since the previous CRL that contained the indicated"]
    #[doc = " * cracaId and crlSeries values."]
    #[doc = " * The difference between deltaLinkedCrl and deltaLinkedCrlWithAlg is in how"]
    #[doc = " * the cryptographic algorithms to be used in the seed evolution function"]
    #[doc = " * and linkage value generation function of 5.1.3.4 are communicated to the"]
    #[doc = " * receiver of the CRL. See below in this subclause for details."]
    #[doc = " *"]
    #[doc = " * @note It is the intent of this standard that once a certificate is revoked,"]
    #[doc = " * it remains revoked for the rest of its lifetime. CRL signers are expected "]
    #[doc = " * to include a revoked certificate on all CRLs issued between the "]
    #[doc = " * certificate's revocation and its expiry."]
    #[doc = " *"]
    #[doc = " * @note Seed evolution function and linkage value generation function"]
    #[doc = " * identification. In order to derive linkage values per the mechanisms given"]
    #[doc = " * in 5.1.3.4, a receiver needs to know the seed evolution function and the"]
    #[doc = " * linkage value generation function."]
    #[doc = " *"]
    #[doc = " * If the contents of this structure is a"]
    #[doc = " * ToBeSignedLinkageValueCrlWithAlgIdentifier, then the seed evolution function"]
    #[doc = " * and linkage value generation function are given explicitly as specified in"]
    #[doc = " * the specification of ToBeSignedLinkageValueCrlWithAlgIdentifier."]
    #[doc = " *"]
    #[doc = " * If the contents of this structure is a ToBeSignedLinkageValueCrl, then the"]
    #[doc = " * seed evolution function and linkage value generation function are obtained"]
    #[doc = " * based on the crlCraca field in the CrlContents:"]
    #[doc = " *  - If crlCraca was obtained with SHA-256 or SHA-384, then"]
    #[doc = " * seedEvolutionFunctionIdentifier is seedEvoFn1-sha256 and"]
    #[doc = " * linkageValueGenerationFunctionIdentifier is lvGenFn1-aes128."]
    #[doc = " *  - If crlCraca was obtained with SM3, then seedEvolutionFunctionIdentifier"]
    #[doc = " * is seedEvoFn1-sm3 and linkageValueGenerationFunctionIdentifier is"]
    #[doc = " * lvGenFn1-sm4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum TypeSpecificCrlContents {
        fullHashCrl(ToBeSignedHashIdCrl),
        deltaHashCrl(ToBeSignedHashIdCrl),
        fullLinkedCrl(ToBeSignedLinkageValueCrl),
        deltaLinkedCrl(ToBeSignedLinkageValueCrl),
        #[rasn(extension_addition)]
        fullLinkedCrlWithAlg(ToBeSignedLinkageValueCrlWithAlgIdentifier),
        #[rasn(extension_addition)]
        deltaLinkedCrlWithAlg(ToBeSignedLinkageValueCrlWithAlgIdentifier),
    }
}
