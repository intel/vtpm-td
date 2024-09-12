// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use core::convert::{TryFrom, TryInto};
pub use der::asn1::{
    AnyRef, BitStringRef, GeneralizedTime, ObjectIdentifier, OctetString, OctetStringRef,
    PrintableString, PrintableStringRef, SequenceOf, SetOfVec, UintRef, UtcTime, Utf8StringRef,
};
use der::{Choice, Decode, DerOrd, Encode, Header, Sequence, Tag, TagNumber, Tagged};
use der::{ErrorKind, TagMode};

#[derive(Debug)]
pub enum X509Error {
    DerEncoding(der::Error),
}

impl From<der::Error> for X509Error {
    fn from(e: der::Error) -> Self {
        X509Error::DerEncoding(e)
    }
}

pub struct CertificateBuilder<'a>(Certificate<'a>);

impl<'a> CertificateBuilder<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
        self_signed: bool,
    ) -> Result<Self, X509Error> {
        Ok(Self(Certificate::new(
            signature,
            algorithm,
            public_key,
            self_signed,
        )?))
    }

    pub fn set_not_before(mut self, time: core::time::Duration) -> Result<Self, X509Error> {
        self.0.tbs_certificate.validity.not_before =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(self)
    }

    pub fn set_not_after(mut self, time: core::time::Duration) -> Result<Self, X509Error> {
        self.0.tbs_certificate.validity.not_after =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(self)
    }

    pub fn set_public_key(
        mut self,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
    ) -> Result<Self, X509Error> {
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitStringRef::new(0, public_key)?,
        };
        self.0.tbs_certificate.subject_public_key_info = subject_public_key_info;
        Ok(self)
    }

    pub fn add_extension(mut self, extension: Extension<'a>) -> Result<Self, X509Error> {
        if let Some(extn) = self.0.tbs_certificate.extensions.as_mut() {
            extn.0.push(extension);
        } else {
            let extensions = vec![extension];
            self.0.tbs_certificate.extensions = Some(Extensions(extensions));
        }
        Ok(self)
    }

    pub fn sign(
        mut self,
        signature: &'a mut alloc::vec::Vec<u8>,
        mut signer: impl FnMut(&[u8], &mut alloc::vec::Vec<u8>),
    ) -> Result<Self, X509Error> {
        let tbs = self.0.tbs_certificate.to_der().unwrap();
        signer(tbs.as_slice(), signature);
        self.0.signature_value = BitStringRef::new(0, signature)?;
        Ok(self)
    }

    pub fn build(self) -> Certificate<'a> {
        self.0
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-3.1
// Certificate  ::=  SEQUENCE  {
//    tbsCertificate       TBSCertificate,
//    signatureAlgorithm   AlgorithmIdentifier,
//    signatureValue       BIT STRING  }
#[derive(Clone, Sequence)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringRef<'a>,
}

impl<'a> Certificate<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
        self_signed: bool,
    ) -> Result<Self, X509Error> {
        let version = Version(UintRef::new(&[2])?);
        let serial_number = UintRef::new(&[1])?;

        let mut issuer_name = SetOfVec::new();
        issuer_name.insert(DistinguishedName {
            attribute_type: ObjectIdentifier::new("2.5.4.3").unwrap(),
            value: Utf8StringRef::new("IntelVTpmCA")?.try_into().unwrap(),
        })?;
        let issuer = vec![issuer_name];

        let subject: alloc::vec::Vec<SetOfVec<DistinguishedName<'_>>> = if self_signed {
            issuer.clone()
        } else {
            alloc::vec::Vec::new()
        };

        let validity = Validity {
            not_before: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
            not_after: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
        };

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitStringRef::new(0, public_key)?,
        };

        let tbs_certificate = TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let signature_value = BitStringRef::new(0, &[])?;

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm: signature,
            signature_value,
        })
    }

    pub fn tbs_certificate(&self) -> &TBSCertificate {
        &self.tbs_certificate
    }

    pub fn set_signature(&mut self, signature: &'a [u8]) -> Result<(), X509Error> {
        self.signature_value = BitStringRef::new(0, signature)?;
        Ok(())
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
// TBSCertificate  ::=  SEQUENCE  {
//     version         [0]  EXPLICIT Version DEFAULT v1,
//     serialNumber         CertificateSerialNumber,
//     signature            AlgorithmIdentifier,
//     issuer               Name,
//     validity             Validity,
//     subject              Name,
//     subjectPublicKeyInfo SubjectPublicKeyInfo,
//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     extensions      [3]  EXPLICIT Extensions OPTIONAL
//                          -- If present, version MUST be v3
// }
#[derive(Clone, Sequence)]
pub struct TBSCertificate<'a> {
    pub version: Version<'a>,
    pub serial_number: UintRef<'a>, // ASN.1 INTEGER
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub validity: Validity,
    pub subject: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<UniqueIdentifier<'a, 1>>,
    pub subject_unique_id: Option<UniqueIdentifier<'a, 2>>,
    pub extensions: Option<Extensions<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier<'a>(pub OctetStringRef<'a>);

impl<'a> Encode for AuthorityKeyIdentifier<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAltName<'a>(pub alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>);

impl<'a> Encode for SubjectAltName<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(4),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(4),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version<'a>(UintRef<'a>);

impl<'a> Decode<'a> for Version<'a> {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        // let res = decoder.any()?;
        let v = decoder
            .context_specific(TagNumber::new(0), TagMode::Explicit)?
            .ok_or(der::Error::new(ErrorKind::Failed, decoder.position()))?;
        // let v = decoder.decode()?;
        Ok(Self(v))
    }
}

impl<'a> Encode for Version<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a> Tagged for Version<'a> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

impl<'a> Choice<'a> for Version<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct DistinguishedName<'a> {
    pub(crate) attribute_type: ObjectIdentifier,
    pub(crate) value: AnyRef<'a>,
}

impl<'a> DerOrd for DistinguishedName<'a> {
    fn der_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        Ok(self.attribute_type.cmp(&other.attribute_type))
    }
}

#[derive(Choice, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    #[asn1(type = "GeneralizedTime")]
    Generalized(GeneralizedTime),
}

impl From<UtcTime> for Time {
    fn from(time: UtcTime) -> Time {
        Time::Utc(time)
    }
}

impl From<GeneralizedTime> for Time {
    fn from(time: GeneralizedTime) -> Time {
        Time::Generalized(time)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitStringRef<'a>,
}

#[derive(Clone)]
pub struct UniqueIdentifier<'a, const N: u8>(BitStringRef<'a>);

impl<'a, const N: u8> Decode<'a> for UniqueIdentifier<'a, N> {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let id = decoder
            .context_specific(TagNumber::new(N), TagMode::Explicit)?
            .ok_or(der::Error::new(ErrorKind::Failed, decoder.position()))?;
        // let id = decoder.decode()?;
        // let uid = BitStringRef::from_der(res.value())?;
        Ok(Self(id))
    }
}

impl<'a, const N: u8> Encode for UniqueIdentifier<'a, N> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a, const N: u8> Tagged for UniqueIdentifier<'a, N> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

impl<'a, const N: u8> Choice<'a> for UniqueIdentifier<'a, N> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extensions<'a>(alloc::vec::Vec<Extension<'a>>);

impl<'a> Extensions<'a> {
    pub fn get(&self) -> &alloc::vec::Vec<Extension<'a>> {
        &self.0
    }
}

impl<'a> Decode<'a> for Extensions<'a> {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let ext = decoder
            .context_specific(TagNumber::new(3), TagMode::Explicit)?
            .ok_or(der::Error::new(ErrorKind::Failed, decoder.position()))?;
        Ok(Self(ext))
    }
}

impl<'a> Encode for Extensions<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a> Tagged for Extensions<'a> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

impl<'a> Choice<'a> for Extensions<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    pub critical: Option<bool>, // ASN.1 BOOLEAN.
    pub extn_value: Option<OctetStringRef<'a>>,
}

impl<'a> Extension<'a> {
    pub fn new(
        extn_id: ObjectIdentifier,
        critical: Option<bool>,
        extn_value: Option<&'a [u8]>,
    ) -> Result<Self, X509Error> {
        let extn_value = if let Some(extn_value) = extn_value {
            Some(OctetStringRef::new(extn_value)?)
        } else {
            None
        };

        Ok(Self {
            extn_id,
            critical,
            extn_value,
        })
    }
}

pub type ExtendedKeyUsage = alloc::vec::Vec<ObjectIdentifier>;
