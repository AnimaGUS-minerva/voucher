use crate::{vec, Vec, BTreeMap};
use crate::debug_println;

use cose::{decoder::*, unpack};
pub use cose::{CoseError, decoder::{CborError, SignatureAlgorithm, COSE_SIGN_ONE_TAG}};

use super::cose_sig::{CoseSig, bytes_from, map_value_from};

pub const COSE_HEADER_VOUCHER_PUBKEY: u64 = 60299;

#[derive(PartialEq, Debug)]
pub struct CoseData {
    protected_bucket: BTreeMap<CborType, CborType>,
    unprotected_bucket: BTreeMap<CborType, CborType>,
    inner: CoseDataInner,
}

#[derive(PartialEq, Debug)]
enum CoseDataInner {
    CoseSignOne(CoseSig),
    CoseSign(Vec<CoseSig>),
}

impl CoseData {
    pub fn sig(&self) -> &CoseSig {
        if let CoseDataInner::CoseSignOne(ref sig) = self.inner {
            sig
        } else {
            unimplemented!();
        }
    }

    pub fn sig_mut(&mut self) -> &mut CoseSig {
        if let CoseDataInner::CoseSignOne(ref mut sig) = self.inner {
            sig
        } else {
            unimplemented!();
        }
    }

    pub fn new(is_sign1: bool) -> Self {
        if !is_sign1 { unimplemented!(); }

        Self {
            protected_bucket: BTreeMap::new(),
            unprotected_bucket: BTreeMap::new(),
            inner: CoseDataInner::CoseSignOne(CoseSig::new_default()),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<(u64, Self), CoseError> {
        match get_cose_sign_array(bytes)? {
            (COSE_SIGN_ONE_TAG, ref array) => {
                let (pb, upb, sig) = Self::decode_cose_sign_one(array)?;

                Ok((COSE_SIGN_ONE_TAG, Self {
                    protected_bucket: pb,
                    unprotected_bucket: upb,
                    inner: CoseDataInner::CoseSignOne(sig),
                }))
            },
            (COSE_SIGN_TAG, ref array) => {
                let (pb, upb, sigs) = Self::decode_cose_sign(array)?;

                Ok((COSE_SIGN_TAG, Self {
                    protected_bucket: pb,
                    unprotected_bucket: upb,
                    inner: CoseDataInner::CoseSign(sigs),
                }))
            },
            (_, ref array) => {
                Self::dump_cose_sign_array(array);
                Err(CoseError::UnexpectedTag)
            },
        }
    }

    pub fn encode(&self, content: Option<Vec<u8>>) -> Result<Vec<u8>, CoseError> {
        let content = if let Some(x) = content { x } else { self.get_content()? };

        self.sig().encode(&self.protected_bucket, &self.unprotected_bucket, content)
    }

    pub fn dump(&self) {
        match &self.inner {
            CoseDataInner::CoseSignOne(sig) => sig.dump(),
            CoseDataInner::CoseSign(sigs) => sigs.iter().for_each(|sig| sig.dump()),
        }
    }

    pub fn get_content(&self) -> Result<Vec<u8>, CoseError> {
        self.sig().extract_content()
    }

    pub fn set_content(&mut self, content: &[u8]) {
        match &mut self.inner {
            CoseDataInner::CoseSignOne(sig) => {
                sig.set_content(content, &self.protected_bucket);
            },
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    pub fn generate_content(&self, sid_data_serialized: &[u8]) -> Result<Vec<u8>, CoseError> {
        CoseSig::new_default()
            .set_content(sid_data_serialized, &self.protected_bucket)
            .extract_content()
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let cert = &self.sig().signer_cert;

        if cert.len() > 0 { Some(cert) } else { None }
    }

    pub fn set_signer_cert(&mut self, cert: &[u8]) {
        self.sig_mut().signer_cert = cert.to_vec();
        self.unprotected_bucket.insert(
            CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY), CborType::Bytes(cert.to_vec()));
    }

    pub fn set_alg(&mut self, alg: SignatureAlgorithm) {
        self.sig_mut().signature_type = alg;
        self.protected_bucket.insert(
            CborType::Integer(COSE_HEADER_ALG), match alg {
                SignatureAlgorithm::ES256 => CborType::SignedInteger(COSE_TYPE_ES256),
                SignatureAlgorithm::ES384 => CborType::SignedInteger(COSE_TYPE_ES384),
                SignatureAlgorithm::ES512 => CborType::SignedInteger(COSE_TYPE_ES512),
                SignatureAlgorithm::PS256 => CborType::SignedInteger(COSE_TYPE_PS256),
            });
    }

    fn dump_cose_sign_array(array: &[CborType]) {
        array.iter().enumerate().for_each(|(i, cbor)| {
            debug_println!("  array[{}]: {:?}", i, cbor);
        });
    }

    fn decode_cose_sign(cose_sign_array: &[CborType]
    ) -> Result<(BTreeMap<CborType, CborType>,
                 BTreeMap<CborType, CborType>,
                 Vec<CoseSig>), CoseError> {
        Ok((
            BTreeMap::new(), // dummy
            BTreeMap::new(), // dummy
            decode_signature_multiple(cose_sign_array, &vec![0u8])? // dummy
                .into_iter()
                .map(|inner| CoseSig::new(inner))
                .collect()
        ))
    }

    fn decode_cose_sign_one(cose_sign_array: &[CborType]
    ) -> Result<(BTreeMap<CborType, CborType>,
                 BTreeMap<CborType, CborType>,
                 CoseSig), CoseError> {
        let is_permissive = true;
        let pb_cbor_serialized = &cose_sign_array[0];

        //

        let mut pb = None;
        let mut ty = None;

        if let Ok(ref pb_cbor) = cose::decoder::decode(&bytes_from(pb_cbor_serialized)?) {
            pb.replace(unpack!(Map, pb_cbor).clone());

            if let Ok(alg) = map_value_from(pb_cbor, &CborType::Integer(COSE_HEADER_ALG)) {
                ty.replace(resolve_alg(&alg)?);
            } else if is_permissive {
                debug_println!("⚠️ missing `COSE_HEADER_ALG`; ES256 is assumed");
                ty.replace(SignatureAlgorithm::ES256);
            } else {
                return Err(CoseError::MissingHeader);
            }
        } else {
            return Err(CoseError::DecodingFailure);
        }

        let pb = pb.unwrap();
        let signature_type = ty.unwrap();

        //

        let upb_cbor = &cose_sign_array[1];
        let upb = unpack!(Map, upb_cbor).clone();

        let signer_cert = map_value_from(upb_cbor, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY))
            .and_then(|val| bytes_from(&val))
            .or::<Vec<u8>>(Ok(vec![]))
            .unwrap();

        //

        let signature = bytes_from(&cose_sign_array[3])?;
        let content = bytes_from(&cose_sign_array[2])?;

        let sig = CoseSig::new(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(pb_cbor_serialized.clone(), &content)
        });

        Ok((pb, upb, sig))
    }
}
