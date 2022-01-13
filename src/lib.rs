//! A compact CBOR-encoded voucher defined by [Constrained BRSKI].
//!
//!
//! # Examples (!! WIP !!)
//!
//! ```ignore
//! use minerva_voucher::{Voucher, Sign, Validate};
//!
//! // (Add notes on the PSA crypto context ...)
//! #[cfg(feature = "v3")]
//! init_psa_crypto();
//!
//! let mut vrq = Voucher::new_vrq();
//!
//! // ...
//!
//! ```
//!
//! A `Voucher` with a known list of attributes can be initialized using macros:
//!
//! ```ignore
//! use minerva_voucher::{vch, vrq};
//!
//! let vch = vch![
//!     Attr::Assertion(Assertion::Logged),
//!     Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
//!
//! let vrq = vrq![
//!     Attr::Assertion(Assertion::Proximity),
//!     Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
//! ```
//!
//! A raw CBOR-encoded voucher can be decoded into a [`Voucher`] through the `TryFrom` and/or `TryInto`
//! traits.
//!
//! ```ignore
//! use core::convert::{TryFrom, TryInto};
//!
//! assert!(Voucher::try_from(VCH_JADA).is_ok());
//!
//! let vch: Voucher = VCH_JADA.try_into().unwrap();
//!
//! vch.iter().for_each(|attr| {
//!     println!("attr: {:?}", attr);
//!     match attr {
//!         Attr::Assertion(x) => assert_eq!(x, &Assertion::Proximity),
//!         Attr::CreatedOn(x) => assert_eq!(x, &1475868702),
//!         Attr::ExpiresOn(x) => assert_eq!(x, &1506816000),
//!         Attr::Nonce(x) => assert_eq!(x, &[97, 98, 99, 100, 49, 50, 51, 52, 53]),
//!         Attr::PinnedDomainPubk(x) => assert_eq!(x[0..4], [77, 70, 107, 119]),
//!         Attr::SerialNumber(x) => assert_eq!(x, "JADA123456789".as_bytes()),
//!         _ => panic!(),
//!     }
//! });
//! ```
//!
//! [Constrained BRSKI]: https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html
#![no_std]

#![feature(arbitrary_enum_discriminant)]
#![feature(core_intrinsics)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, self as alloc};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc};

use alloc::{boxed::Box, vec, vec::Vec, collections::{BTreeMap, BTreeSet}};

use core::convert::TryFrom;

#[cfg(test)]
mod tests;

mod utils;

pub mod attr;
use attr::*;

mod yang;

mod sid;
use sid::{Sid, SidDisc};

mod sid_data;
use sid_data::SidData;

mod cose_sig;
mod cose_data;
use cose_data::{CoseError, CborError, CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

#[cfg(debug_assertions)]
pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::sid_data::{content_comp, content_comp_permissive};
}

//

pub trait Sign {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError>;
}

pub trait Validate {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, VoucherError>;
}

#[cfg(any(feature = "sign", feature = "sign-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

//

#[derive(PartialEq, Debug)]
pub enum VoucherError {
    CborFailure(CborError),
    CoseFailure(CoseError),
    InvalidArgument,
    MalformedInput,
    MissingAttributes,
    SigningFailed,
    UnexpectedCborType,
    ValidationFailed,
}

#[derive(PartialEq, Debug)]
pub struct Voucher {
    sd: SidData,
    cd: CoseData,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum VoucherType {
    Vch, // 'voucher'
    Vrq, // 'voucher request'
}

impl Voucher {
    pub fn new_vch() -> Self {
        Self::new(VoucherType::Vch)
    }

    pub fn new_vrq() -> Self {
        Self::new(VoucherType::Vrq)
    }

    pub fn is_vch(&self) -> bool {
        !self.is_vrq()
    }

    pub fn is_vrq(&self) -> bool {
        self.sd.is_vrq()
    }

    fn new(ty: VoucherType) -> Self {
        Self {
            sd: match ty {
                VoucherType::Vch => SidData::new_vch_cbor(),
                VoucherType::Vrq => SidData::new_vrq_cbor(),
            },
            cd: CoseData::new(true),
        }
    }

    /// Returns a reference to the attribute in the voucher, if any, that corresponds to the given attribute discriminant value.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// vrq.set(Attr::CreatedOn(1475868702));
    ///
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1475868702)));
    /// assert_eq!(vrq.get(ATTR_SERIAL_NUMBER), None);
    /// ```
    pub fn get(&self, adisc: AttrDisc) -> Option<&Attr> {
        let sdisc = self.to_sid_disc(adisc)?;
        for sid in self.sd.iter() {
            if sid.disc() == sdisc {
                return sid.as_attr();
            }
        }

        None
    }

    /// Adds an attribute to the voucher, replacing the existing attribute, if any, that corresponds to the given one. Returns a `mut` reference to the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), None);
    ///
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1475868702)));
    ///
    /// vrq.set(Attr::CreatedOn(1599086034));
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1599086034)));
    /// ```
    pub fn set(&mut self, attr: Attr) -> &mut Self {
        let sdisc = self.to_sid_disc(attr.disc()).unwrap();
        self.set_sid(Sid::try_from((attr.into_yang(), sdisc)).unwrap());

        self
    }

    fn set_sid(&mut self, sid: Sid) -> &mut Self {
        self.sd.replace(sid);

        self
    }

    /// Removes an attribute from the voucher. Returns whether the attribute was present in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// vrq.set(Attr::CreatedOn(1475868702));
    ///
    /// assert_eq!(vrq.remove(ATTR_CREATED_ON), true);
    /// assert_eq!(vrq.remove(ATTR_CREATED_ON), false);
    /// ```
    pub fn remove(&mut self, adisc: AttrDisc) -> bool {
        if let Some(sdisc) = self.to_sid_disc(adisc) {
            self.sd.remove(sdisc)
        } else {
            false
        }
    }

    /// Removes and returns the attribute in the voucher, if any, that corresponds to the given attribute discriminant value.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.take(ATTR_CREATED_ON), Some(Attr::CreatedOn(1475868702)));
    /// assert_eq!(vrq.take(ATTR_CREATED_ON), None);
    ///
    /// let sn = "00-D0-E5-F2-00-02".as_bytes();
    /// vrq.set(Attr::SerialNumber(sn.to_vec()));
    /// assert_eq!(vrq.take(ATTR_SERIAL_NUMBER), Some(Attr::SerialNumber(sn.to_vec())));
    /// assert_eq!(vrq.take(ATTR_SERIAL_NUMBER), None);
    /// ```
    pub fn take(&mut self, adisc: AttrDisc) -> Option<Attr> {
        self.sd
            .take(self.to_sid_disc(adisc)?)
            .and_then(|sid| sid.into_attr())
    }

    fn to_sid_disc(&self, adisc: AttrDisc) -> Option<SidDisc> {
        Attr::to_sid_disc(adisc, self.is_vrq())
    }

    /// Returns the number of attributes in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::Attr};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// assert_eq!(vrq.len(), 0);
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Gets an iterator that visits the attributes in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::{Attr, Assertion}};
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// vrq.set(Attr::Assertion(Assertion::Proximity))
    ///     .set(Attr::CreatedOn(1599086034))
    ///     .set(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()));
    ///
    /// let mut vrq_iter = vrq.iter();
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_none());
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Attr> + '_ {
        self.iter_with_sid()
            .map(|(attr, _)| attr)
    }

    /// todo
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn iter_with_sid(&self) -> impl Iterator<Item = (&Attr, sid::SidDisc)> + '_ {
        self.sd.iter()
            .filter_map(|sid| Some((sid.as_attr()?, sid.disc())))
    }

    /// todo
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn dump(&self) {
        println!("======== Voucher::dump()");
        self.sd.dump();
        self.cd.dump();
        println!("========");
    }

    #[cfg(test)]
    pub fn dump_and_panic(&self) {
        self.dump();
        panic!();
    }

    /// todo
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, VoucherError> {
        if self.get(ATTR_ASSERTION).is_none() {
            debug_println!("serialize(): `Attr::Assertion` is mandatory; but missing");
            return Err(VoucherError::MissingAttributes);
        }

        if self.get(ATTR_SERIAL_NUMBER).is_none() {
            debug_println!("serialize(): `Attr::SerialNumber` is mandatory; but missing");
            return Err(VoucherError::MissingAttributes);
        }

        CoseData::encode(&self.cd).or_else(|ce| {
            debug_println!("serialize(): `CoseData::encode()` failed.  (Maybe, voucher not signed yet?)");

            Err(VoucherError::CoseFailure(ce))
        })
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        let sig = self.cd.sig();

        (&sig.signature, &sig.signature_type)
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let signer_cert = &self.cd.sig().signer_cert;

        if signer_cert.len() > 0 { Some(signer_cert) } else { None }
    }

    // c.f. `Voucher::try_from(VCH_JADA).unwrap().dump_and_panic();`
    pub fn set_signer_cert(&mut self, _cert: &[u8]) -> &mut Self {
        unimplemented!();

        //self
    }

    #[cfg(test)]
    fn get_cose_content(&self) -> Option<Vec<u8>> {
        println!("get_cose_content(): self.sd: {:?}", self.sd);

        let content = self.cd.get_content().ok();
        println!("get_cose_content(): content: {:?}", content);

        content
    }

    fn update_cose_content(&mut self) -> &mut Self {
        use sid::Cbor;

        let content = if let Some(cbor) = self.sd.serialize() { cbor } else {
            debug_println!("update_cose_content(): Failed to generate `content`");

            vec![]
        };

        self.cd.set_content(&content);

        self
    }

    /// Interface with meta data to be used in ECDSA based signing
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn to_sign(&mut self) -> (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]) {
        use core::ops::DerefMut;

        let sig = self
            .update_cose_content()
            .cd.sig_mut().deref_mut();

        (&mut sig.signature, &mut sig.signature_type, &sig.to_verify)
    }

    /// Interface with meta data to be used in ECDSA based validation
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.cd.sig().to_verify)
    }
}

/// todo
///
/// # Examples
///
/// ```
/// ;
/// ```
impl TryFrom<&[u8]> for Voucher {
    type Error = VoucherError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (tag, cd) = CoseData::decode(raw).or_else(|ce| {
            debug_println!("Failed to decode raw voucher");
            Err(VoucherError::CoseFailure(ce))
        })?;

        if tag != COSE_SIGN_ONE_TAG {
            debug_println!("Only `CoseSign1` vouchers are supported");
            return Err(VoucherError::CoseFailure(CoseError::UnexpectedTag));
        }

        let content = cd.get_content().or_else(|ce| {
            debug_println!("Failed to get `content`");
            Err(VoucherError::CoseFailure(ce))
        })?;

        let sidhash = cose_sig::decode(&content).or_else(|ce| {
            debug_println!("Failed to decode `content`");
            Err(VoucherError::CborFailure(ce))
        })?;
        debug_println!("sidhash: {:?}", sidhash);

        SidData::try_from(sidhash)
            .and_then(|sd| Ok(Self { sd, cd }))
    }
}

//

macro_rules! debug_println {
    ( $( $x:expr ),* ) => {
        if cfg!(debug_assertions) {
            crate::println!( $( $x ),* );
        }
    };
}

use debug_println;

//

#[allow(unused_macros)]
macro_rules! build_voucher {
    ( $voucher:expr, $( $attr:expr ),* ) => {
        {
            let mut voucher = $voucher;
            $(
                voucher.set($attr);
            )*
            voucher
        }
    };
}

#[allow(unused_imports)]
use build_voucher;

/// todo
///
/// # Examples
///
/// ```
/// ;
/// ```
#[macro_export]
macro_rules! vch {
    ( ) => (Voucher::new_vch());
    ( $( $attr:expr ),* ) => (build_voucher!( Voucher::new_vch(), $( $attr ),* ));
}

/// todo
///
/// # Examples
///
/// ```
/// ;
/// ```
#[macro_export]
macro_rules! vrq {
    ( ) => (Voucher::new_vrq());
    ( $( $attr:expr ),* ) => (build_voucher!( Voucher::new_vrq(), $( $attr ),* ));
}
