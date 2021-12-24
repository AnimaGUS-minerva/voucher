use crate::{println, vec, Vec, BTreeMap, BTreeSet};
pub use cose::decoder::CborType;

pub use super::yang::{Yang, YangEnum};
use super::yang;

use core::intrinsics::discriminant_value as disc;
use core::convert::TryFrom;

pub trait Cbor {
    fn to_cbor(&self) -> Option<CborType>;

    fn serialize(&self) -> Option<Vec<u8>> {
        self.to_cbor().and_then(|c| Some(c.serialize()))
    }
}

pub type SidDisc = u64;

pub const SID_VCH_TOP_LEVEL: SidDisc =                                   2451; // 'voucher' <- ['ietf-cwt-voucher', 'ietf-voucher-constrained:voucher']
pub const SID_VCH_ASSERTION: SidDisc =                                   2452; // 'assertion'
pub const SID_VCH_CREATED_ON: SidDisc =                                  2453; // 'created-on'
pub const SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =               2454; // 'domain-cert-revocation-checks'
pub const SID_VCH_EXPIRES_ON: SidDisc =                                  2455; // 'expires-on'
pub const SID_VCH_IDEVID_ISSUER: SidDisc =                               2456; // 'idevid-issuer'
pub const SID_VCH_LAST_RENEWAL_DATE: SidDisc =                           2457; // 'last-renewal-date'
pub const SID_VCH_NONCE: SidDisc =                                       2458; // 'nonce'
pub const SID_VCH_PINNED_DOMAIN_CERT: SidDisc =                          2459; // 'pinned-domain-cert'
pub const SID_VCH_PINNED_DOMAIN_PUBK: SidDisc =                          2460; // 'pinned-domain-pubk'
pub const SID_VCH_PINNED_DOMAIN_PUBK_SHA256: SidDisc =                   2461; // 'pinned-domain-pubk-sha256'
pub const SID_VCH_SERIAL_NUMBER: SidDisc =                               2462; // 'serial-number'

pub const SID_VRQ_TOP_LEVEL: SidDisc =                                   2501; // 'voucher' <- ['ietf-cwt-voucher-request', 'ietf-cwt-voucher-request:voucher', 'ietf-voucher-request-constrained:voucher']
pub const SID_VRQ_ASSERTION: SidDisc =                                   2502; // 'assertion'
pub const SID_VRQ_CREATED_ON: SidDisc =                                  2503; // 'created-on'
pub const SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =               2504; // 'domain-cert-revocation-checks'
pub const SID_VRQ_EXPIRES_ON: SidDisc =                                  2505; // 'expires-on'
pub const SID_VRQ_IDEVID_ISSUER: SidDisc =                               2506; // 'idevid-issuer'
pub const SID_VRQ_LAST_RENEWAL_DATE: SidDisc =                           2507; // 'last-renewal-date'
pub const SID_VRQ_NONCE: SidDisc =                                       2508; // 'nonce'
pub const SID_VRQ_PINNED_DOMAIN_CERT: SidDisc =                          2509; // 'pinned-domain-cert'
pub const SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST: SidDisc =                2510; // 'prior-signed-voucher-request'
pub const SID_VRQ_PROXIMITY_REGISTRAR_CERT: SidDisc =                    2511; // 'proximity-registrar-cert'
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK: SidDisc =                    2513; // 'proximity-registrar-pubk'
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256: SidDisc =             2512; // 'proximity-registrar-pubk-sha256'
pub const SID_VRQ_SERIAL_NUMBER: SidDisc =                               2514; // 'serial-number'

#[repr(u64)]
#[derive(Clone, Eq, Debug)]
pub enum Sid {
    VchTopLevel(TopLevel) =                           SID_VCH_TOP_LEVEL,
    VchAssertion(Yang) =                              SID_VCH_ASSERTION,
    VchCreatedOn(Yang) =                              SID_VCH_CREATED_ON,
    VchDomainCertRevocationChecks(Yang) =             SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS,
    VchExpiresOn(Yang) =                              SID_VCH_EXPIRES_ON,
    VchIdevidIssuer(Yang) =                           SID_VCH_IDEVID_ISSUER,
    VchLastRenewalDate(Yang) =                        SID_VCH_LAST_RENEWAL_DATE,
    VchNonce(Yang) =                                  SID_VCH_NONCE,
    VchPinnedDomainCert(Yang) =                       SID_VCH_PINNED_DOMAIN_CERT,
    VchPinnedDomainPubk(Yang) =                       SID_VCH_PINNED_DOMAIN_PUBK,
    VchPinnedDomainPubkSha256(Yang) =                 SID_VCH_PINNED_DOMAIN_PUBK_SHA256,
    VchSerialNumber(Yang) =                           SID_VCH_SERIAL_NUMBER,
    VrqTopLevel(TopLevel) =                           SID_VRQ_TOP_LEVEL,
    VrqAssertion(Yang) =                              SID_VRQ_ASSERTION,
    VrqCreatedOn(Yang) =                              SID_VRQ_CREATED_ON,
    VrqDomainCertRevocationChecks(Yang) =             SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS,
    VrqExpiresOn(Yang) =                              SID_VRQ_EXPIRES_ON,
    VrqIdevidIssuer(Yang) =                           SID_VRQ_IDEVID_ISSUER,
    VrqLastRenewalDate(Yang) =                        SID_VRQ_LAST_RENEWAL_DATE,
    VrqNonce(Yang) =                                  SID_VRQ_NONCE,
    VrqPinnedDomainCert(Yang) =                       SID_VRQ_PINNED_DOMAIN_CERT,
    VrqPriorSignedVoucherRequest(Yang) =              SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST,
    VrqProximityRegistrarCert(Yang) =                 SID_VRQ_PROXIMITY_REGISTRAR_CERT,
    VrqProximityRegistrarPubk(Yang) =                 SID_VRQ_PROXIMITY_REGISTRAR_PUBK,
    VrqProximityRegistrarPubkSha256(Yang) =           SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256,
    VrqSerialNumber(Yang) =                           SID_VRQ_SERIAL_NUMBER,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TopLevel {
    CwtVoucher,
    VoucherVoucher,
    CwtVoucherRequest,
    CwtVoucherRequestVoucher,
    VoucherRequestVoucher,
}

impl TopLevel {
    const fn value(self) -> &'static str {
        match self {
            Self::CwtVoucher => "ietf-cwt-voucher",
            Self::VoucherVoucher => "ietf-voucher:voucher",
            Self::CwtVoucherRequest => "ietf-cwt-voucher-request",
            Self::CwtVoucherRequestVoucher => "ietf-cwt-voucher-request:voucher",
            Self::VoucherRequestVoucher=> "ietf-voucher-request:voucher",
        }
    }
}

impl Ord for Sid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        disc(self).cmp(&disc(other))
    }
}

impl PartialOrd for Sid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        disc(self) == disc(other)
    }
}

impl Cbor for Sid {
    fn to_cbor(&self) -> Option<CborType> {
        use Sid::*;
        use yang::*;

        let yang_to_cbor =
            |yg: &Yang, ygd| if disc(yg) == ygd { yg.to_cbor() } else { None };

        match self {
            VchTopLevel(_) |
            VrqTopLevel(_) =>
                None,
            VchAssertion(yg) |
            VrqAssertion(yg) =>
                yang_to_cbor(yg, YANG_ENUMERATION),
            VchDomainCertRevocationChecks(yg) |
            VrqDomainCertRevocationChecks(yg) =>
                yang_to_cbor(yg, YANG_BOOLEAN),
            VchCreatedOn(yg) |
            VchExpiresOn(yg) |
            VchLastRenewalDate(yg) |
            VrqCreatedOn(yg) |
            VrqExpiresOn(yg) |
            VrqLastRenewalDate(yg) =>
                yang_to_cbor(yg, YANG_DATE_AND_TIME),
            VchIdevidIssuer(yg) |
            VchNonce(yg) |
            VchPinnedDomainCert(yg) |
            VchPinnedDomainPubk(yg) |
            VchPinnedDomainPubkSha256(yg) |
            VrqIdevidIssuer(yg) |
            VrqNonce(yg) |
            VrqPinnedDomainCert(yg) |
            VrqPriorSignedVoucherRequest(yg) |
            VrqProximityRegistrarCert(yg) |
            VrqProximityRegistrarPubk(yg) |
            VrqProximityRegistrarPubkSha256(yg) =>
                yang_to_cbor(yg, YANG_BINARY),
            VchSerialNumber(yg) |
            VrqSerialNumber(yg) =>
                yang_to_cbor(yg, YANG_STRING),
        }
    }
}

impl TryFrom<(Yang, SidDisc)> for Sid {
    type Error = ();

    fn try_from(input: (Yang, SidDisc)) -> Result<Self, Self::Error> {
        let (yg, sid_disc) = input;
        match sid_disc {
            SID_VCH_TOP_LEVEL => Err(()),
            SID_VCH_ASSERTION => Ok(Sid::VchAssertion(yg)),
            SID_VCH_CREATED_ON => Ok(Sid::VchCreatedOn(yg)),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS => Ok(Sid::VchDomainCertRevocationChecks(yg)),
            SID_VCH_EXPIRES_ON => Ok(Sid::VchExpiresOn(yg)),
            SID_VCH_IDEVID_ISSUER => Ok(Sid::VchIdevidIssuer(yg)),
            SID_VCH_LAST_RENEWAL_DATE => Ok(Sid::VchLastRenewalDate(yg)),
            SID_VCH_NONCE => Ok(Sid::VchNonce(yg)),
            SID_VCH_PINNED_DOMAIN_CERT => Ok(Sid::VchPinnedDomainCert(yg)),
            SID_VCH_PINNED_DOMAIN_PUBK => Ok(Sid::VchPinnedDomainPubk(yg)),
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 => Ok(Sid::VchPinnedDomainPubkSha256(yg)),
            SID_VCH_SERIAL_NUMBER => Ok(Sid::VchSerialNumber(yg)),
            SID_VRQ_TOP_LEVEL => Err(()),
            SID_VRQ_ASSERTION => Ok(Sid::VrqAssertion(yg)),
            SID_VRQ_CREATED_ON => Ok(Sid::VrqCreatedOn(yg)),
            SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS => Ok(Sid::VrqDomainCertRevocationChecks(yg)),
            SID_VRQ_EXPIRES_ON => Ok(Sid::VrqExpiresOn(yg)),
            SID_VRQ_IDEVID_ISSUER => Ok(Sid::VrqIdevidIssuer(yg)),
            SID_VRQ_LAST_RENEWAL_DATE => Ok(Sid::VrqLastRenewalDate(yg)),
            SID_VRQ_NONCE => Ok(Sid::VrqNonce(yg)),
            SID_VRQ_PINNED_DOMAIN_CERT => Ok(Sid::VrqPinnedDomainCert(yg)),
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST => Ok(Sid::VrqPriorSignedVoucherRequest(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_CERT => Ok(Sid::VrqProximityRegistrarCert(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK => Ok(Sid::VrqProximityRegistrarPubk(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 => Ok(Sid::VrqProximityRegistrarPubkSha256(yg)),
            SID_VRQ_SERIAL_NUMBER => Ok(Sid::VrqSerialNumber(yg)),
            _ => Err(()),
        }
    }
}

//

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// TODO - update according to 'draft-ietf-anima-constrained-voucher-15'
// TODO - checker on serialize/sign/****
// #   +---- voucher
// #      +---- created-on?                      yang:date-and-time
// #      +---- expires-on?                      yang:date-and-time
// #      +---- assertion                        enumeration
// #      +---- serial-number                    string
// #      +---- idevid-issuer?                   binary
// #      +---- pinned-domain-cert?              binary
// #      +---- domain-cert-revocation-checks?   boolean
// #      +---- nonce?                           binary
// #      +---- last-renewal-date?               yang:date-and-time
// #      +---- prior-signed-voucher-request?    binary
// #      +---- proximity-registrar-cert?        binary
impl SidData {
    pub fn new_vch() -> Self { Self::Voucher(BTreeSet::new()) }
    pub fn new_vrq() -> Self { Self::VoucherRequest(BTreeSet::new()) }
    pub fn vch_from(set: BTreeSet<Sid>) -> Self { Self::Voucher(set) }
    pub fn vrq_from(set: BTreeSet<Sid>) -> Self { Self::VoucherRequest(set) }

    pub fn new_vch_cbor() -> Self {
        Self::Voucher(BTreeSet::from([Sid::VchTopLevel(TopLevel::VoucherVoucher)]))
    }

    pub fn new_vrq_cbor() -> Self {
        Self::VoucherRequest(BTreeSet::from([Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)]))
    }

    pub fn replace(&mut self, sid: Sid) {
        self.inner_mut().replace(sid);
    }

    fn inner_mut(&mut self) -> &mut BTreeSet<Sid> {
        match self {
            Self::Voucher(set) => set,
            Self::VoucherRequest(set) => set,
        }
    }

    pub fn inner(&self) -> (&BTreeSet<Sid>, bool /* is_vrq */) {
        match self {
            Self::Voucher(set) => (set, false),
            Self::VoucherRequest(set) => (set, true),
        }
    }

    pub fn is_vrq(&self) -> bool {
        self.inner().1
    }
}

impl Cbor for SidData {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        let (set, is_vrq) = self.inner();
        let tl = if is_vrq {
            &Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)
        } else {
            &Sid::VchTopLevel(TopLevel::VoucherVoucher)
        };

        if set.contains(tl) {
            Some(Map(BTreeMap::from([(Integer(disc(tl)), {
                let mut attrs = BTreeMap::new();
                set.iter()
                    .filter(|sid| !matches!(*sid, Sid::VchTopLevel(_) | Sid::VrqTopLevel(_)))
                    .for_each(|sid| {
                        let delta = disc(sid) - disc(tl);
                        attrs.insert(Integer(delta), sid.to_cbor().unwrap());
                    });

                Map(attrs)
            })])))
        } else {
            println!("to_cbor(): not a CBOR vch/vrq instance");

            None
        }
    }
}

impl TryFrom<CborType> for SidData {
    type Error = ();

    fn try_from(sidhash: CborType) -> Result<Self, Self::Error> {
        from_sidhash(sidhash).ok_or(())
    }
}

fn from_sidhash(sidhash: CborType) -> Option<SidData> {
    use super::cose_sig::map_value_from;
    use CborType::*;

    let (is_vrq, btmap, sid_tl_disc, sid_tl) =
        if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VCH_TOP_LEVEL)) {
            (false, btmap, SID_VCH_TOP_LEVEL, Sid::VchTopLevel(TopLevel::VoucherVoucher))
        } else if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VRQ_TOP_LEVEL)) {
            (true, btmap, SID_VRQ_TOP_LEVEL, Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher))
        } else {
            return None;
        };

    let mut sd = if is_vrq { SidData::new_vrq() } else { SidData::new_vch() };
    sd.replace(sid_tl);

    btmap.iter()
        .filter_map(|(k, v)| if let Integer(delta) = k { Some((sid_tl_disc + delta, v)) } else { None })
        .map(|(sid_disc, v)| Sid::try_from(
            (Yang::try_from((v, sid_disc)).unwrap(), sid_disc)).unwrap())
        .for_each(|sid| sd.replace(sid));

    Some(sd)
}

//

pub fn content_comp(a: &[u8], b: &[u8]) -> bool {
    let sum = |v: &[u8]| -> u32 { v.iter().map(|b| *b as u32).sum() };

    a.len() == b.len() && sum(a) == sum(b)
}

pub fn vrhash_sidhash_content_02_00_2e() -> Vec<u8> {
    vec![161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]
}

#[test]
fn test_sid_02_00_2e() {
    assert_eq!(disc(&Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)), 1001154);
    assert_eq!(disc(&Sid::VrqAssertion(Yang::Enumeration(YangEnum::Proximity))), 1001155);
    assert_eq!(disc(&Sid::VrqCreatedOn(Yang::DateAndTime(1635218340))), 1001156);
    assert_eq!(disc(&Sid::VrqNonce(Yang::Binary(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]))),
               1001161);

    let serial_02_00_2e = "00-D0-E5-02-00-2E".as_bytes();
    assert_eq!(serial_02_00_2e, [48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69]);
    assert_eq!(disc(&Sid::VrqSerialNumber(Yang::String(serial_02_00_2e.to_vec()))), 1001164);
}

#[test]
fn test_sid_data_vch_02_00_2e() {
    let _sd_vch = SidData::vch_from(BTreeSet::from([
        // ...
    ]));

    // TODO
}

#[test]
fn test_sid_data_vrq_02_00_2e() {
    let sd_vrq = SidData::vrq_from(BTreeSet::from([
        Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher),
        Sid::VrqAssertion(Yang::Enumeration(YangEnum::Proximity)),
        Sid::VrqCreatedOn(Yang::DateAndTime(1635218340)),
        Sid::VrqNonce(Yang::Binary(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103])),
        Sid::VrqSerialNumber(Yang::String("00-D0-E5-02-00-2E".as_bytes().to_vec())),
    ]));

    println!("sd_vrq: {:?}", sd_vrq);
    assert!(content_comp(&sd_vrq.serialize().unwrap(),
                         &vrhash_sidhash_content_02_00_2e()));
}

#[test]
fn test_sid_cbor_boolean() {
    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(false));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(true));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(false));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(true));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));

    assert_eq!(CborType::Null.serialize(), vec![246]); // FYI
}
