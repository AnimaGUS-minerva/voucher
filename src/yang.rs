use crate::{Box, Vec};
use super::sid::{CborType, Cbor, SidDisc};
use core::convert::TryFrom;

use super::attr::Attr;

pub type YangDisc = u8;
pub const YANG_DATE_AND_TIME: YangDisc =  0x00; // 'yang:date-and-time'
pub const YANG_STRING: YangDisc =         0x01; // 'string'
pub const YANG_BINARY: YangDisc =         0x02; // 'binary'
pub const YANG_BOOLEAN: YangDisc =        0x03; // 'boolean'
pub const YANG_ENUMERATION: YangDisc =    0x04; // 'enumeration'

#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    //%%%% DateAndTime(u64) =       YANG_DATE_AND_TIME,
    // String(Vec<u8>) =        YANG_STRING,
    // Binary(Vec<u8>) =        YANG_BINARY,
    // Boolean(bool) =          YANG_BOOLEAN,
    // Enumeration(YangEnum) =  YANG_ENUMERATION,
    DateAndTime(Attr) =  YANG_DATE_AND_TIME,
    String(Attr) =       YANG_STRING,
    Binary(Attr) =       YANG_BINARY,
    Boolean(Attr) =      YANG_BOOLEAN,
    Enumeration(Attr) =  YANG_ENUMERATION,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum YangEnum {
    Verified,
    Logged,
    Proximity,
}

impl YangEnum {
    const fn value(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Logged => "logged",
            Self::Proximity => "proximity",
        }
    }
}

//%%%% impl Yang {
//     pub fn to_dat(&self) -> Option<u64> {
//         if let Yang::DateAndTime(x) = self { Some(*x) } else { None }
//     }
//     pub fn to_string(&self) -> Option<Vec<u8>> {
//         if let Yang::String(x) = self { Some(x.clone()) } else { None }
//     }
//     pub fn to_binary(&self) -> Option<Vec<u8>> {
//         if let Yang::Binary(x) = self { Some(x.clone()) } else { None }
//     }
//     pub fn to_boolean(&self) -> Option<bool> {
//         if let Yang::Boolean(x) = self { Some(*x) } else { None }
//     }
// }

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

//%%%% impl TryFrom<(&CborType, YangDisc)> for Yang {
//     type Error = ();
//
//     fn try_from(input: (&CborType, YangDisc)) -> Result<Self, Self::Error> {
//         use CborType::*;
//
//         match input {
//             (Tag(tag, bx), YANG_DATE_AND_TIME) => {
//                 if *tag != CBOR_TAG_UNIX_TIME { return Err(()) }
//                 if let Integer(dat) = **bx { Ok(Yang::DateAndTime(dat)) } else { Err(()) }
//             },
//             (Bytes(x), YANG_STRING) /* permissive */ | (StringAsBytes(x), YANG_STRING) =>
//                 Ok(Yang::String(x.to_vec())),
//             (StringAsBytes(x), YANG_BINARY) /* permissive */ | (Bytes(x), YANG_BINARY) =>
//                 Ok(Yang::Binary(x.to_vec())),
//             (True, YANG_BOOLEAN) => Ok(Yang::Boolean(true)),
//             (False, YANG_BOOLEAN) => Ok(Yang::Boolean(false)),
//             (StringAsBytes(x), YANG_ENUMERATION) => {
//                 let cands = [
//                     YangEnum::Verified,
//                     YangEnum::Logged,
//                     YangEnum::Proximity,
//                 ];
//                 let residue: Vec<_> = cands.iter()
//                     .enumerate()
//                     .filter_map(|(i, ye)| if ye.value().as_bytes() == x { Some(cands[i]) } else { None })
//                     .collect();
//                 if residue.len() == 1 { Ok(Yang::Enumeration(residue[0])) } else { Err(()) }
//             },
//             _ => Err(()),
//         }
//     }
// }

impl TryFrom<(&CborType, SidDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, SidDisc)) -> Result<Self, Self::Error> {
        use super::sid::*;
        use super::attr::*;

        //====
        let (cbor, sid_disc) = input;
        let yg = match sid_disc {
            SID_VCH_ASSERTION | SID_VRQ_ASSERTION =>
                Yang::Enumeration(Attr::try_from((cbor, ATTR_ASSERTION))?),
            SID_VCH_CREATED_ON | SID_VRQ_CREATED_ON =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_CREATED_ON))?),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS | SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS =>
                Yang::Boolean(Attr::try_from((cbor, ATTR_DOMAIN_CERT_REVOCATION_CHECKS))?),
            SID_VCH_EXPIRES_ON | SID_VRQ_EXPIRES_ON =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_EXPIRES_ON))?),
            SID_VCH_IDEVID_ISSUER | SID_VRQ_IDEVID_ISSUER =>
                Yang::Binary(Attr::try_from((cbor, ATTR_IDEVID_ISSUER))?),
            SID_VCH_LAST_RENEWAL_DATE | SID_VRQ_LAST_RENEWAL_DATE =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_LAST_RENEWAL_DATE))?),
            SID_VCH_NONCE | SID_VRQ_NONCE =>
                Yang::Binary(Attr::try_from((cbor, ATTR_NONCE))?),
            SID_VCH_PINNED_DOMAIN_CERT | SID_VRQ_PINNED_DOMAIN_CERT =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_CERT))?),
            SID_VCH_PINNED_DOMAIN_PUBK =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_PUBK))?),
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_PUBK_SHA256))?),
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST))?),
            SID_VRQ_PROXIMITY_REGISTRAR_CERT =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_CERT))?),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_PUBK))?),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256))?),
            SID_VCH_SERIAL_NUMBER | SID_VRQ_SERIAL_NUMBER =>
                Yang::String(Attr::try_from((cbor, ATTR_SERIAL_NUMBER))?),
            _ => return Err(()),
        };

        Ok(yg)
        //==== %%%%
        // let (cbor, sid_disc) = input;
        // match sid_disc {
        //     SID_VCH_ASSERTION |
        //     SID_VRQ_ASSERTION =>
        //         Yang::try_from((cbor, YANG_ENUMERATION)),
        //     SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS |
        //     SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS =>
        //         Yang::try_from((cbor, YANG_BOOLEAN)),
        //     SID_VCH_CREATED_ON |
        //     SID_VCH_EXPIRES_ON |
        //     SID_VCH_LAST_RENEWAL_DATE |
        //     SID_VRQ_CREATED_ON |
        //     SID_VRQ_EXPIRES_ON |
        //     SID_VRQ_LAST_RENEWAL_DATE =>
        //         Yang::try_from((cbor, YANG_DATE_AND_TIME)),
        //     SID_VCH_IDEVID_ISSUER |
        //     SID_VCH_NONCE |
        //     SID_VCH_PINNED_DOMAIN_CERT |
        //     SID_VCH_PINNED_DOMAIN_PUBK |
        //     SID_VCH_PINNED_DOMAIN_PUBK_SHA256 |
        //     SID_VRQ_IDEVID_ISSUER |
        //     SID_VRQ_NONCE |
        //     SID_VRQ_PINNED_DOMAIN_CERT |
        //     SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST |
        //     SID_VRQ_PROXIMITY_REGISTRAR_CERT |
        //     SID_VRQ_PROXIMITY_REGISTRAR_PUBK |
        //     SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 =>
        //         Yang::try_from((cbor, YANG_BINARY)),
        //     SID_VCH_SERIAL_NUMBER |
        //     SID_VRQ_SERIAL_NUMBER =>
        //         Yang::try_from((cbor, YANG_STRING)),
        //     _ => Err(()),
        // }
    }
}

impl Cbor for Yang {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        /* zzz ttt
        let cbor = match self {
            Yang::DateAndTime(x) => Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x))),
            Yang::String(x) => StringAsBytes(x.clone()),
            Yang::Binary(x) => Bytes(x.clone()),
            Yang::Boolean(x) => if *x { True } else { False },
            Yang::Enumeration(x) => StringAsBytes(x.value().as_bytes().to_vec()),
        };
         */ let cbor = Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(4242))); // todo: Cbor for Attr

        Some(cbor)
    }
}
/* zzz
#[test]
fn test_yang_conversion() {
    use core::convert::TryInto;

    let ref cbor = CborType::Tag(CBOR_TAG_UNIX_TIME, Box::new(CborType::Integer(42)));
    assert_eq!(Yang::try_from((cbor, YANG_DATE_AND_TIME)), Ok(Yang::DateAndTime(42)));

    let result: Result<Yang, ()> = (cbor, YANG_DATE_AND_TIME).try_into();
    assert_eq!(result, Ok(Yang::DateAndTime(42)));

    // TODO tests for other YANG variants
}
*/