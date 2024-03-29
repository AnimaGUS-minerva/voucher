#[allow(unused_imports)]
use crate::{Vec, SignatureAlgorithm};

#[cfg(any(feature = "mbedtls-backend", feature = "sign", feature = "validate"))]
pub mod minerva_mbedtls_utils {
    use super::*;
    use minerva_mbedtls::{psa_crypto, psa_ifce::*, mbedtls_error};

    /// Initializes the [PSA cryptography API](https://armmbed.github.io/mbed-crypto/html/)
    /// context.  Call this function when using the `Sign`/`Validate` trait backed by mbedtls.
    pub fn init_psa_crypto() {
        psa_crypto::init().unwrap();
        psa_crypto::initialized().unwrap();
    }

    pub fn compute_digest(msg: &[u8], alg: &SignatureAlgorithm) -> (md_type_t, Vec<u8>) {
        let ty = match *alg {
            SignatureAlgorithm::ES256 => MD_SHA256,
            SignatureAlgorithm::ES384 => MD_SHA384,
            SignatureAlgorithm::ES512 => MD_SHA512,
            SignatureAlgorithm::PS256 => unimplemented!("handle PS256"),
        };

        (ty, md_info::from_type(ty).md(msg))
    }

    pub fn pk_from_privkey_pem(pem: &[u8], f_rng: Option<FnRng>) -> Result<pk_context, mbedtls_error> {
        let mut pk = pk_context::new();
        pk.parse_key(pem, None, f_rng, core::ptr::null_mut())?;

        Ok(pk)
    }
}
