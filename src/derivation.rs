//! Shared cryptographic calculations for stealth payments.
//!
//! Uses HKDF-SHA256 with a fixed public salt and separate purpose labels.

use curve25519_dalek::{EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{
    PublicKey as X25519PublicKey, SharedSecret as X25519SharedSecret, StaticSecret as X25519Secret,
};
use zeroize::{Zeroize, Zeroizing};

/// Protocol constants. Changing these bytes changes the derived addresses.
const HKDF_SALT: &[u8] = b"stealth-keygen-v3";
const DISCOVERY_INFO: &[u8] = b"discovery-tag";
const TWEAK_INFO: &[u8] = b"spend-tweak";
const CT_IKM_INFO: &[u8] = b"ct-ikm-v1";

/// Public account context for ElGamal and symmetric balance keys.
/// Both parties must use identical values.
/// `chain_id` is the cluster genesis hash; the remaining fields are addresses.
/// Encoding: chain_id || program_id || mint || token_account, each 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfidentialContext {
    pub chain_id: [u8; 32],
    pub program_id: [u8; 32],
    pub mint: [u8; 32],
    pub token_account: [u8; 32],
}

impl ConfidentialContext {
    fn encode(&self) -> [u8; 128] {
        let mut bytes = [0; 128];
        for (chunk, field) in bytes.chunks_exact_mut(32).zip([
            &self.chain_id,
            &self.program_id,
            &self.mint,
            &self.token_account,
        ]) {
            chunk.copy_from_slice(field);
        }
        bytes
    }
}

/// Secret input for deriving one account's ElGamal and symmetric keys.
/// Disclosure grants full read access to that account, but not signing authority.
/// Cleared on drop; intentionally does not implement Debug, Clone, or Copy.
pub struct ConfidentialKeyMaterial(Zeroizing<[u8; 32]>);

impl ConfidentialKeyMaterial {
    /// Import disclosed material. A receipt verifier must authenticate the derived
    /// ElGamal public key against the referenced account or transaction.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow secret bytes for SDK derivation or deliberate disclosure.
    /// Any copies made by the caller must be protected separately.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    InvalidSharedSecret,
    InvalidSpendPublicKey,
    InvalidPaymentPublicKey,
    InvalidKdfOutputLength,
}

/// A shared secret that has passed the X25519 contributory check.
///
/// The field is private so callers cannot construct an unchecked value.
/// Intentionally does not implement Debug, Clone, or Copy.
pub(crate) struct PaymentSharedSecret {
    secret: X25519SharedSecret,
    ephemeral_public_key: [u8; 32],
}

impl PaymentSharedSecret {
    /// Compute a shared secret and reject an all-zero result.
    /// Bind the exact sender ephemeral bytes from the announcement on both sides.
    /// Do not normalize R: X25519 accepts distinct encodings with the same secret.
    ///
    /// Sender:
    ///     derive_secret(ephemeral_secret, recipient_scan_public_key, R)
    /// Recipient:
    ///     derive_secret(recipient_scan_secret, ephemeral_public_key, R)
    pub(crate) fn derive_secret(
        own_secret: &X25519Secret,
        peer_public: &X25519PublicKey,
        ephemeral_public_key: &[u8; 32],
    ) -> Result<Self, DeriveError> {
        let shared = own_secret.diffie_hellman(peer_public);

        if !shared.was_contributory() {
            return Err(DeriveError::InvalidSharedSecret);
        }

        Ok(Self {
            secret: shared,
            ephemeral_public_key: *ephemeral_public_key,
        })
    }

    /// Derive the public one-byte discovery filter.
    /// HKDF-Expand(PRK, "discovery-tag" || R, 1)
    pub(crate) fn discovery_tag(&self) -> Result<u8, DeriveError> {
        let mut tag = [0u8; 1];
        self.expand(DISCOVERY_INFO, &[], &mut tag)?;
        Ok(tag[0])
    }

    /// Derive the private scalar tweak from 64 HKDF output bytes.
    /// Interpret the output as a little-endian integer and reduce modulo l.
    pub(crate) fn tweak(&self) -> Result<Zeroizing<Scalar>, DeriveError> {
        let mut wide = Zeroizing::new([0u8; 64]);
        self.expand(TWEAK_INFO, &[], &mut wide[..])?;
        Ok(Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide)))
    }

    /// Derive account-scoped input for the client's confidential-key SDK.
    pub(crate) fn ct_ikm(
        &self,
        context: &ConfidentialContext,
    ) -> Result<ConfidentialKeyMaterial, DeriveError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        self.expand(CT_IKM_INFO, &context.encode(), &mut bytes[..])?;
        Ok(ConfidentialKeyMaterial(bytes))
    }

    /// Expand with info = purpose || R || context, using fixed-width public fields.
    /// Repeating extraction reconstructs the same PRK without retaining another
    /// long-lived secret. Callers keep secret output buffers zeroizing.
    fn expand(&self, purpose: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), DeriveError> {
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), self.secret.as_bytes());
        prk[..].zeroize();
        hkdf.expand_multi_info(&[purpose, &self.ephemeral_public_key, context], output)
            .map_err(|_| DeriveError::InvalidKdfOutputLength)
    }
}

/// Derive the one-time payment public key:
///
/// P = B + t·G
///
/// Rejects an invalid recipient spend point and an identity result.
pub(crate) fn payment_public_key(
    recipient_spend: &EdwardsPoint,
    tweak: &Scalar,
) -> Result<EdwardsPoint, DeriveError> {
    // Accept only nonidentity points in the prime-order subgroup.
    if recipient_spend.is_small_order() || !recipient_spend.is_torsion_free() {
        return Err(DeriveError::InvalidSpendPublicKey);
    }

    let payment = recipient_spend + (tweak * ED25519_BASEPOINT_POINT);

    // Both terms are in the prime-order subgroup. Their sum could
    // still be the identity if their scalars cancel.
    if payment.is_small_order() {
        return Err(DeriveError::InvalidPaymentPublicKey);
    }

    Ok(payment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{hex, vector};
    use curve25519_dalek::constants::EIGHT_TORSION;

    fn encryption_context() -> ConfidentialContext {
        ConfidentialContext {
            chain_id: [1; 32],
            program_id: [2; 32],
            mint: [3; 32],
            token_account: [4; 32],
        }
    }

    fn shared_secret() -> PaymentSharedSecret {
        PaymentSharedSecret::derive_secret(
            &X25519Secret::from(vector::<32>("ephemeral_entropy")),
            &X25519PublicKey::from(vector::<32>("scan_public")),
            &vector::<32>("ephemeral_public"),
        )
        .unwrap()
    }

    #[test]
    fn equivalent_ephemeral_encodings_have_distinct_derivations() {
        let scan = X25519Secret::from([2; 32]);
        let r = X25519PublicKey::from(&X25519Secret::from([3; 32])).to_bytes();
        let mut alias = r;
        alias[31] ^= 0x80; // X25519 ignores this bit; our transcript must not.
        let original =
            PaymentSharedSecret::derive_secret(&scan, &X25519PublicKey::from(r), &r).unwrap();
        let modified =
            PaymentSharedSecret::derive_secret(&scan, &X25519PublicKey::from(alias), &alias)
                .unwrap();
        assert_eq!(original.secret.as_bytes(), modified.secret.as_bytes());
        assert_ne!(
            original.tweak().unwrap().to_bytes(),
            modified.tweak().unwrap().to_bytes()
        );
        let context = encryption_context();
        assert_ne!(
            original.ct_ikm(&context).unwrap().as_bytes(),
            modified.ct_ikm(&context).unwrap().as_bytes()
        );
        // A one-byte discovery tag can collide; it is not an identity check.
    }

    #[test]
    fn ct_ikm_matches_independent_vector_and_is_domain_separated() {
        let shared = shared_secret();
        let context = encryption_context();
        assert_eq!(context.encode(), vector::<128>("confidential_context"));
        let material = shared.ct_ikm(&context).unwrap();
        assert_eq!(material.as_bytes(), &vector::<32>("ct_ikm"));
        assert_eq!(
            material.as_bytes(),
            shared.ct_ikm(&context).unwrap().as_bytes()
        );
        assert_ne!(material.as_bytes(), &shared.tweak().unwrap().to_bytes());
        let mut other_purpose = [0; 32];
        shared
            .expand(TWEAK_INFO, &context.encode(), &mut other_purpose)
            .unwrap();
        assert_ne!(material.as_bytes(), &other_purpose);
        let imported = ConfidentialKeyMaterial::from_bytes(*material.as_bytes());
        assert_eq!(imported.as_bytes(), material.as_bytes());
    }

    #[test]
    fn ct_ikm_binds_every_context_field() {
        let shared = shared_secret();
        let base = encryption_context();
        let material = shared.ct_ikm(&base).unwrap();
        for field in 0..4 {
            let mut changed = base;
            match field {
                0 => changed.chain_id[0] ^= 1,
                1 => changed.program_id[0] ^= 1,
                2 => changed.mint[0] ^= 1,
                _ => changed.token_account[0] ^= 1,
            }
            assert_ne!(
                material.as_bytes(),
                shared.ct_ikm(&changed).unwrap().as_bytes()
            );
        }
    }

    #[test]
    fn hkdf_matches_rfc5869_case_one() {
        let (mut prk, hkdf) =
            Hkdf::<Sha256>::extract(Some(&(0u8..13).collect::<Vec<_>>()), &[0x0b; 22]);
        assert_eq!(
            prk[..],
            hex::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut output = [0; 42];
        hkdf.expand(&(0xf0u8..0xfa).collect::<Vec<_>>(), &mut output)
            .unwrap();
        assert_eq!(
            output,
            hex::<42>(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        prk[..].zeroize();
    }

    #[test]
    fn prk_tag_and_tweak_match_independent_vector() {
        let scan = X25519Secret::from(vector::<32>("scan_entropy"));
        let ephemeral = X25519Secret::from(vector::<32>("ephemeral_entropy"));
        let sender = PaymentSharedSecret::derive_secret(
            &ephemeral,
            &X25519PublicKey::from(&scan),
            &X25519PublicKey::from(&ephemeral).to_bytes(),
        )
        .unwrap();
        let recipient = PaymentSharedSecret::derive_secret(
            &scan,
            &X25519PublicKey::from(&ephemeral),
            &X25519PublicKey::from(&ephemeral).to_bytes(),
        )
        .unwrap();
        let (mut prk, _) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), sender.secret.as_bytes());
        assert_eq!(prk[..], vector::<32>("hkdf_prk"));
        prk[..].zeroize();
        let mut wide = Zeroizing::new([0; 64]);
        sender.expand(TWEAK_INFO, &[], &mut wide[..]).unwrap();
        assert_eq!(*wide, vector::<64>("tweak_material"));
        for secret in [&sender, &recipient] {
            assert_eq!(
                secret.discovery_tag().unwrap(),
                vector::<1>("discovery_tag")[0]
            );
            assert_eq!(secret.tweak().unwrap().to_bytes(), vector::<32>("tweak"));
        }
    }

    #[test]
    fn purposes_are_separated_and_invalid_expansion_length_fails() {
        let secret = PaymentSharedSecret::derive_secret(
            &X25519Secret::from([3; 32]),
            &X25519PublicKey::from(&X25519Secret::from([2; 32])),
            &X25519PublicKey::from(&X25519Secret::from([3; 32])).to_bytes(),
        )
        .unwrap();
        let mut discovery = Zeroizing::new([0; 64]);
        let mut tweak = Zeroizing::new([0; 64]);
        secret
            .expand(DISCOVERY_INFO, &[], &mut discovery[..])
            .unwrap();
        secret.expand(TWEAK_INFO, &[], &mut tweak[..]).unwrap();
        assert_ne!(*discovery, *tweak);
        let mut oversized = Zeroizing::new(vec![0; 255 * 32 + 1]);
        assert_eq!(
            secret.expand(TWEAK_INFO, &[], &mut oversized[..]),
            Err(DeriveError::InvalidKdfOutputLength)
        );
    }

    #[test]
    fn rfc7748_shared_secret_matches() {
        let a = X25519Secret::from(hex::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = X25519PublicKey::from(hex::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let secret =
            PaymentSharedSecret::derive_secret(&a, &b, &X25519PublicKey::from(&a).to_bytes())
                .unwrap();
        assert_eq!(
            secret.secret.to_bytes(),
            hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn low_order_x25519_inputs_are_rejected() {
        let secret = X25519Secret::from([9; 32]);
        for encoding in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let peer = X25519PublicKey::from(hex::<32>(encoding));
            assert!(matches!(
                PaymentSharedSecret::derive_secret(&secret, &peer, &peer.to_bytes()),
                Err(DeriveError::InvalidSharedSecret)
            ));
        }
    }

    #[test]
    fn small_order_spend_points_are_rejected() {
        for point in EIGHT_TORSION {
            assert_eq!(
                payment_public_key(&point, &Scalar::ONE),
                Err(DeriveError::InvalidSpendPublicKey)
            );
        }
    }

    #[test]
    fn mixed_torsion_spend_points_are_rejected() {
        for torsion in EIGHT_TORSION.iter().skip(1) {
            assert_eq!(
                payment_public_key(&(ED25519_BASEPOINT_POINT + torsion), &Scalar::ONE),
                Err(DeriveError::InvalidSpendPublicKey)
            );
        }
    }

    #[test]
    fn cancellation_to_identity_is_rejected() {
        assert_eq!(
            payment_public_key(&ED25519_BASEPOINT_POINT, &(-Scalar::ONE)),
            Err(DeriveError::InvalidPaymentPublicKey)
        );
    }

    #[test]
    fn zero_tweak_preserves_valid_spend_point() {
        assert_eq!(
            payment_public_key(&ED25519_BASEPOINT_POINT, &Scalar::ZERO),
            Ok(ED25519_BASEPOINT_POINT)
        );
    }
}
