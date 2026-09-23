//! Sender-side derivation of one-time payment destinations.
//!
//! Uses only the recipient's public keys.
//! The sender never obtains the recipient's payment signing key.

use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::{
    derivation::{DeriveError, PaymentSharedSecret, payment_public_key},
    keys::RecipientPublicKeys,
};

/// Public discovery information for one payment.
///
/// This is an in-memory representation. A versioned wire format
/// can be defined separately when announcements are serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAnnouncement {
    pub ephemeral_public_key: [u8; 32],
    pub discovery_tag: u8,
}

/// Sender-side result for one payment.
/// Intentionally does not implement Debug, Clone, or Copy.
pub struct SenderPayment {
    /// Compressed Ed25519 public key P.
    /// These are the raw 32 bytes of the receiving authority.
    pub payment_public_key: [u8; 32],

    /// Public information needed for recipient discovery.
    pub announcement: PaymentAnnouncement,

    shared_secret: PaymentSharedSecret,
}

impl SenderPayment {
    /// Internal access for the future encryption module.
    pub(crate) fn shared_secret(&self) -> &PaymentSharedSecret {
        &self.shared_secret
    }
}

#[derive(Debug)]
pub enum SenderError<E> {
    Randomness(E),
    Derivation(DeriveError),
}

/// Derive a fresh payment destination for a recipient.
pub fn derive_payment<R>(
    recipient: &RecipientPublicKeys,
    rng: &mut R,
) -> Result<SenderPayment, SenderError<R::Error>>
where
    R: TryCryptoRng + ?Sized,
{
    // 1. Generate fresh ephemeral private material r.
    let mut ephemeral_bytes = Zeroizing::new([0u8; 32]);

    rng.try_fill_bytes(&mut ephemeral_bytes[..])
        .map_err(SenderError::Randomness)?;

    let ephemeral_secret = X25519Secret::from(*ephemeral_bytes);

    // 2. Derive the public announcement key R.
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // 3. Compute S = X25519(r, recipient_scan_public_key).
    //    derive_secret rejects an all-zero shared secret.
    let shared_secret =
        PaymentSharedSecret::derive_secret(&ephemeral_secret, recipient.scan_public_key())
            .map_err(SenderError::Derivation)?;

    // 4. Derive the public discovery tag and private tweak.
    let discovery_tag = shared_secret.discovery_tag();
    let tweak = shared_secret.tweak();

    // 5. Compute P = B + t·G.
    let payment = payment_public_key(recipient.spend_public_key(), &tweak)
        .map_err(SenderError::Derivation)?;

    // 6. Return public payment information and retain S privately
    //    for the future confidential-account encryption step.
    Ok(SenderPayment {
        payment_public_key: payment.compress().to_bytes(),
        announcement: PaymentAnnouncement {
            ephemeral_public_key: ephemeral_public.to_bytes(),
            discovery_tag,
        },
        shared_secret,
    })
}
