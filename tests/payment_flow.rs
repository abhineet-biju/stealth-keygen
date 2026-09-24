//! Exercise the same exported API an external application uses.

#[path = "../src/test_support.rs"]
mod support;

use ed25519_dalek::{Signature, VerifyingKey};
use stealth_keygen::{
    DeriveError, PaymentAnnouncement, RecipientError, RecipientSecretKeys, RecoveredPayment,
    SenderError, derive_payment, recover_payment,
};
use support::{ScriptedRng, TestRngError, identity_rng, payment_rng, vector};

fn recipient(spend: u8, scan: u8) -> RecipientSecretKeys {
    RecipientSecretKeys::generate(&mut ScriptedRng::new(
        [vec![spend; 64], vec![scan; 32]].concat(),
    ))
    .unwrap()
}

fn payment() -> RecoveredPayment {
    let recipient = RecipientSecretKeys::generate(&mut identity_rng()).unwrap();
    let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
    let recovered = recover_payment(&recipient, &sent.announcement)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.payment_public_key, sent.payment_public_key);
    recovered
}

#[test]
fn public_api_matches_fixed_payment_and_signature_vector() {
    let recovered = payment();
    assert_eq!(recovered.payment_public_key, vector::<32>("payment_public"));
    let message = b"stealth-keygen test vector";
    let signature = recovered.sign(message);
    assert_eq!(signature, vector::<64>("signature"));
    VerifyingKey::from_bytes(&recovered.payment_public_key)
        .unwrap()
        .verify_strict(message, &Signature::from_bytes(&signature))
        .unwrap();
}

#[test]
fn standard_verifier_accepts_multiple_keys_and_message_boundaries() {
    for seed in [1u8, 7, 31, 91, 171] {
        let recipient = recipient(seed, seed + 1);
        let sent = derive_payment(
            &recipient.derive_public_keys(),
            &mut ScriptedRng::new(vec![seed + 2; 32]),
        )
        .unwrap();
        let recovered = recover_payment(&recipient, &sent.announcement)
            .unwrap()
            .unwrap();
        let verifier = VerifyingKey::from_bytes(&sent.payment_public_key).unwrap();
        // Includes empty/binary messages and SHA-512 padding/block boundaries.
        for length in [0, 1, 31, 32, 63, 64, 111, 112, 127, 128, 129, 1232, 4096] {
            let message: Vec<_> = (0..length).map(|i| (i % 256) as u8).collect();
            verifier
                .verify_strict(&message, &Signature::from_bytes(&recovered.sign(&message)))
                .unwrap();
        }
    }
}

#[test]
fn every_incorrect_discovery_tag_is_rejected() {
    let recipient = recipient(1, 2);
    let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
    for tag in 0..=u8::MAX {
        let note = PaymentAnnouncement {
            discovery_tag: tag,
            ..sent.announcement.clone()
        };
        let result = recover_payment(&recipient, &note).unwrap();
        assert_eq!(result.is_some(), tag == sent.announcement.discovery_tag);
    }
}

#[test]
fn discovery_tag_collision_does_not_authorize_another_recipients_payment() {
    let alice = recipient(1, 2);
    let bob = recipient(8, 9);
    let sent = derive_payment(&alice.derive_public_keys(), &mut payment_rng()).unwrap();
    let verifier = VerifyingKey::from_bytes(&sent.payment_public_key).unwrap();
    let mut candidates = 0;
    // Exhaustive tags force a match for Bob without assuming random tags differ.
    for tag in 0..=u8::MAX {
        let note = PaymentAnnouncement {
            discovery_tag: tag,
            ..sent.announcement.clone()
        };
        if let Some(candidate) = recover_payment(&bob, &note).unwrap() {
            candidates += 1;
            assert_ne!(candidate.payment_public_key, sent.payment_public_key);
            assert!(
                verifier
                    .verify_strict(b"claim", &Signature::from_bytes(&candidate.sign(b"claim")))
                    .is_err()
            );
        }
    }
    assert_eq!(candidates, 1);
}

#[test]
fn invalid_ephemeral_keys_are_errors_and_do_not_prevent_later_recovery() {
    let recipient = recipient(1, 2);
    for first in [0, 1] {
        let mut ephemeral_public_key = [0; 32];
        ephemeral_public_key[0] = first;
        let note = PaymentAnnouncement {
            ephemeral_public_key,
            discovery_tag: 0,
        };
        assert!(matches!(
            recover_payment(&recipient, &note),
            Err(RecipientError::Derivation(DeriveError::InvalidSharedSecret))
        ));
    }
    let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
    assert!(
        recover_payment(&recipient, &sent.announcement)
            .unwrap()
            .is_some()
    );
}

#[test]
fn fresh_payments_have_distinct_keys_and_cannot_sign_for_each_other() {
    let recipient = recipient(1, 2);
    let public = recipient.derive_public_keys();
    let mut rng = ScriptedRng::new([vec![3; 32], vec![4; 32]].concat());
    let a = derive_payment(&public, &mut rng).unwrap();
    let b = derive_payment(&public, &mut rng).unwrap();
    assert_eq!(rng.calls, 2);
    assert_ne!(
        a.announcement.ephemeral_public_key,
        b.announcement.ephemeral_public_key
    );
    assert_ne!(a.payment_public_key, b.payment_public_key);
    let recovered = recover_payment(&recipient, &a.announcement)
        .unwrap()
        .unwrap();
    let signature = Signature::from_bytes(&recovered.sign(b"message"));
    VerifyingKey::from_bytes(&a.payment_public_key)
        .unwrap()
        .verify_strict(b"message", &signature)
        .unwrap();
    assert!(
        VerifyingKey::from_bytes(&b.payment_public_key)
            .unwrap()
            .verify_strict(b"message", &signature)
            .is_err()
    );
}

#[test]
fn signatures_are_deterministic_and_message_specific() {
    let recovered = payment();
    assert_eq!(recovered.sign(b"same"), recovered.sign(b"same"));
    assert_eq!(recovered.sign(b"same"), payment().sign(b"same"));
    assert_ne!(recovered.sign(b"one")[..32], recovered.sign(b"two")[..32]);
}

#[test]
fn altered_messages_and_signatures_are_rejected() {
    let recovered = payment();
    let verifier = VerifyingKey::from_bytes(&recovered.payment_public_key).unwrap();
    let original = recovered.sign(b"message");
    assert!(
        verifier
            .verify_strict(b"message!", &Signature::from_bytes(&original))
            .is_err()
    );
    for index in 0..64 {
        let mut signature = original;
        signature[index] ^= 1;
        assert!(
            verifier
                .verify_strict(b"message", &Signature::from_bytes(&signature))
                .is_err()
        );
    }
}

#[test]
fn public_key_field_mutation_cannot_change_the_signing_challenge() {
    let mut recovered = payment();
    let original_key = recovered.payment_public_key;
    let original_signature = recovered.sign(b"message");
    recovered.payment_public_key = recipient(8, 9)
        .derive_public_keys()
        .spend_public_key_bytes();
    assert_eq!(recovered.sign(b"message"), original_signature);
    VerifyingKey::from_bytes(&original_key)
        .unwrap()
        .verify_strict(
            b"message",
            &Signature::from_bytes(&recovered.sign(b"message")),
        )
        .unwrap();
}

#[test]
fn public_errors_preserve_randomness_failure() {
    let public = recipient(1, 2).derive_public_keys();
    let result = derive_payment(&public, &mut payment_rng().failing_on(1));
    assert!(matches!(
        result,
        Err(SenderError::Randomness(TestRngError::InjectedFailure))
    ));
}
