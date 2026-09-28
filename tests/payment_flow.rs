//! Exercise the same exported API an external application uses.

#[path = "../src/test_support.rs"]
mod support;

use ed25519_dalek::{Signature, VerifyingKey};
use stealth_keygen::{
    DeriveError, PaymentAnnouncement, RecipientError, RecipientSecretKeys, RecoveredPayment,
    SenderError, derive_payment, recover_payment,
};
use support::{ScriptedRng, TestRngError, identity_rng, payment_rng, vector};

fn encryption_context() -> stealth_keygen::ElGamalContext {
    stealth_keygen::ElGamalContext {
        chain_id: [1; 32],
        program_id: [2; 32],
        mint: [3; 32],
        token_account: [4; 32],
    }
}

#[test]
fn sender_and_recipient_derive_usable_elgamal_keys() {
    let recipient = recipient(1, 2);
    let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
    let recovered = recover_payment(&recipient, &sent.announcement)
        .unwrap()
        .unwrap();
    let context = encryption_context();
    let sender_keys = sent.derive_elgamal_keypair(&context).unwrap();
    let recipient_keys = recovered.derive_elgamal_keypair(&context).unwrap();
    assert_eq!(sender_keys.pubkey(), recipient_keys.pubkey());
    assert_eq!(sender_keys.secret(), recipient_keys.secret());
    assert_eq!(
        sender_keys.secret().as_bytes(),
        &vector::<32>("elgamal_scalar")
    );
    for amount in [0u64, 1, 42, 65_535] {
        let ciphertext = sender_keys.pubkey().encrypt_u64(amount);
        assert_eq!(
            recipient_keys.secret().decrypt_u32(&ciphertext),
            Some(amount)
        );
    }
    // A consuming application can produce/verify proofs without library wrappers.
    use solana_zk_sdk::zk_elgamal_proof_program::{
        VerifyZkProof, build_pubkey_validity_proof_data,
    };
    let proof = build_pubkey_validity_proof_data(&sender_keys).unwrap();
    proof.verify_proof().unwrap();
}

#[test]
fn elgamal_is_deterministic_and_separate_for_each_payment() {
    let recipient = recipient(1, 2);
    let public = recipient.derive_public_keys();
    let context = encryption_context();
    let a = derive_payment(&public, &mut payment_rng()).unwrap();
    let b = derive_payment(&public, &mut ScriptedRng::new(vec![4; 32])).unwrap();
    assert_eq!(
        a.derive_elgamal_keypair(&context).unwrap().pubkey(),
        a.derive_elgamal_keypair(&context).unwrap().pubkey()
    );
    assert_ne!(
        a.derive_elgamal_keypair(&context).unwrap().pubkey(),
        b.derive_elgamal_keypair(&context).unwrap().pubkey()
    );
}

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

#[test]
fn balance_keys_agree_and_encrypt_full_u64_balances() {
    let recipient = recipient(1, 2);
    let sent = derive_payment(&recipient.derive_public_keys(), &mut payment_rng()).unwrap();
    let recovered = recover_payment(&recipient, &sent.announcement)
        .unwrap()
        .unwrap();
    let context = encryption_context();
    let sender_key = sent.derive_balance_key(&context).unwrap();
    let recipient_key = recovered.derive_balance_key(&context).unwrap();
    assert_eq!(sender_key, recipient_key);
    for amount in [0, 1, 42, u32::MAX as u64, u64::MAX] {
        assert_eq!(
            recipient_key.decrypt(&sender_key.encrypt(amount)),
            Some(amount)
        );
        assert_eq!(
            sender_key.decrypt(&recipient_key.encrypt(amount)),
            Some(amount)
        );
    }
}

#[test]
fn balance_key_recovery_is_deterministic_and_payment_specific() {
    let recipient = recipient(1, 2);
    let public = recipient.derive_public_keys();
    let a = derive_payment(&public, &mut payment_rng()).unwrap();
    let b = derive_payment(&public, &mut ScriptedRng::new(vec![4; 32])).unwrap();
    let context = encryption_context();
    let original = a.derive_balance_key(&context).unwrap();
    let recovered = recover_payment(&recipient, &a.announcement)
        .unwrap()
        .unwrap();
    assert_eq!(original, a.derive_balance_key(&context).unwrap());
    assert_eq!(original, recovered.derive_balance_key(&context).unwrap());
    let other = b.derive_balance_key(&context).unwrap();
    assert_ne!(original, other);
    assert_eq!(other.decrypt(&original.encrypt(42)), None);
}

#[test]
fn balance_encryption_rejects_wrong_context_and_modified_ciphertext() {
    use solana_zk_sdk::encryption::auth_encryption::AeCiphertext;
    let recovered = payment();
    let context = encryption_context();
    let key = recovered.derive_balance_key(&context).unwrap();
    let ciphertext = key.encrypt(42);
    let mut changed = context;
    changed.token_account[0] ^= 1;
    assert_eq!(
        recovered
            .derive_balance_key(&changed)
            .unwrap()
            .decrypt(&ciphertext),
        None
    );
    let original = ciphertext.to_bytes();
    for i in 0..original.len() {
        let mut corrupted = original;
        corrupted[i] ^= 1;
        let parsed = AeCiphertext::from_bytes(&corrupted).unwrap();
        assert_eq!(key.decrypt(&parsed), None);
    }
}
