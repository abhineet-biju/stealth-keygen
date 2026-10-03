<h1 align="center">stealth-keygen</h1>

`stealth-keygen` is a Rust library for generating recipient spend and scan keypairs, deriving one-time payment public keys, recovering their private signing scalars, and signing messages with the recovered keys. A sender uses the recipient's public keys and fresh randomness or a supplied ephemeral secret to derive a destination and a public announcement. The recipient uses their private keys and that announcement to recover the matching payment key. All key calculations happen off-chain.

<p align="center">
  <img src="docs/images/stealth-keygen-overview.svg" alt="Recipient key setup and sender flow: ephemeral key generation, X25519 shared-secret agreement, discovery tag and tweak derivation, and one-time payment public key" width="600" />
</p>

A matching discovery tag identifies a candidate; the recipient must check the destination authority before accepting a payment.

This library explores stealth key generation as a step toward building our Turbin3 Builders capstone project.

## Key notation

Lowercase symbols denote private keys; uppercase symbols denote public keys.

| Private | Public | Purpose |
|---|---|---|
| `a` | `A` | Recipient's long-term Ed25519 spend key. |
| `b` | `B` | Recipient's long-term X25519 scan key. |
| `r` | `R` | Ephemeral X25519 key for one payment. |
| `e` | `E` | Account's ElGamal key, with `E = e⁻¹·H` using the SDK's Pedersen generator `H`. |
| `p` | `P` | One-time Ed25519 payment signing key. |

The Ed25519 signing nonce and nonce point are denoted `r_sig` and `R_sig`,
separate from the ephemeral X25519 keys. These symbols match the diagram;
they do not change the API or serialized bytes.

## Key derivation

`derive_payment(&public_keys, &mut rng)` uses HKDF-SHA256 with the fixed public
salt `stealth-keygen-v3`. Every expansion binds the exact 32-byte ephemeral
public key `R` from the announcement:

```text
PRK    = Extract("stealth-keygen-v3", S)
tag    = Expand(PRK, "discovery-tag" || R, 1)
t      = reduce_mod_l(Expand(PRK, "spend-tweak" || R, 64))
ct_ikm = Expand(PRK, "ct-ikm-v1" || R || C, 32)
C      = chain_id || program_id || mint || token_account
```

`derive_payment_with_ephemeral(&public_keys, &ephemeral)` uses the same schedule
with caller-supplied X25519 secret material. `EphemeralSecret::from_bytes(r)`
imports 32 secret bytes; X25519 applies clamping during key derivation. The
wrapper clears its secret on drop and has no `Debug`, `Clone` or `Copy`.
Callers must protect any copies of the input bytes separately.

The same recipient and ephemeral secret reconstruct the same `SenderPayment`:
`payment_public_key` is P, and `announcement` contains R and the discovery tag.
R is available as `payment.announcement.ephemeral_public_key`. Derive the
token-account address from R, then build the confidential context and call
`derive_ct_ikm`. The supplied-secret API returns `DeriveError`; the random API
also reports RNG failures through `SenderError`.

Use a fresh ephemeral key for each distinct payment. Reuse it only to rebuild
that payment, such as when resuming a payout row. Run-secret derivation and
storage belong to the client and remain planned; this API does not generate or
persist a run secret.

Each context field is 32 bytes. Both parties derive the same `ct_ikm` with
`derive_ct_ikm(&context)`. The consuming application passes
`material.as_bytes()` to `solana_zk_sdk::encryption::derivation::derive_confidential_keys_from_ikm`,
which uses HKDF-SHA512 to derive an ElGamal keypair and a symmetric `AeKey`.
The library has no production dependency on the SDK; interoperability tests use 7.0.1.

`ConfidentialKeyMaterial` clears its buffer on drop and has no `Debug`, `Clone`,
or `Copy` implementation. Its bytes are secret. Disclosing them grants the
account's full read access, but does not reveal the payment signing scalar.
A receipt verifier must compare the derived ElGamal public key with the
referenced transaction. The client must also check a decrypted balance hint
against the ElGamal balance before trusting it.

This schedule is incompatible with the earlier SHA-256 and unbound HKDF
versions. Both parties must upgrade together; announcements carry no scheme
identifier. Account creation, proofs, and receipt verification belong to the client.

## Public API

| Function or method | Purpose |
|---|---|
| `RecipientSecretKeys::generate(&mut rng)` | Generate the recipient's private spend and scan keys. |
| `recipient.derive_public_keys()` | Obtain the public keys shared with senders. |
| `public_keys.spend_public_key_bytes()` | Export the public spend key as 32 bytes. |
| `public_keys.scan_public_key_bytes()` | Export the public scan key as 32 bytes. |
| `derive_payment(&public_keys, &mut rng)` | Derive a one-time payment public key and discovery announcement. |
| `EphemeralSecret::from_bytes(bytes)` | Import protected X25519 secret material for one payment. |
| `derive_payment_with_ephemeral(&public_keys, &ephemeral)` | Reconstruct a payment from supplied ephemeral secret material. |
| `recover_payment(&secret_keys, &announcement)` | Recover a candidate payment; returns `Ok(None)` if the discovery tag does not match. |
| `recovered.sign(message)` | Sign message bytes with the recovered payment key. |
| `payment.derive_ct_ikm(&context)` | Derive protected input for the account's confidential keys. |
| `material.as_bytes()` | Borrow secret bytes for SDK derivation or deliberate disclosure. |
| `ConfidentialKeyMaterial::from_bytes(bytes)` | Import disclosed material for client-side verification. |

Confidential-material derivation is available on both `SenderPayment` and
`RecoveredPayment`. Both parties must supply the same `ConfidentialContext`,
containing the chain genesis hash, application program ID, mint, and token-account
address as 32-byte fields.

## Dependencies

- `curve25519-dalek`: Edwards point and scalar arithmetic for spend and payment keys.
- `hkdf`: HKDF-SHA256 extraction and expansion for discovery tags, spending tweaks, and confidential key material.
- `rand_core`: Cryptographic RNG traits for generating key material.
- `sha2`: SHA-2 hashing for discovery tags, scalar tweaks, and signing.
- `x25519-dalek`: X25519 key agreement, with the `static_secrets` feature enabled.
- `zeroize`: Clearing sensitive key material and temporary buffers from memory.

## Tests

Run `cargo test --locked` for unit tests and the public payment-flow integration
tests. Signatures are checked with `ed25519-dalek`, a test-only dependency.
SDK interoperability and disclosure tests also run with that command;
`solana-zk-sdk` is a test-only dependency. Fixed vectors and their independent
Python generator are documented in
[tests/fixtures/README.md](tests/fixtures/README.md).
