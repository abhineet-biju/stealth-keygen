# Test vectors

`hkdf.txt` fixes the HKDF-SHA256 PRK, discovery tag, 64-byte tweak material,
reduced tweak, recovered scalar, payment public key, and signature.
All secrets in this file are deterministic public test inputs.

The salt is `stealth-keygen-v3`; its expansion labels are `discovery-tag`
and `spend-tweak`, followed by the exact 32-byte announcement `R`. The signing domain remains `stealth-keygen-v1-nonce`.
These versioned strings are cryptographic constants, not selectable schemes.
Renaming either would change outputs. This schedule replaces the earlier unbound HKDF derivation.

Generate it with `python3 scripts/generate_test_vectors.py`. The script uses
Python's standard library and separate curve arithmetic, checked against
[RFC 7748 section 6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1),
[RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), and
[RFC 5869 appendix A.1](https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1).

The Rust tests consume committed expected values. They never regenerate them.
Changing a vector requires review of the protocol change, not just rerunning
the script until a failing test passes. The Python arithmetic is variable-time
and must never be used with real secrets.

The ElGamal fields use `elgamal-key-v1` followed by `R` and the fixed-width context
`chain_id || program_id || mint || token_account`. Each field is 32 bytes.
The generator independently checks the 64-byte expansion and reduced secret
scalar; SDK interoperability tests check public-key construction and proofs.

The symmetric balance key uses `balance-ae-key-v1` followed by `R` and the same
128-byte account context and expands to 16 bytes without scalar reduction.
The `balance_key` fixture is derived independently with Python HMAC-SHA256.
