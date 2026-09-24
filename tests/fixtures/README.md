# Test vectors

`v1.txt` fixes the output bytes for the custom `stealth-keygen-v1-tweak` and
`stealth-keygen-v1-nonce` domains. It is not an SLNT compatibility vector.
All secrets in this file are deterministic public test inputs.

Generate it with `python3 scripts/generate_test_vectors.py`. The script uses
Python's standard library, separate curve arithmetic, and the published
[RFC 7748 section 6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1) and
[RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
vectors to check its reference calculations before generating the fixture.

The Rust tests consume committed expected values. They never regenerate them.
Changing a vector requires review of the protocol change, not just rerunning
the script until a failing test passes. The Python arithmetic is variable-time
and must never be used with real secrets.
