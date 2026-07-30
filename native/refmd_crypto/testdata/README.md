# HPKE PQ test vector provenance

`draft-ietf-hpke-pq-04-a5-1.json` is the Base mode
MLKEM768-X25519 / HKDF-SHA256 / ChaCha20Poly1305 suite copied without
regeneration from `hpkewg/hpke-pq` tag `draft-ietf-hpke-pq-04`, file
`test-vectors.json`.

Source: https://github.com/hpkewg/hpke-pq/blob/draft-ietf-hpke-pq-04/test-vectors.json

`registry-v1.json` is the authoritative versioned registry for immutable crypto
fixtures. Each entry pins the fixture path, SHA-256 digest, provenance, and
normative purpose. Tests consume these checked-in bytes directly and must not
regenerate normative expected values.

`refmd-signed-pq-wrap-v1.json` is the RefMD signed PQ wrap golden vector for the
approved design version 19 ADR-023. It fixes canonical preimages, hashes,
hybrid signatures, HPKE output, plaintext opening, and executable negative
mutations for the production validators.
