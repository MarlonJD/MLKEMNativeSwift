# Changelog

## 0.2.0

- Adds incremental ML-KEM-768 operations for ML-KEM Braid / Triple Ratchet
  protocol implementations.
- Exposes split public-key representation (`header` + encapsulation-key
  vector), split ciphertext operations (`ct1` + `ct2`), and split
  decapsulation.
- Documents the Triple Ratchet-oriented API surface in the README.
- Adds deterministic tests proving incremental encapsulation matches full
  ML-KEM encapsulation output.

## 0.1.0

- Initial public package.
- Adds ML-KEM-768 key generation, public/private representation loading,
  encapsulation, and decapsulation.
- Wraps `mlkem-native` portable C backend pinned to upstream release `v1.1.0`.
- Adds deterministic and roundtrip tests.
