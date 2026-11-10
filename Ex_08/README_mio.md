# To Inventory and Beyond

This report describes the changes and fixes actually made in `crypto.go` and `crypto_test.go`, compared with the original ones.

Group members: Edoardo Barbieri 264679, Lorenzo Zarantonello 268174, Marco Battagliola 264454

## 1. CBOM analysis

We generated `cbom-cdxgen.json` and `cbom-cbomkit-hyperion.json` from the original project. They remain inventories of the **original implementation**, not of the fixed code.

An algorithm appearing in a CBOM does not necessarily mean that the tool explicitly reports its vulnerability. We therefore distinguish asset detection from the security conclusions drawn during our analysis.

| Crytpogaphic asset | cdxgen | CBOMkit-hyperion | Result of our review |
| --- | --- | --- | --- |
| RSA signing keys | Lists `rsa` and related key material | Lists `RSA-2048` | RSA is not post-quantum secure; replaced with ML-DSA-65 |
| MD5 | Lists `md5`, explicitly marked `weak` | Lists MD5 at checksum, signing and verification locations | Deprecated hash, replaced with SHA-256. The signature scheme was also replaced |
| ECDH over P-256 | Not listed as a cryptographic asset | Not listed | Identified by reading the code; replaced with ML-KEM-1024 |
| AES | Lists AES as `strong`, without identifying the mode | Lists AES, without identifying the mode | This remains unchanged |
| SHA-256 | Listed | Listed | Mantained and introduced in place of MD5 |

## 2. Implemented changes

### RSA/MD5 signatures → ML-DSA-65 over a SHA-256 digest

The original `Sign` and `Verify` used RSA PKCS#1 v1.5 with an MD5 digest. MD5 has broken collision resistance, and RSA does not provide post-quantum security.

We replaced RSA with ML-DSA-65 from `github.com/cloudflare/circl/sign/mldsa/mldsa65`. `NewKeys` now generates a 32-byte seed using `crypto/rand.Read` and reconstructs the signing key pair with `NewKeyFromSeed`. This also removes the time-seeded pseudorandom generator from signing-key generation.

`Sign` computes `SHA256(data)` and passes that digest to `mldsa65.SignTo`, with an empty context and randomized (hedged) signing enabled. `Verify` checks the public-key length, unpacks the key and verifies the signature over the same digest.

Precisely, this is **ML-DSA applied to an application-computed SHA-256 digest**. It is not the standardized HashML-DSA prehash construction. The outer hash also limits the collision resistance of the overall signing construction; selecting ML-DSA-65 alone does not establish the security strength of the entire application.

### ECDH P-256 → ML-KEM-1024

The original wrapping operation generated an ephemeral P-256 key, performed ECDH with the recipient's public key, and hashed the shared secret with SHA-256 to obtain a key-encryption key. This ECDH usage was absent from both algorithm inventories and was identified manually.

We replaced it with ML-KEM-1024 from Go's `crypto/mlkem` package:

1. `NewKeys` generates a 64-byte random seed and constructs the recipient's decapsulation key.
2. `WrapKey` parses the recipient's encapsulation key and calls `Encapsulate`, obtaining a shared secret and a KEM ciphertext.
3. The shared secret is hashed with SHA-256, and the resulting 32-byte key is passed to `Encrypt` to wrap the file key.
4. `UnwrapKey` decapsulates the KEM ciphertext, derives the same wrapping key and decrypts the wrapped file key. It rejects a recovered key whose length is not 32 bytes.

The first output of `WrapKey` is therefore now a **KEM ciphertext**, rather than an ephemeral elliptic-curve public key. The symmetric encryption used inside this operation has not been changed.

### MD5 checksum → SHA-256

`Checksum` now returns the hexadecimal SHA-256 digest instead of MD5. Its output changes from 32 to 64 hexadecimal characters. Both CBOMs detected MD5; cdxgen additionally labelled it weak.

A plain checksum is not an authentication mechanism: replacing MD5 does not prevent an attacker who can replace both the data and its checksum from modifying them consistently.

### Key storage and public-key encoding

The `Keys` structure now stores `DSASeed` and `MLKEMSeed` as PEM-encoded seeds, replacing `RSAPrivate` and `ECCPrivate`. `Load` checks that the decoded seeds have lengths of 32 and 64 bytes respectively, then reconstructs the key objects. `PublicKeys` returns raw ML-DSA and ML-KEM public-key encodings.

These formats are incompatible with the original RSA/ECDH identities and packages. Existing identities must be regenerated or explicitly migrated. PEM is an encoding, not encryption: the stored seeds remain secret key material requiring protection.

## 3. Test updates

We also modified `crypto_test.go` so that its expectations are consistent with the implemented changes:

- Replaced the MD5 checksum vectors for the empty string and `abc` with SHA-256 vectors.
- Updated storage/loading tests to use `DSASeed` and `MLKEMSeed`, compare reconstructed public keys and verify a signature produced by a reloaded key.
- Updated invalid-key loading cases, including malformed PEM and an incorrectly sized ML-DSA seed.
- Retained valid-signature, altered-message, corrupted-signature and wrong-signer checks, and added checks for signature length, verification failure under an all-zero public key and differing randomized signatures on the same message.
- Adapted wrapping tests to ML-KEM public keys and ciphertexts, including round trips, distinct encapsulations, wrong-recipient behaviour and malformed inputs.

Existing encryption/decryption, Argon2id, salt-length and fingerprint tests remain in place. They check functional behaviour; they do not establish that the unchanged encryption mode or salt generation is secure. In particular, `TestNewSalt` checks only the salt length.

**Validation status:** the source and test changes were reviewed together, but the tests were not executed while preparing this report. A usable Go toolchain and the complete project/module files were not available for that validation. In the complete repository, with dependencies configured, run:

```bash
go test ./...
```

## 4. Remaining issues and completion notes

The submitted changes migrate the asymmetric primitives and remove MD5, but they do **not** resolve every cryptographic issue in the original implementation:

- **ECB-style encryption remains.** `blocks` encrypts each block independently, with PKCS#7 padding and no authentication tag. Its comment claiming equivalence to AES-GCM is incorrect. Moving to authenticated encryption would require changes to the ciphertext format and tests, including tampering rejection.
- **Salt generation remains time-seeded.** `NewSalt` still calls `fastReader`, which seeds `math/rand` with Unix time in seconds. Calls within the same second produce the same salt. It should use cryptographic randomness; the existing change only fixes randomness for key generation.
- **Code annotations are incomplete.** The exercise requires `CBOMs` and `FIXES` comments for every modification. The supplied modified source contains only one such pair, above `NewKeys`; other changes still need their own annotations.
- **Some comments and test messages still use the old terminology.** `PublicKeys` mentions RSA/P-256, `WrapKey` mentions `recipientECC`, and a wrapping test still refers to an ephemeral key.
- **Application integration needs checking.** Renamed fields, new encodings and the added CIRCL dependency must be reflected wherever necessary in the complete project, including its module files. The supplied files do not establish that `main.go` and application-level tests have been updated.

These are follow-up tasks, not fixes already implemented. The CBOM comparison illustrates the main lesson of the exercise: an inventory helps identify cryptographic assets, but manual review is still needed to assess how they are used and to find omitted assets.

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [Go `crypto/mlkem` documentation](https://pkg.go.dev/crypto/mlkem)
- Project evidence: the original and modified Go files and the two supplied CBOM JSON files.
