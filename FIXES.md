# EasyCrypt Publishing and Fix Plan

The first phase prepares the Maven project structure and artifacts for publishing. The crypto and correctness fixes follow that restructuring so module boundaries and artifact names are stable before compatibility-sensitive changes begin.

## Phase 0: Prepare the library modules for public Maven publishing

**Status:** Implemented locally. Binary/source/Javadoc JARs build, and local Maven dependency resolution succeeds. The `ua.cn.al` namespace must be registered in the Central Portal before an actual release.

**Manual steps still outstanding:** Register/verify `ua.cn.al` in Central Portal, put a Central user token in Maven `settings.xml` as server `central`, configure a GPG signing key, then build and review a signed release bundle. Publishing itself remains a separate manual action.

Publish only the reusable `easycrypt` and `easycrypt-identity` libraries for public Maven builds. The CLI, examples, and identity examples remain project tools and are not release artifacts. Maven Central is the intended public repository. The repository is already a Maven reactor, but the root POM has no publishing configuration, and the CLI assembly uses a fixed `easycrypt` filename even though its Maven artifactId is `easycryptutil`.

### 0.1 Define the published artifact set

- Publish `easycrypt` and `easycrypt-identity` as the consumer-facing libraries.
- Exclude `easycrypt-util`, `easycrypt-examples`, and `easycrypt-identity-examples` from release/deploy while retaining them in the source repository and development reactor as useful.
- Keep existing library coordinates stable if already released; verify the coordinates and dependency relationship before configuring release automation.

### 0.2 Separate library packaging from executable packaging

- Ensure `easycrypt` and `easycrypt-identity` publish ordinary dependency-aware JARs with POM metadata, rather than shaded/uber JARs.
- Keep the CLI executable assembly as a local build output only; it must not be attached to either published library artifact or replace a Maven artifact.
- Make all inter-module dependencies resolve through the reactor and published coordinates consistently.

### 0.3 Make the parent and modules publishable

- Give the parent POM a clear artifactId/name and retain its `pom` packaging so published child POMs can resolve their parent. Publish this small support POM with the libraries; it is required to resolve their published Maven POMs.
- Add release metadata needed by the selected Maven repository (project URL, SCM, license, developers, and descriptions) to the appropriate published POMs.
- Configure source and Javadoc artifacts for library modules and make compiler/JDK requirements consistent across POMs and documentation.
- Configure Maven Central release metadata, staging/publishing, and required artifact signing for the library modules. Keep credentials and signing secrets outside the repository.

### 0.4 Verify the publication shape

- Build the reactor and inspect each candidate artifact and generated POM, including dependency scopes, parent coordinates, and classifiers.
- Verify that a clean consumer project can resolve the published library coordinates and compile against their public APIs.
- Document the release command and list the two library modules being released. Validate artifacts locally; do not publish to Maven Central as part of this structural phase.

**Acceptance criteria:** Intended libraries produce correctly named, dependency-aware Maven artifacts with usable POMs and source/Javadoc attachments; examples are not accidentally released; CLI packaging cannot replace a library artifact; release credentials are not committed.

## 1. Correct password-based key derivation

**Status:** Implemented in the library API. New-key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations and requires a 16-byte minimum salt. The former low-iteration API remains deprecated for existing data. Callers must persist KDF parameters themselves because `CryptedContainer` receives a raw key and its IV salt is not KDF metadata.

- Keep new derivations at a suitably costly, documented work factor with an explicit-iteration overload; avoid baking the count into the implementation.
- Require a random salt of at least 16 bytes for the new API and provide a salt-generation helper.
- Preserve the old 16-iteration derivation as a deprecated compatibility method. New data must record algorithm, salt, and iteration count alongside the ciphertext at the application layer.
- Reject invalid passwords, salts, and iteration values, clear temporary password material and `PBEKeySpec` state, and report unavailable algorithms as exceptions rather than returning `null`.

**Acceptance criteria:** The new API uses documented parameters and can reproduce derived keys from retained metadata; legacy key derivation remains explicitly callable; invalid input produces a documented exception rather than `null` or an unchecked failure.

## Phase 2: Make AES-GCM nonce handling safe and predictable

**Status:** Implemented. Symmetric encryption generates a fresh random nonce per operation, decryption loads the message nonce without treating repeated decryptions as reuse, IV accessors copy state, input lengths are validated, and cipher initialization failures are propagated.

- Separate nonce assignment for encryption from loading a nonce for decryption. Decryption must accept the nonce carried by the message, including repeated decryptions.
- Ensure encryption obtains a fresh nonce for every operation, or clearly require and validate caller-provided unique nonces. Do not present a comparison with only the current nonce as reuse protection.
- Define whether the salt is part of the transmitted IV or supplied out of band, and make the message format and API follow one consistent rule.
- Avoid returning the mutable internal IV array; validate IV and nonce lengths before copying.
- Propagate cipher initialization failures instead of logging them and returning an uninitialized cipher.

**Acceptance criteria:** Repeated decryption of a valid message succeeds; each encryption under a key uses a unique nonce according to the selected API contract; malformed IV/nonce lengths fail with clear exceptions; GCM authentication failures remain failures and never return plaintext.

## Phase 3: Harden AEAD message parsing

**Status:** Implemented. AEAD and legacy AES-GCM parsers validate headers, signed lengths, overflow-safe payload bounds, exact input consumption, payload limits, and minimum tag length; malformed data raises `CryptoNotValidException` before allocation.

- Check the minimum message length before reading the IV or length fields.
- Reject negative lengths, integer overflow, declared sizes beyond the configured maximum, and any mismatch between declared lengths and remaining bytes.
- Validate minimum ciphertext length for the configured authentication tag before attempting decryption.
- Make malformed input consistently produce the library's documented checked exception (or a single documented parsing exception), rather than leaking `BufferUnderflowException` and array allocation errors.
- Review the legacy `Ciphered` parser for equivalent bounds and size checks.

**Acceptance criteria:** Truncated, oversized, negative-length, inconsistent-length, and tag-short messages are rejected before large allocations or cipher use; valid current-format messages still parse.

## Phase 4: Fix and clarify RSA encryption behavior

- Correct the API documentation to reflect the actual maximum plaintext size for the selected RSA key and padding.
- Prefer hybrid encryption for arbitrary-size data: generate a random symmetric key, encrypt the payload with authenticated encryption, and wrap the key with RSA using an approved padding scheme such as OAEP.
- If the existing raw RSA mode must remain for compatibility, impose a clear input-size limit and label the mode as legacy; do not claim that it chunks large messages.
- Define and test the serialized hybrid envelope, including versioning and authentication of relevant metadata.

**Acceptance criteria:** Large-message behavior matches the documented contract; encryption rejects unsupported inputs clearly or uses the hybrid format; new RSA encryption avoids PKCS#1 v1.5 encryption for the recommended path; compatibility behavior is documented.

## Phase 5: Repair keystore status and lifecycle behavior

- Make `PKCS12KeyStore.save` return `true` after a successful store and `false` on failure.
- Clear or rebuild aliases and certificates when opening another keystore so results do not accumulate across calls.
- Close file streams with try-with-resources, including keystore creation.
- Review null-password handling and report failures consistently.

**Acceptance criteria:** Successful saves report success, failed saves report failure, and repeated opens expose only entries from the most recently opened store.

## Phase 6: Complete certificate validation contracts

- Document what `ExtCert.isValid` verifies and distinguish validity dates from trust-chain, signature, key-usage, and revocation checks.
- Implement only the checks the API promises; make unsupported checks explicit rather than implying full certificate validation.
- Review private-key/certificate matching and certificate-chain validation entry points for consistent error reporting.

**Acceptance criteria:** Callers can tell which certificate properties were checked, and APIs do not imply trust validation when they only check dates or key correspondence.

## Phase 7: Align build requirements and documentation

- Reconcile the README's Java 11+ statements with the Maven compiler source/target of 21 and the stated release requirements.
- State the supported JDK version consistently across the root and module documentation.
- Update RSA and crypto-parameter documentation to match the implemented behavior after the earlier fixes.

**Acceptance criteria:** A user can determine the minimum supported JDK and actual cryptographic behavior from the documentation without conflicting claims.

## Suggested work sequence

1. Configure the two library modules for Maven Central and leave the CLI/examples unpublished.
2. Restructure Maven packaging and release metadata; validate generated artifacts without publishing them.
3. Agree on compatibility requirements for existing encrypted messages and RSA ciphertexts.
4. Fix and validate AES-GCM nonce handling and AEAD parsing.
5. Introduce versioned KDF metadata and stronger password derivation defaults.
6. Replace or constrain RSA encryption and document migration behavior.
7. Fix keystore lifecycle/status behavior and clarify certificate validation.
8. Align the Java version and module documentation with the final implementation.

For each implementation step, add focused regression tests for its acceptance criteria and run the relevant module tests before moving on.
