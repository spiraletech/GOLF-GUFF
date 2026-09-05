# L15 — Authority Receipts / Signer Interface

L15 gives GOLF GUFF a pluggable proof-of-authority envelope without binding the Ring to one UI, OS account, hardware key, cloud identity provider or cryptographic implementation.

## Contract

An `AuthorityEnvelope` binds:

- purpose: recovery, destructive execution, persistent symbiosis or capability grant
- subject identity
- actor reference
- signer identity
- issuance timestamp
- nonce
- SHA-256 of the exact authorized scope

`AuthoritySigner` and `AuthorityVerifier` are interfaces. GUFF owns the canonical envelope and verification policy; a platform cartridge may later provide Ed25519, OS-backed keys, hardware keys, secure enclaves or another approved implementation.

Issuance returns a content-addressed `guff:authority:sha256:<digest>` receipt. Verification recomputes both the envelope digest and receipt identity before asking the verifier to validate the signature.

## Security boundary

A receipt is not a secret. It is proof metadata. Private signing material never belongs in the receipt, transaction journal, DOJO or barcode transport.

A signer cannot broaden purpose or subject after issuance: both are part of the signed canonical envelope. Tampering with scope, actor, signer, nonce, subject or purpose invalidates the content identity/signature.

## SpiralOS handoff

SpiralOS may render a receipt reference as a compact barcode token. The barcode is transport/presentation only. It should carry identifiers and hashes sufficient to locate/validate the receipt, never private key material and never become an authority source by itself.

Law: **scan → resolve receipt → verify signer + digest + purpose + subject → authorize. Never scan → blindly execute.**
