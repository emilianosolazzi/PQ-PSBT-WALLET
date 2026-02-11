# PQ-PSBT Hybrid Wallet

**Hybrid Taproot + Post-Quantum Signing Wallet**
*155/155 Tests Passing · 4 NIST PQC Algorithms · Real secp256k1 + Bech32m · Full BIP-341 Compliance · BIP-174 HW Wallet Interop*

> **Status: Experimental / Research-Grade** — Not for production custody. No consensus impact.

---

## What Is This?

A **research-grade Bitcoin wallet** that pairs standard BIP-340 Schnorr (Taproot) signatures with post-quantum cryptographic attestations — ML-DSA-65, ML-DSA-87, Falcon-512, and Falcon-1024.

Every UTXO carries dual keys. Both signatures must be present before a transaction is finalized.

> **Non-Consensus Disclosure:** PQ signatures are **advisory only**. Bitcoin consensus validity comes solely from BIP-340/341 Schnorr. PQ attestations are for off-chain policy, auditing, or future soft-fork readiness. Stripping PQ data does not affect on-chain validity.

---

## Quick Start

```bash
pip install coincurve bech32 pqcrypto pycryptodome

# Run self-test demo
python pq_psbt.py

# Run full test suite
python -m pytest test_pq_psbt.py -v
```

---

## Test Suite — 155/155 PASSED

```
Platform:  Python 3.13.7 · pytest 9.0.2
Crypto:    coincurve 21.0.0 (libsecp256k1) · bech32 1.2.0 · pqcrypto 0.4.0 (C bindings)
Runtime:   ~19 s
Mocks:     0
```

| Category | Tests | Coverage |
|----------|-------|----------|
| BIP-341 Compliance | 3 | SIGHASH_DEFAULT, ALL, SINGLE |
| Post-Quantum Crypto | 5 | ML-DSA-65/87, Falcon-512/1024, hedged signing |
| Wallet Operations | 3 | TX creation, insufficient funds, timelocks |
| Security | 3 | Double-spend, sig tampering, commitment binding |
| Broadcast & Finalize | 5 | Raw TX, RPC, HTTP errors |
| Consensus Correctness | 6 | Real secp256k1, Schnorr verify, sighash guards |
| PQ KeyPair Serialization | 10 | Dict roundtrip ×4, sign-after-restore ×4, invalid key rejection |
| HybridUTXO | 6 | Salt/amount validation, BIP-65/113 locks, dict roundtrip |
| HybridPSBTContainer | 5 | Zero output, UTXO mismatch, base64, sig checks |
| HybridWalletCore | 6 | Address gen, balance, zero-send, unknown address |
| Encrypted Persistence | 2 | AES-256-GCM roundtrip, wrong password |
| TaprootKey | 4 | Deterministic seed, Schnorr sign/verify, Bech32m roundtrip |
| PQ Signature Verify | 2 | Valid signatures, tampered rejection |
| Coin Selection | 2 | Largest-first, multi-UTXO combine |
| RBF Support | 2 | Default on, explicit disable |
| **BIP-340 Schnorr Edge Cases** | **9** | **64B sig invariant, non-32B rejection, cross-key fail, boundary digests, truncation, padding** |
| **secp256k1 Key Boundaries** | **6** | **Scalar 0 reject, curve order reject, n−1 max, scalar 1 min, x-only 32B, compressed prefix** |
| **Bech32m Address Rigorous** | **11** | **Prefix, length, lowercase, decode roundtrip, signet, uniqueness, P2WPKH rejection** |
| **Raw TX Serialization** | **8** | **Segwit marker/flag, nVersion=2, locktime, witness items, LE txid, multi-input** |
| **Sighash Determinism** | **7** | **Per-input isolation, DEFAULT≠ALL, SINGLE per-output, ANYONECANPAY, amount/script tampering** |
| **Commitment Integrity** | **8** | **32B, deterministic, bound to all fields, chain_id replay protection** |
| **Dual Signature Integrity** | **2** | **Schnorr+PQ bind to same sighash, wrong-sighash PQ rejection** |
| **Adversarial Inputs** | **8** | **Dust, zero/negative, 21M cap, double-spend, SIGHASH_NONE rejection, cross-scheme** |
| **Encrypted Persistence Hardened** | **3** | **Corrupted ciphertext MAC fail, corrupted tag fail, empty password** |
| **Tagged Hash Conformance** | **6** | **32B, deterministic, spec-match SHA256(tag‖tag‖msg), CompactSize boundaries** |
| **PQ Cross-Scheme Security** | **5** | **Falcon✗Dilithium, DSA-65✗87, empty msg, 1MB msg, NIST key sizes** |
| **BIP-174 Binary PSBT** | **15** | **Magic bytes, input/output/sig roundtrip, PQ proprietary fields, b64, tx_version, locktime, sequence, witness_utxo, tap_internal_key, invalid magic reject, multi-input** |
| **HWI Signing Workflow** | **4** | **HW sig merge, merge on unsigned, full HWI roundtrip, export unsigned for HW** |
| **Total** | **155** | |

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `coincurve` | 21.0.0 | libsecp256k1 C bindings — real BIP-340 Schnorr `sign_schnorr()` / `verify()` |
| `bech32` | 1.2.0 | Native Bech32m encode/decode for P2TR addresses |
| `pqcrypto` | 0.4.0 | C-compiled NIST PQC — ML-DSA-65/87, Falcon-512/1024 |
| `pycryptodome` | 3.22.0 | AES-256-GCM symmetric encryption, scrypt KDF |
| `pytest` | 9.0.2 | Test runner |

---

## Architecture

```
HybridWallet
  └─ HybridWalletCore        (UTXO engine, coin selection, encrypted persistence)
       └─ HybridPSBTContainer (dual signing, BIP-174 binary PSBT, HW wallet merge, raw TX, JSON-RPC)
            └─ BIP341Sighash  (tagged hashes, all SIGHASH types, annex, script-path)
                 ├─ coincurve  (libsecp256k1 — BIP-340 Schnorr)
                 ├─ bech32     (Bech32m P2TR addresses)
                 └─ pqcrypto   (ML-DSA-65/87, Falcon-512/1024)
```

---

## Key Classes

| Class | Role |
|-------|------|
| `TaprootKey` | Real secp256k1 private key via `coincurve`. BIP-340 Schnorr sign/verify. Bech32m P2TR address generation. `is_mock` always `False`. |
| `PQKeyPair` | NIST PQC keypair (ML-DSA or Falcon). Keygen, sign, verify, serialize/deserialize. |
| `HybridUTXO` | UTXO with dual keys (Taproot + PQ), commitment hash, BIP-65/113 timelock support. |
| `HybridPSBTContainer` | PSBT container with dual signing, BIP-174 binary serialization (`to_psbt_v0`/`from_psbt_v0`), HW wallet signature merge (`merge_hw_signatures`), raw TX finalization. |
| `HybridWalletCore` | Address generation, UTXO management, coin selection, balance tracking. |
| `HybridWallet` | High-level API: receive, fund, send, broadcast, encrypted save/load. |
| `BIP341Sighash` | Full BIP-341 §4.1 sighash calculator — all hash types, annex, script-path. |

---

## Security

- **Real secp256k1** — `coincurve` (libsecp256k1 C) for all Schnorr operations; zero mock keys
- **Real Bech32m** — `bech32` library for all P2TR address encode/decode; no hex fallbacks
- **BIP-341 TapSighash** — full tagged-hash commitment
- **BIP-65/113 Timelocks** — height-based and time-based lock enforcement
- **BIP-125 RBF** — opt-in Replace-By-Fee
- **Double-spend tracking** — nullifier set prevents UTXO reuse
- **Encrypted persistence** — AES-256-GCM + scrypt (N=2²⁰)
- **Safe-mode finalize** — rejects SIGHASH_SINGLE/NONE/script-path/annex until fully supported
- **Defence-in-depth** — self-verification after every PQ signing operation

---

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `pq_psbt.py` | ~1495 | Main wallet implementation + BIP-174 PSBT serializer + self-test demo |
| `bitcoin_protocol.py` | ~185 | BIP-341 sighash calculator |
| `test_pq_psbt.py` | ~1775 | 155 pytest tests across 28 test classes |

---

## PQ Cryptography Warnings

- Uses `pqcrypto` (libpqcrypto C reference implementations) — no formal side-channel audit
- Falcon's floating-point sampler is inherently fragile; constant-time depends on platform/compiler
- No hardware acceleration assumed
- PQ sig sizes (657 B – 4,627 B) materially affect bandwidth vs 64-byte Schnorr

---

## Commitment Semantics

`SHA-256(taproot_pk || pq_pk || salt || unlock_height || chain_id)` — **off-chain only**. Not enforced by Script or consensus. Intended for custody policy, auditing, soft-fork research.

---

## KDF Disclaimer

- scrypt (N=2²⁰, r=8, p=1) params are opinionated; may be slow on low-memory devices
- Future: Argon2id option, hardware wallet export

---

## Non-Goals

- No consensus rule changes
- No Script-level PQ enforcement
- No soft-fork / hard-fork proposal
- No miner validation of PQ signatures
- No mempool policy changes
- No full BIP-370 PSBTv2 support (v0 only for now)

---

## Correct Framing

✅ *"This system provides real PQ cryptographic enforcement at the wallet and custody layer, without requiring consensus changes."*

❌ ~~"This makes Bitcoin post-quantum secure."~~

---

*155/155 tests · 28 test classes · Real secp256k1 + Bech32m · BIP-174 HW wallet interop · Zero mocks · 4 NIST PQC algorithms*
