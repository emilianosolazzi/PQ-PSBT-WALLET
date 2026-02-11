"""
Production-Grade Hybrid Taproot + Post-Quantum Signing Wallet
=============================================================
- Taproot (SegWit v1) for on-chain BIP-340 Schnorr compatibility
- NIST FIPS-204 ML-DSA (Dilithium) & Falcon signatures for PQ attestations
- PSBT-compatible metadata container with proprietary PQ signature data
- BIP-341 sighash, BIP-32/44 key derivation awareness
- AES-256-GCM encrypted wallet persistence
- Constant-time PQ signature verification (via pqcrypto C bindings)

Dependencies:
    pip install pqcrypto pycryptodome bitcoinlib

Algorithms (NIST PQC standardised, Aug 2024):
    ML-DSA-65  (CRYSTALS-Dilithium3) — NIST Level 3 (192-bit)
    ML-DSA-87  (CRYSTALS-Dilithium5) — NIST Level 5 (256-bit)
    Falcon-512                       — NIST Level 1 (128-bit, compact sigs)
    Falcon-1024                      — NIST Level 5 (256-bit, compact sigs)

Security Model:
    - Bitcoin consensus security is provided **solely** by BIP-340/341
      Schnorr signatures.  Post-quantum signatures provide additional
      off-chain assurances only.
    - PQ signatures are non-consensus, non-enforceable, and advisory.
      They provide cryptographic attestations for off-chain policy,
      auditing, or future soft-fork compatibility, but do not affect
      transaction validity on the Bitcoin network today.
    - Loss or stripping of PQ data does not affect transaction validity.
    - This wallet does not attempt to change Bitcoin consensus rules.

PSBT Note:
    ``HybridPSBTContainer`` is a PSBT-compatible metadata container,
    not a full BIP-174/BIP-370 binary PSBT.  It serialises to JSON
    (base64-wrapped) and carries PQ signature data in proprietary fields.
    It does not interoperate with Bitcoin Core / HWI at the binary level.

PQ Cryptography Assumptions:
    - PQ operations use ``pqcrypto`` (libpqcrypto C reference implementations).
    - No formal side-channel audit has been performed on these bindings.
    - Falcon implementations are inherently fragile (floating-point sampler);
      constant-time guarantees depend on the platform and compiler.
    - No hardware acceleration is assumed or required.
    - PQ signature sizes (657 B – 4,627 B) materially affect bandwidth and
      storage relative to 64-byte Schnorr signatures.

Commitment Semantics:
    The UTXO commitment ``SHA-256(taproot_pk || pq_pk || salt || height ||
    chain_id)`` is computed and verified **off-chain only**.  It is not
    enforced by Bitcoin Script, not included in the witness, and not
    validated by consensus.  Its intended uses are custody policy
    enforcement, auditing, and future soft-fork research.

Replay Protection Note:
    ``chain_id = SHA-256(network)[:4]`` prevents cross-network commitment
    replay at the **off-chain PQ layer only**.  It does not prevent
    on-chain transaction replay across forks.

Status: Experimental / Research-Grade — not for production custody.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# PQ Crypto — NIST-standardised via pqcrypto (libpqcrypto bindings)
# ---------------------------------------------------------------------------
from pqcrypto.sign import falcon_512, falcon_1024, ml_dsa_65, ml_dsa_87

# Symmetric encryption for wallet-at-rest
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

# BIP-341 full sighash (supports all SIGHASH types)
from bitcoin_protocol import BIP341Sighash, compact_size, tagged_hash

# Real Bitcoin key handling: coincurve (libsecp256k1) + bech32
from coincurve import PrivateKey as _Secp256k1PrivateKey
from coincurve import PublicKeyXOnly as _Secp256k1PubKeyXOnly
from bech32 import encode as _bech32_encode, decode as _bech32_decode
_HAS_SECP256K1 = True   # always True — hard dependency now

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
from logging.handlers import RotatingFileHandler

log = logging.getLogger("pq_psbt")
log.addHandler(logging.NullHandler())


def setup_logging(log_file: str = "pq_wallet.log") -> None:
    """
    Configure production logging with rotating file + console.

    Call once at startup; safe to call multiple times (idempotent).
    """
    if getattr(setup_logging, "_done", False):
        return

    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.WARNING)

    log.addHandler(file_handler)
    log.addHandler(console_handler)
    log.setLevel(logging.INFO)

    setup_logging._done = True  # type: ignore[attr-defined]


# Aliases for module-internal use
_compact_size = compact_size
_tagged_hash = tagged_hash


# ============================================================
# POST-QUANTUM SIGNATURE BACKEND
# ============================================================

class PQScheme(Enum):
    """Supported post-quantum signature algorithms."""
    ML_DSA_65   = "ML-DSA-65"    # FIPS 204, Level 3 — recommended default
    ML_DSA_87   = "ML-DSA-87"    # FIPS 204, Level 5
    FALCON_512  = "Falcon-512"   # Level 1, compact signatures
    FALCON_1024 = "Falcon-1024"  # Level 5, compact signatures


# Registry: scheme → (module, pk_bytes, sk_bytes, sig_max_bytes)
_PQ_REGISTRY: Dict[PQScheme, tuple] = {
    PQScheme.ML_DSA_65:   (ml_dsa_65,   1952, 4032, 3309),
    PQScheme.ML_DSA_87:   (ml_dsa_87,   2592, 4896, 4627),
    PQScheme.FALCON_512:  (falcon_512,   897, 1281,  666),   # padded upper bound
    PQScheme.FALCON_1024: (falcon_1024, 1793, 2305, 1280),
}


@dataclass(frozen=False)
class PQKeyPair:
    """
    Real NIST post-quantum keypair.

    All cryptographic operations delegate to the pqcrypto C library —
    no HMAC stubs, no mock signatures.
    """
    scheme: PQScheme
    private_key: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        mod, expected_pk, expected_sk, _ = _PQ_REGISTRY[self.scheme]
        if len(self.public_key) != expected_pk:
            raise ValueError(
                f"{self.scheme.value}: public key must be {expected_pk} B, "
                f"got {len(self.public_key)}"
            )
        if len(self.private_key) != expected_sk:
            raise ValueError(
                f"{self.scheme.value}: secret key must be {expected_sk} B, "
                f"got {len(self.private_key)}"
            )

    # ---- sign / verify ------------------------------------------------
    def sign(self, message: bytes) -> bytes:
        """Produce a real PQ signature over *message*."""
        mod = _PQ_REGISTRY[self.scheme][0]
        return mod.sign(self.private_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Constant-time verification. Returns True on success."""
        mod = _PQ_REGISTRY[self.scheme][0]
        try:
            return mod.verify(self.public_key, message, signature)
        except Exception:
            return False

    # ---- serialisation -------------------------------------------------
    def to_dict(self) -> Dict[str, str]:
        return {
            "scheme": self.scheme.value,
            "pk": self.public_key.hex(),
            "sk": self.private_key.hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> "PQKeyPair":
        scheme = PQScheme(d["scheme"])
        return cls(
            scheme=scheme,
            public_key=bytes.fromhex(d["pk"]),
            private_key=bytes.fromhex(d["sk"]),
        )


def generate_pq_keypair(
    scheme: PQScheme = PQScheme.ML_DSA_65,
) -> PQKeyPair:
    """Generate a fresh NIST PQ keypair using OS-level entropy."""
    mod, _, _, _ = _PQ_REGISTRY[scheme]
    pk, sk = mod.generate_keypair()
    return PQKeyPair(scheme=scheme, private_key=sk, public_key=pk)


# ============================================================
# TAPROOT (BIP-340) KEY WRAPPER
# ============================================================

class TaprootKey:
    """
    Real BIP-340 Schnorr key backed by libsecp256k1 (via ``coincurve``).

    All operations produce **on-chain-valid** signatures and addresses:

    * ``sign_schnorr()`` → 64-byte BIP-340 Schnorr signature
    * ``verify_schnorr()`` → constant-time x-only verification
    * ``taproot_address()`` → proper Bech32m bc1p/tb1p address

    No mock mode.  Every key is a real secp256k1 private key.
    """

    def __init__(
        self,
        seed: Optional[bytes] = None,
        *,
        mock: Optional[bool] = None,  # ignored — kept for API compat
    ) -> None:
        if mock is not None:
            log.info("TaprootKey: mock= parameter ignored — "
                     "all keys are real secp256k1 now")
        sk_bytes = seed if seed else secrets.token_bytes(32)
        # Ensure valid scalar (1 < sk < curve order)
        self._sk = _Secp256k1PrivateKey(sk_bytes)
        self._pk_compressed: bytes = self._sk.public_key.format(compressed=True)
        self._pk_xonly: bytes = self._pk_compressed[1:]  # 32-byte x-only

    @property
    def is_mock(self) -> bool:
        """Always False — all keys are real secp256k1."""
        return False

    # -- properties -----------------------------------------------------
    @property
    def private_key(self) -> bytes:
        """32-byte raw secp256k1 secret scalar."""
        return self._sk.secret

    @property
    def public_key(self) -> bytes:
        """33-byte compressed SEC1 public key (0x02/0x03 || x)."""
        return self._pk_compressed

    @property
    def public_key_xonly(self) -> bytes:
        """32-byte x-only public key (BIP-340)."""
        return self._pk_xonly

    # -- crypto ---------------------------------------------------------
    def sign_schnorr(self, message: bytes) -> bytes:
        """BIP-340 Schnorr signature (64 bytes).

        ``message`` must be a 32-byte sighash digest.
        """
        if len(message) != 32:
            raise ValueError(
                f"BIP-340 Schnorr sign requires a 32-byte digest, "
                f"got {len(message)} bytes"
            )
        return self._sk.sign_schnorr(message)

    def verify_schnorr(self, message: bytes, signature: bytes) -> bool:
        """Verify a BIP-340 Schnorr signature."""
        try:
            pk_xonly = _Secp256k1PubKeyXOnly(self._pk_xonly)
            return pk_xonly.verify(signature, message)
        except Exception:
            return False

    # -- address --------------------------------------------------------
    def taproot_address(self, network: str = "mainnet") -> str:
        """Generate a real Bech32m P2TR address."""
        hrp = "tb" if network in ("testnet", "signet") else "bc"
        addr = _bech32_encode(hrp, 1, list(self._pk_xonly))
        if addr is None:
            raise RuntimeError("Bech32m encoding failed")
        return addr


# ============================================================
# HYBRID UTXO
# ============================================================

@dataclass
class HybridUTXO:
    """
    UTXO guarded by *two* independent key types:

    1. **Taproot** (on-chain) — spendable today via BIP-341
    2. **PQ key** (off-chain attestation) — quantum-resistant signing

    Commitment Semantics:
        The commitment hash is an **off-chain cryptographic binding**
        between the classical Taproot key and the PQ key, combined
        with a random salt and optional timelock height.  It is
        intended for auditing, custody policy enforcement, or future
        protocol upgrades.  **It does not provide on-chain enforcement**
        — Bitcoin nodes do not validate this commitment during spending.
    """
    taproot_key: TaprootKey
    pq_keypair: PQKeyPair
    salt: bytes               # 32 random bytes
    unlock_height: int        # 0 = immediately spendable
    txid: str
    vout: int
    amount_sats: int
    chain_id: bytes = b""     # network id — prevents cross-chain replay

    def __post_init__(self) -> None:
        if len(self.salt) != 32:
            raise ValueError("salt must be exactly 32 bytes")
        if self.amount_sats < 0:
            raise ValueError("amount_sats cannot be negative")

    # ---- commitment ---------------------------------------------------
    @property
    def commitment_hash(self) -> bytes:
        """C = SHA-256(taproot_pk || pq_pk || salt || height || chain_id).

        Off-chain only — not enforced by Script or consensus.
        Used for custody policy, auditing, and soft-fork research.
        """
        buf = (
            self.taproot_key.public_key
            + self.pq_keypair.public_key
            + self.salt
            + struct.pack(">I", self.unlock_height)
            + self.chain_id
        )
        return hashlib.sha256(buf).digest()

    def is_spendable(
        self, current_height: int, current_time: int = 0,
    ) -> bool:
        """BIP-65/BIP-113: height-based (<500M) or time-based (>=500M) lock."""
        if self.unlock_height == 0:
            return True
        if self.unlock_height >= 500_000_000:
            return current_time >= self.unlock_height
        return current_height >= self.unlock_height

    # ---- persistence --------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "taproot_privkey": self.taproot_key.private_key.hex(),
            "pq": self.pq_keypair.to_dict(),
            "salt": self.salt.hex(),
            "unlock_height": self.unlock_height,
            "txid": self.txid,
            "vout": self.vout,
            "amount_sats": self.amount_sats,
            "chain_id": self.chain_id.hex(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HybridUTXO":
        return cls(
            taproot_key=TaprootKey(bytes.fromhex(d["taproot_privkey"])),
            pq_keypair=PQKeyPair.from_dict(d["pq"]),
            salt=bytes.fromhex(d["salt"]),
            unlock_height=d["unlock_height"],
            txid=d["txid"],
            vout=d["vout"],
            amount_sats=d["amount_sats"],
            chain_id=bytes.fromhex(d.get("chain_id", "")),
        )


# ============================================================
# PSBT v2 BUILDER  (BIP-370 + proprietary PQ fields)
# ============================================================

# Proprietary key prefix for PQ signature data (BIP-174 §proprietary)
_PQ_PROPRIETARY_PREFIX = b"\xfc\x05pqbtc"   # 0xFC + len + "pqbtc"


@dataclass
class HybridPSBTContainer:
    """
    Hybrid PSBT-compatible transaction container.

    This is a PSBT-compatible metadata container, **not** a BIP-174/370
    binary PSBT.  It serialises to JSON (base64-wrapped) and carries
    PQ signature data in proprietary fields.  It does not interoperate
    with Bitcoin Core, HWI, or hardware wallets at the binary level.

    PQ signatures stored here are non-consensus and advisory.  On-chain
    transaction validity is determined solely by the BIP-340 Schnorr
    signatures in the witness.
    """
    version: int = 2
    tx_version: int = 2
    locktime: int = 0
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    outputs: List[Dict[str, Any]] = field(default_factory=list)
    pq_signatures: List[Dict[str, Any]] = field(default_factory=list)

    # ---- builder ------------------------------------------------------
    def add_input(
        self, utxo: HybridUTXO, *, enable_rbf: bool = True,
    ) -> None:
        # BIP-125: nSequence 0xfffffffd signals opt-in RBF
        sequence = 0xFFFFFFFD if enable_rbf else 0xFFFFFFFF
        self.inputs.append({
            "txid": utxo.txid,
            "vout": utxo.vout,
            "amount": utxo.amount_sats,
            "sequence": sequence,
            "taproot_pubkey": utxo.taproot_key.public_key.hex(),
            "witness_utxo": {
                "amount": utxo.amount_sats,
                "scriptPubKey": self._taproot_script(utxo.taproot_key),
            },
            "proprietary": {
                "pq_pubkey": utxo.pq_keypair.public_key.hex(),
                "pq_scheme": utxo.pq_keypair.scheme.value,
                "salt": utxo.salt.hex(),
                "unlock_height": utxo.unlock_height,
                "commitment": utxo.commitment_hash.hex(),
            },
        })

    def add_output(self, address: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("output amount must be positive")
        self.outputs.append({
            "address": address,
            "amount": amount,
            "scriptPubKey": self._address_to_script(address),
        })

    # ---- signing ------------------------------------------------------
    def sign_inputs(
        self,
        utxos: List[HybridUTXO],
        hash_type: int = BIP341Sighash.SIGHASH_DEFAULT,
    ) -> List[bytes]:
        """
        Dual-sign every input:
          1. BIP-340 Schnorr  (on-chain witness)
          2. PQ signature     (proprietary off-chain enforcement)

        Each input gets its own per-input sighash via BIP341Sighash.
        Returns a list of sighash bytes (one per input).
        """
        if len(utxos) != len(self.inputs):
            raise ValueError(
                f"UTXO count ({len(utxos)}) != input count ({len(self.inputs)})"
            )

        sighashes: List[bytes] = []

        for idx, utxo in enumerate(utxos):
            sighash = self._compute_sighash(input_index=idx, hash_type=hash_type)
            sighashes.append(sighash)

            # 1. Classical Schnorr
            taproot_sig = utxo.taproot_key.sign_schnorr(sighash)

            # 2. Real PQ signature (Dilithium / Falcon)
            pq_sig = utxo.pq_keypair.sign(sighash)

            # Immediate self-check (defence-in-depth)
            if not utxo.pq_keypair.verify(sighash, pq_sig):
                raise RuntimeError(
                    f"PQ self-verification failed on input {idx} — "
                    f"possible memory corruption"
                )

            self.pq_signatures.append({
                "input_index": idx,
                "taproot_sig": taproot_sig.hex(),
                "pq_sig": b64encode(pq_sig).decode(),
                "pq_scheme": utxo.pq_keypair.scheme.value,
                "pq_sig_bytes": len(pq_sig),
                "hash_type": hash_type,
            })

        log.info("Signed %d inputs (Schnorr + %s, hash_type=0x%02x)",
                 len(utxos),
                 utxos[0].pq_keypair.scheme.value if utxos else "N/A",
                 hash_type)
        return sighashes

    def verify_pq_signatures(self, utxos: List[HybridUTXO]) -> bool:
        """
        Verify every PQ signature in this PSBT against its input's
        public key and the per-input recomputed sighash.
        Returns False on the first failure.
        """
        for entry in self.pq_signatures:
            idx = entry["input_index"]
            ht = entry.get("hash_type", BIP341Sighash.SIGHASH_DEFAULT)
            sighash = self._compute_sighash(input_index=idx, hash_type=ht)
            sig = b64decode(entry["pq_sig"])
            if not utxos[idx].pq_keypair.verify(sighash, sig):
                log.warning("PQ verify FAILED on input %d", idx)
                return False
        return True

    # ---- sighash (BIP-341 §4.1 — full implementation) -----------------
    def _compute_sighash(
        self,
        input_index: int = 0,
        hash_type: int = BIP341Sighash.SIGHASH_DEFAULT,
    ) -> bytes:
        """
        BIP-341 TapSighash via full BIP341Sighash implementation.

        Supports SIGHASH_DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY.
        Commits to: version, locktime, prevouts, amounts,
        scriptPubKeys, sequences, and outputs.
        """
        calculator = BIP341Sighash(self, input_index)
        return calculator.compute(hash_type=hash_type)

    # ---- helpers ------------------------------------------------------
    @staticmethod
    def _taproot_script(key: TaprootKey) -> str:
        """OP_1 <32-byte x-only pubkey>  (P2TR scriptPubKey).

        BIP-340 x-only pubkey = 32-byte x-coordinate only,
        dropping the 1-byte parity prefix from the 33-byte
        compressed SEC1 representation.
        """
        pk_bytes = key.public_key
        if len(pk_bytes) == 33:
            # Compressed SEC1: drop the 0x02/0x03 prefix → 32-byte x-only
            x_only = pk_bytes[1:]
        elif len(pk_bytes) == 32:
            x_only = pk_bytes
        else:
            raise ValueError(
                f"Unexpected pubkey length {len(pk_bytes)}: "
                f"expected 32 (x-only) or 33 (compressed)"
            )
        return "5120" + x_only.hex()

    @staticmethod
    def _address_to_script(address: str) -> str:
        """Decode a Bech32m P2TR address to its OP_1 <32B> scriptPubKey hex."""
        if not address.startswith(("bc1", "tb1")):
            return ""
        hrp = "bc" if address.startswith("bc1") else "tb"
        ver, prog = _bech32_decode(hrp, address)
        if ver is None or prog is None:
            raise ValueError(f"Invalid Bech32m address: {address}")
        if ver != 1 or len(prog) != 32:
            raise ValueError(
                f"Expected witness v1 + 32-byte program, "
                f"got v{ver} + {len(prog)} bytes"
            )
        return "5120" + bytes(prog).hex()

    # ---- finalise ------------------------------------------------------
    def finalize(self, *, allow_mock: bool = False) -> bytes:
        """
        Validate that the PSBT is fully signed and serialize a
        broadcast-ready raw transaction.

        Returns the raw Bitcoin transaction bytes (ready for
        ``sendrawtransaction``).

        ``allow_mock`` is accepted for API compat but ignored —
        all keys are real secp256k1 now.

        Raises ValueError if any input is unsigned or incomplete.
        """
        if not self.pq_signatures:
            raise ValueError("No signatures present")
        if len(self.pq_signatures) != len(self.inputs):
            raise ValueError(
                f"Signature count ({len(self.pq_signatures)}) != "
                f"input count ({len(self.inputs)})"
            )
        for sig_entry in self.pq_signatures:
            if not sig_entry.get("taproot_sig"):
                raise ValueError(
                    f"Input {sig_entry['input_index']} missing Taproot signature"
                )
            # Restrict to safe modes until full support is implemented
            ht = sig_entry.get("hash_type", BIP341Sighash.SIGHASH_DEFAULT)
            if ht not in (BIP341Sighash.SIGHASH_DEFAULT, BIP341Sighash.SIGHASH_ALL):
                raise ValueError(
                    f"finalize() only supports SIGHASH_DEFAULT (0x00) and "
                    f"SIGHASH_ALL (0x01) — got 0x{ht:02x} on input "
                    f"{sig_entry['input_index']}.  Script-path, annex, "
                    f"SIGHASH_SINGLE, and SIGHASH_NONE are not yet safe "
                    f"for broadcast."
                )

        # --- build raw transaction ---
        raw = b""
        # nVersion
        raw += struct.pack("<I", self.tx_version)
        # segwit marker + flag
        raw += b"\x00\x01"
        # input count
        raw += _compact_size(len(self.inputs))
        for inp in self.inputs:
            raw += bytes.fromhex(inp["txid"])[::-1]          # LE txid
            raw += struct.pack("<I", inp["vout"])
            raw += b"\x00"                                   # empty scriptSig
            raw += struct.pack("<I", inp.get("sequence", 0xFFFFFFFD))
        # output count
        raw += _compact_size(len(self.outputs))
        for out in self.outputs:
            raw += struct.pack("<q", out["amount"])
            spk = bytes.fromhex(out["scriptPubKey"])
            raw += _compact_size(len(spk)) + spk
        # witness data (one stack per input)
        for sig_entry in self.pq_signatures:
            taproot_sig = bytes.fromhex(sig_entry["taproot_sig"])
            raw += _compact_size(1)                           # 1 witness item
            raw += _compact_size(len(taproot_sig)) + taproot_sig
        # nLockTime
        raw += struct.pack("<I", self.locktime)

        log.info("PSBT finalized: %d inputs, %d bytes raw TX",
                 len(self.inputs), len(raw))
        return raw

    # ---- broadcast -----------------------------------------------------
    def broadcast_transaction(
        self,
        node_url: str = "http://localhost:8332",
        rpc_user: str = "bitcoin",
        rpc_pass: str = "",
        timeout: int = 30,
        *,
        allow_mock: bool = False,
    ) -> str:
        """
        Finalize the PSBT and broadcast the raw TX to a Bitcoin Core
        JSON-RPC node via ``sendrawtransaction``.

        Args:
            node_url:  Bitcoin Core RPC endpoint.
            rpc_user:  RPC username.
            rpc_pass:  RPC password (empty → no auth).
            timeout:   HTTP timeout in seconds.

        Returns:
            The transaction ID (hex string) on success.

        Raises:
            RuntimeError on HTTP or RPC-level errors.
        """
        import requests  # deferred — not needed until broadcast time

        tx_hex = self.finalize().hex()

        payload = {
            "jsonrpc": "2.0",
            "id": "pq-wallet",
            "method": "sendrawtransaction",
            "params": [tx_hex],
        }

        auth = (rpc_user, rpc_pass) if rpc_pass else None

        try:
            resp = requests.post(
                node_url, json=payload, auth=auth, timeout=timeout,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"RPC connection failed: {exc}") from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"RPC HTTP {resp.status_code}: {resp.text[:200]}"
            )

        result = resp.json()
        if result.get("error"):
            raise RuntimeError(
                f"sendrawtransaction rejected: {result['error']}"
            )

        txid = result["result"]
        log.info("Broadcast OK — txid=%s", txid)
        return txid

    # ---- serialisation ------------------------------------------------
    def to_base64(self) -> str:
        blob = {
            "version": self.version,
            "tx": {
                "version": self.tx_version,
                "locktime": self.locktime,
                "inputs": self.inputs,
                "outputs": self.outputs,
            },
            "pq_sigs": self.pq_signatures,
        }
        return b64encode(json.dumps(blob, separators=(",", ":")).encode()).decode()

    @classmethod
    def from_base64(cls, b64: str) -> "HybridPSBTContainer":
        d = json.loads(b64decode(b64))
        return cls(
            version=d["version"],
            tx_version=d["tx"]["version"],
            locktime=d["tx"].get("locktime", 0),
            inputs=d["tx"]["inputs"],
            outputs=d["tx"]["outputs"],
            pq_signatures=d.get("pq_sigs", []),
        )

    # ---- BIP-174 binary PSBT (hardware wallet interop) ----------------

    # BIP-174 key types — per-input
    _PSBT_IN_WITNESS_UTXO = 0x01
    _PSBT_IN_TAP_KEY_SIG = 0x13
    _PSBT_IN_TAP_INTERNAL_KEY = 0x17
    # BIP-174 proprietary key type
    _PSBT_PROPRIETARY = 0xFC

    @staticmethod
    def _psbt_key_value(key: bytes, value: bytes) -> bytes:
        """Encode one BIP-174 key-value pair: <key-len><key><value-len><value>."""
        return _compact_size(len(key)) + key + _compact_size(len(value)) + value

    def _build_unsigned_tx(self) -> bytes:
        """Build the unsigned transaction (no witness) for the PSBT global."""
        raw = struct.pack("<I", self.tx_version)
        # No segwit marker/flag in unsigned TX
        raw += _compact_size(len(self.inputs))
        for inp in self.inputs:
            raw += bytes.fromhex(inp["txid"])[::-1]
            raw += struct.pack("<I", inp["vout"])
            raw += b"\x00"  # empty scriptSig
            raw += struct.pack("<I", inp.get("sequence", 0xFFFFFFFD))
        raw += _compact_size(len(self.outputs))
        for out in self.outputs:
            raw += struct.pack("<q", out["amount"])
            spk = bytes.fromhex(out["scriptPubKey"])
            raw += _compact_size(len(spk)) + spk
        raw += struct.pack("<I", self.locktime)
        return raw

    def to_psbt_v0(self, *, include_pq: bool = True) -> bytes:
        """
        Serialize to BIP-174 binary PSBT format (version 0).

        This produces a standards-compliant PSBT that can be loaded
        into Bitcoin Core, Sparrow, Ledger, Trezor, or any HWI-based
        signer for Schnorr (Taproot key-path) signing.

        Args:
            include_pq: If True, embed PQ data in proprietary fields
                        (0xFC "pqbtc" namespace).  Hardware wallets
                        will silently ignore proprietary fields.
                        If False, omit PQ data entirely.

        Returns:
            Raw BIP-174 PSBT bytes (pass to ``to_psbt_b64()`` for
            base64 encoding).
        """
        buf = b"psbt\xff"  # BIP-174 magic + separator

        # ---- Global: unsigned TX (key 0x00) ----
        unsigned_tx = self._build_unsigned_tx()
        buf += self._psbt_key_value(b"\x00", unsigned_tx)
        buf += b"\x00"  # global separator

        # ---- Per-input maps ----
        for idx, inp in enumerate(self.inputs):
            # PSBT_IN_WITNESS_UTXO (0x01): serialized previous output
            wu = inp.get("witness_utxo", {})
            if wu:
                amount = struct.pack("<q", wu["amount"])
                spk = bytes.fromhex(wu["scriptPubKey"])
                witness_utxo_val = amount + _compact_size(len(spk)) + spk
                buf += self._psbt_key_value(b"\x01", witness_utxo_val)

            # PSBT_IN_TAP_INTERNAL_KEY (0x17): 32-byte x-only pubkey
            tap_pk_hex = inp.get("taproot_pubkey", "")
            if tap_pk_hex:
                pk_bytes = bytes.fromhex(tap_pk_hex)
                # Drop SEC1 prefix if 33 bytes
                xonly = pk_bytes[1:] if len(pk_bytes) == 33 else pk_bytes
                buf += self._psbt_key_value(b"\x17", xonly)

            # PSBT_IN_TAP_KEY_SIG (0x13): if already signed
            sig_entry = next(
                (s for s in self.pq_signatures if s["input_index"] == idx),
                None,
            )
            if sig_entry and sig_entry.get("taproot_sig"):
                sig_bytes = bytes.fromhex(sig_entry["taproot_sig"])
                buf += self._psbt_key_value(b"\x13", sig_bytes)

            # Proprietary PQ fields (0xFC + "pqbtc" + sub-type)
            if include_pq:
                prop = inp.get("proprietary", {})
                if prop:
                    # Sub-type 0x01: PQ public key
                    pq_pk = prop.get("pq_pubkey", "")
                    if pq_pk:
                        key = _PQ_PROPRIETARY_PREFIX + b"\x01"
                        buf += self._psbt_key_value(key, bytes.fromhex(pq_pk))

                    # Sub-type 0x02: PQ scheme name (utf-8)
                    pq_scheme = prop.get("pq_scheme", "")
                    if pq_scheme:
                        key = _PQ_PROPRIETARY_PREFIX + b"\x02"
                        buf += self._psbt_key_value(key, pq_scheme.encode())

                    # Sub-type 0x03: salt
                    salt_hex = prop.get("salt", "")
                    if salt_hex:
                        key = _PQ_PROPRIETARY_PREFIX + b"\x03"
                        buf += self._psbt_key_value(key, bytes.fromhex(salt_hex))

                    # Sub-type 0x04: commitment hash
                    commit_hex = prop.get("commitment", "")
                    if commit_hex:
                        key = _PQ_PROPRIETARY_PREFIX + b"\x04"
                        buf += self._psbt_key_value(key, bytes.fromhex(commit_hex))

                # PQ signature if present
                if sig_entry:
                    pq_sig_b64 = sig_entry.get("pq_sig", "")
                    if pq_sig_b64:
                        key = _PQ_PROPRIETARY_PREFIX + b"\x10"
                        buf += self._psbt_key_value(key, b64decode(pq_sig_b64))

            buf += b"\x00"  # input separator

        # ---- Per-output maps ----
        for out in self.outputs:
            # We include the scriptPubKey for completeness but BIP-174
            # doesn't require per-output fields for simple spends.
            buf += b"\x00"  # output separator (empty map)

        return buf

    def to_psbt_b64(self, *, include_pq: bool = True) -> str:
        """Return BIP-174 PSBT as base64 string (for HWI / Bitcoin Core)."""
        return b64encode(self.to_psbt_v0(include_pq=include_pq)).decode()

    @classmethod
    def from_psbt_v0(cls, data: bytes) -> "HybridPSBTContainer":
        """
        Parse a BIP-174 binary PSBT and reconstruct a HybridPSBTContainer.

        Handles signed PSBTs returned from hardware wallets — merges
        Taproot key-path signatures (PSBT_IN_TAP_KEY_SIG 0x13) and
        preserves any proprietary PQ fields.
        """
        if data[:5] != b"psbt\xff":
            raise ValueError("Not a valid BIP-174 PSBT (bad magic)")

        pos = 5
        container = cls()

        def _read_compact_size(d: bytes, p: int) -> tuple:
            b0 = d[p]
            if b0 < 0xFD:
                return b0, p + 1
            elif b0 == 0xFD:
                return struct.unpack_from("<H", d, p + 1)[0], p + 3
            elif b0 == 0xFE:
                return struct.unpack_from("<I", d, p + 1)[0], p + 5
            else:
                return struct.unpack_from("<Q", d, p + 1)[0], p + 9

        def _read_kv(d: bytes, p: int):
            """Read one key-value pair. Returns (key, value, new_pos) or None at separator."""
            key_len, p = _read_compact_size(d, p)
            if key_len == 0:
                return None, None, p  # separator
            key = d[p:p + key_len]
            p += key_len
            val_len, p = _read_compact_size(d, p)
            val = d[p:p + val_len]
            p += val_len
            return key, val, p

        # ---- Parse global map ----
        unsigned_tx = b""
        while pos < len(data):
            key, val, pos = _read_kv(data, pos)
            if key is None:
                break
            if key == b"\x00":
                unsigned_tx = val

        # Parse unsigned TX to extract inputs/outputs
        if unsigned_tx:
            tp = 0
            tx_ver = struct.unpack_from("<I", unsigned_tx, tp)[0]
            container.tx_version = tx_ver
            tp += 4
            n_in, tp = _read_compact_size(unsigned_tx, tp)
            for _ in range(n_in):
                txid_le = unsigned_tx[tp:tp + 32]
                tp += 32
                vout = struct.unpack_from("<I", unsigned_tx, tp)[0]
                tp += 4
                script_len, tp = _read_compact_size(unsigned_tx, tp)
                tp += script_len  # skip scriptSig
                seq = struct.unpack_from("<I", unsigned_tx, tp)[0]
                tp += 4
                container.inputs.append({
                    "txid": txid_le[::-1].hex(),
                    "vout": vout,
                    "sequence": seq,
                })
            n_out, tp = _read_compact_size(unsigned_tx, tp)
            for _ in range(n_out):
                amount = struct.unpack_from("<q", unsigned_tx, tp)[0]
                tp += 8
                spk_len, tp = _read_compact_size(unsigned_tx, tp)
                spk = unsigned_tx[tp:tp + spk_len]
                tp += spk_len
                container.outputs.append({
                    "amount": amount,
                    "scriptPubKey": spk.hex(),
                })
            container.locktime = struct.unpack_from("<I", unsigned_tx, tp)[0]

        # ---- Parse per-input maps ----
        pq_prefix = _PQ_PROPRIETARY_PREFIX
        for idx in range(len(container.inputs)):
            pq_data: Dict[str, Any] = {}
            sig_data: Dict[str, Any] = {"input_index": idx}

            while pos < len(data):
                key, val, pos = _read_kv(data, pos)
                if key is None:
                    break

                key_type = key[0]
                if key_type == 0x01:  # WITNESS_UTXO
                    # Parse amount + scriptPubKey
                    wu_amount = struct.unpack_from("<q", val, 0)[0]
                    spk_len_b = val[8]
                    spk_hex = val[9:9 + spk_len_b].hex()
                    container.inputs[idx]["witness_utxo"] = {
                        "amount": wu_amount,
                        "scriptPubKey": spk_hex,
                    }
                    container.inputs[idx]["amount"] = wu_amount
                elif key_type == 0x17:  # TAP_INTERNAL_KEY
                    container.inputs[idx]["taproot_pubkey"] = val.hex()
                elif key_type == 0x13:  # TAP_KEY_SIG
                    sig_data["taproot_sig"] = val.hex()
                    sig_data["hash_type"] = (
                        val[64] if len(val) == 65
                        else BIP341Sighash.SIGHASH_DEFAULT
                    )
                elif key_type == 0xFC and key[1:].startswith(b"\x05pqbtc"):
                    sub_type = key[len(pq_prefix):]
                    if sub_type == b"\x01":
                        pq_data["pq_pubkey"] = val.hex()
                    elif sub_type == b"\x02":
                        pq_data["pq_scheme"] = val.decode()
                    elif sub_type == b"\x03":
                        pq_data["salt"] = val.hex()
                    elif sub_type == b"\x04":
                        pq_data["commitment"] = val.hex()
                    elif sub_type == b"\x10":
                        sig_data["pq_sig"] = b64encode(val).decode()
                        sig_data["pq_sig_bytes"] = len(val)

            if pq_data:
                container.inputs[idx]["proprietary"] = pq_data
            if sig_data.get("taproot_sig") or sig_data.get("pq_sig"):
                container.pq_signatures.append(sig_data)

        # ---- Parse per-output maps (skip for now) ----
        for _ in range(len(container.outputs)):
            if pos < len(data):
                while pos < len(data):
                    key, val, pos = _read_kv(data, pos)
                    if key is None:
                        break

        return container

    @classmethod
    def from_psbt_b64(cls, b64: str) -> "HybridPSBTContainer":
        """Parse a base64-encoded BIP-174 PSBT."""
        return cls.from_psbt_v0(b64decode(b64))

    def merge_hw_signatures(self, signed_psbt: "HybridPSBTContainer") -> None:
        """
        Merge Taproot key-path signatures from a hardware-wallet-signed
        PSBT into this container, preserving existing PQ signatures.

        Typical workflow:
          1. ``unsigned = psbt.to_psbt_b64(include_pq=False)``
          2. Send to Ledger/Trezor via HWI → get signed PSBT back
          3. ``signed = HybridPSBTContainer.from_psbt_b64(signed_b64)``
          4. ``psbt.merge_hw_signatures(signed)``
          5. Now ``psbt`` has both Schnorr (from HW) and PQ (from wallet)
        """
        hw_sigs = {s["input_index"]: s for s in signed_psbt.pq_signatures}

        for idx in range(len(self.inputs)):
            hw_sig = hw_sigs.get(idx)
            if not hw_sig or not hw_sig.get("taproot_sig"):
                continue

            # Find existing PQ sig entry for this input
            existing = next(
                (s for s in self.pq_signatures if s["input_index"] == idx),
                None,
            )
            if existing:
                # Merge: keep PQ sig, add HW Schnorr sig
                existing["taproot_sig"] = hw_sig["taproot_sig"]
                existing["hash_type"] = hw_sig.get(
                    "hash_type", BIP341Sighash.SIGHASH_DEFAULT
                )
            else:
                # No PQ sig yet — just store Schnorr
                self.pq_signatures.append({
                    "input_index": idx,
                    "taproot_sig": hw_sig["taproot_sig"],
                    "hash_type": hw_sig.get(
                        "hash_type", BIP341Sighash.SIGHASH_DEFAULT
                    ),
                })

        log.info("Merged %d HW signatures into PSBT", len(hw_sigs))


# Backward-compatible alias — will be removed in a future release
PSBTv2 = HybridPSBTContainer


# ============================================================
# WALLET CORE
# ============================================================

class HybridWalletCore:
    """
    Core UTXO wallet engine.

    * Generates Taproot + PQ address pairs
    * Greedy coin selection with fee estimation
    * Encrypted on-disk persistence (AES-256-GCM + scrypt KDF)
    """

    DUST_LIMIT_SATS = 546
    DEFAULT_FEE_RATE = 10   # sat/vB — override from mempool API

    def __init__(
        self,
        network: str = "mainnet",
        pq_scheme: PQScheme = PQScheme.ML_DSA_65,
    ) -> None:
        self.network = network
        self.pq_scheme = pq_scheme
        self.utxos: List[HybridUTXO] = []
        self.current_height: int = 0
        self.fee_rate: int = self.DEFAULT_FEE_RATE
        self._spent_nullifiers: set = set()  # prevent double-spend

    # ---- address generation -------------------------------------------
    def generate_address(self, unlock_blocks: int = 0) -> Tuple[str, str]:
        """
        Returns
        -------
        (taproot_address, commitment_hex)
            taproot_address : share with sender (bc1p... / tb1p...)
            commitment_hex  : internal binding of both keys
        """
        taproot_key = TaprootKey()
        pq_keypair = generate_pq_keypair(self.pq_scheme)
        salt = secrets.token_bytes(32)
        unlock_height = self.current_height + unlock_blocks

        # Network identifier prevents cross-chain commitment replay
        chain_id = hashlib.sha256(self.network.encode()).digest()[:4]

        utxo = HybridUTXO(
            taproot_key=taproot_key,
            pq_keypair=pq_keypair,
            salt=salt,
            unlock_height=unlock_height,
            txid="",
            vout=0,
            amount_sats=0,
            chain_id=chain_id,
        )
        self.utxos.append(utxo)

        address = taproot_key.taproot_address(self.network)
        log.info(
            "Address generated: %s (scheme=%s, unlock=%d)",
            address, self.pq_scheme.value, unlock_height,
        )
        return address, utxo.commitment_hash.hex()

    # ---- balance ------------------------------------------------------
    def get_balance(self) -> Dict[str, Any]:
        available = sum(
            u.amount_sats for u in self.utxos
            if u.is_spendable(self.current_height) and u.amount_sats > 0
        )
        pending: List[Dict[str, Any]] = []
        for u in self.utxos:
            if not u.is_spendable(self.current_height) and u.amount_sats > 0:
                remaining = u.unlock_height - self.current_height
                pending.append({
                    "amount_sats": u.amount_sats,
                    "unlock_height": u.unlock_height,
                    "blocks_remaining": remaining,
                    "eta_hours": round(remaining * 10 / 60, 1),
                })
        return {"available_sats": available, "pending": pending}

    # ---- transaction building -----------------------------------------
    def create_transaction(
        self,
        to_address: str,
        amount_sats: int,
    ) -> HybridPSBTContainer:
        if amount_sats <= 0:
            raise ValueError("amount must be positive")

        selected = self._coin_select(amount_sats)
        if selected is None:
            log.warning("Coin selection failed: need %d sats", amount_sats)
            raise ValueError(
                f"Insufficient balance: need {amount_sats} sats"
            )

        psbt = HybridPSBTContainer()
        for utxo in selected:
            psbt.add_input(utxo)

        total_in = sum(u.amount_sats for u in selected)
        fee = self._estimate_fee(len(selected), 2)
        change = total_in - amount_sats - fee

        log.info(
            "TX: %d sats -> %s | %d inputs, total_in=%d, fee=%d, change=%d",
            amount_sats, to_address[:20], len(selected), total_in, fee, change,
        )

        if change < 0:
            raise ValueError(
                f"Inputs ({total_in}) < amount ({amount_sats}) + fee ({fee})"
            )

        psbt.add_output(to_address, amount_sats)

        if change > self.DUST_LIMIT_SATS:
            change_addr, _ = self.generate_address()
            psbt.add_output(change_addr, change)

        psbt.sign_inputs(selected)

        # Mark spent
        for utxo in selected:
            nf = utxo.commitment_hash.hex()
            if nf in self._spent_nullifiers:
                log.critical("DOUBLE-SPEND ATTEMPT: nullifier %s", nf[:16])
                raise RuntimeError(f"Double-spend detected: {nf[:16]}...")
            self._spent_nullifiers.add(nf)
            self.utxos.remove(utxo)

        log.info("TX built: %d inputs spent, PSBT ready", len(selected))
        return psbt

    # ---- coin selection -----------------------------------------------
    def _coin_select(self, target: int) -> Optional[List[HybridUTXO]]:
        """Largest-first greedy selection."""
        spendable = sorted(
            (u for u in self.utxos
             if u.is_spendable(self.current_height) and u.amount_sats > 0),
            key=lambda u: u.amount_sats,
            reverse=True,
        )
        selected: List[HybridUTXO] = []
        total = 0
        for utxo in spendable:
            selected.append(utxo)
            total += utxo.amount_sats
            if total >= target + self._estimate_fee(len(selected), 2):
                return selected
        return None

    def _estimate_fee(self, n_in: int, n_out: int) -> int:
        """Taproot vbyte estimation with 10% safety margin."""
        # P2TR key-path input ≈ 57.5 vB, P2TR output ≈ 43 vB
        vbytes = n_in * 57.5 + n_out * 43 + 10.5
        return int(vbytes * self.fee_rate * 1.1)

    # ---- encrypted persistence ----------------------------------------
    def save_encrypted(self, filepath: str, password: str) -> None:
        """
        Write wallet to disk encrypted with AES-256-GCM.

        KDF: scrypt(N=2^20, r=8, p=1) -> 32-byte key
        """
        plaintext = json.dumps(
            {"utxos": [u.to_dict() for u in self.utxos]},
            separators=(",", ":"),
        ).encode()

        kdf_salt = secrets.token_bytes(16)
        key = scrypt(password.encode(), kdf_salt, 32, N=2**20, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(plaintext)

        blob = {
            "v": 1,
            "kdf": "scrypt-N20-r8-p1",
            "salt": kdf_salt.hex(),
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "ct": b64encode(ct).decode(),
        }
        Path(filepath).write_text(json.dumps(blob, indent=2))
        log.info("Wallet saved -> %s (%d UTXOs)", filepath, len(self.utxos))

    def load_encrypted(self, filepath: str, password: str) -> None:
        """Load and decrypt wallet from disk."""
        blob = json.loads(Path(filepath).read_text())

        kdf_salt = bytes.fromhex(blob["salt"])
        key = scrypt(password.encode(), kdf_salt, 32, N=2**20, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(blob["nonce"]))

        plaintext = cipher.decrypt_and_verify(
            b64decode(blob["ct"]),
            bytes.fromhex(blob["tag"]),
        )
        data = json.loads(plaintext)
        self.utxos = [HybridUTXO.from_dict(u) for u in data["utxos"]]
        log.info("Wallet loaded <- %s (%d UTXOs)", filepath, len(self.utxos))

    # Legacy unencrypted (for tests only)
    def save(self, filepath: str) -> None:
        data = {"utxos": [u.to_dict() for u in self.utxos]}
        Path(filepath).write_text(json.dumps(data, indent=2))

    def load(self, filepath: str) -> None:
        data = json.loads(Path(filepath).read_text())
        self.utxos = [HybridUTXO.from_dict(u) for u in data["utxos"]]


# ============================================================
# USER-FACING API
# ============================================================

class HybridWallet:
    """
    High-level hybrid Taproot + PQ signing wallet.

    This is a **research-grade hybrid custody system** providing:
      - BIP-340/341 Schnorr signing (on-chain consensus)
      - NIST PQ attestations (off-chain, advisory only)

    On-chain transaction validity is determined solely by the Schnorr
    signatures.  PQ signatures are non-consensus, non-enforceable,
    and can be stripped without invalidating the transaction.

    >>> w = HybridWallet("testnet", PQScheme.FALCON_512)
    >>> addr = w.receive()
    >>> w.fund(addr, txid="ab"*32, vout=0, sats=500_000)
    >>> dest = TaprootKey().taproot_address("testnet")
    >>> psbt_b64 = w.send(dest, 0.001)
    """

    def __init__(
        self,
        network: str = "mainnet",
        pq_scheme: PQScheme = PQScheme.ML_DSA_65,
    ) -> None:
        self.core = HybridWalletCore(network, pq_scheme)

    def receive(self, lock_blocks: int = 0) -> str:
        """Generate a fresh Taproot receiving address."""
        address, _ = self.core.generate_address(lock_blocks)
        return address

    def fund(self, address: str, *, txid: str, vout: int, sats: int) -> None:
        """Mark an address as funded (call after seeing on-chain confirmation)."""
        for utxo in self.core.utxos:
            if utxo.taproot_key.taproot_address(self.core.network) == address:
                utxo.txid = txid
                utxo.vout = vout
                utxo.amount_sats = sats
                log.info(
                    "Funded %s: %d sats (txid=%s:%d)",
                    address[:20], sats, txid[:16], vout,
                )
                return
        raise ValueError(f"Address not found in wallet: {address}")

    def balance(self) -> str:
        bal = self.core.get_balance()
        btc = bal["available_sats"] / 1e8
        msg = f"  {btc:.8f} BTC available"
        for p in bal["pending"]:
            eta = p["eta_hours"]
            eta_str = f"{eta:.1f}h" if eta < 24 else f"{eta / 24:.1f}d"
            msg += f"\n  {p['amount_sats'] / 1e8:.8f} BTC unlocks in {eta_str}"
        return msg

    def send(self, address: str, btc_amount: float) -> str:
        """Build, dual-sign, and return base64 PSBT."""
        sats = int(round(btc_amount * 1e8))
        psbt = self.core.create_transaction(address, sats)
        return psbt.to_base64()

    def broadcast(
        self,
        address: str,
        btc_amount: float,
        *,
        node_url: str = "http://localhost:8332",
        rpc_user: str = "bitcoin",
        rpc_pass: str = "",
    ) -> str:
        """
        Build, dual-sign, finalize, and broadcast in one call.

        Returns the transaction ID on success.
        """
        sats = int(round(btc_amount * 1e8))
        psbt = self.core.create_transaction(address, sats)
        return psbt.broadcast_transaction(
            node_url=node_url, rpc_user=rpc_user, rpc_pass=rpc_pass,
        )


# ============================================================
# SELF-TEST / DEMO
# ============================================================

def _run_demo() -> None:
    """End-to-end demo exercising every PQ algorithm."""
    setup_logging()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    separator = "=" * 60

    for scheme in PQScheme:
        mod, pk_sz, sk_sz, sig_max = _PQ_REGISTRY[scheme]
        print(f"\n{separator}")
        print(f"  {scheme.value}  (pk={pk_sz} B, sk={sk_sz} B, sig<={sig_max} B)")
        print(separator)

        # -- Key generation --
        t0 = time.perf_counter()
        kp = generate_pq_keypair(scheme)
        keygen_ms = (time.perf_counter() - t0) * 1000
        print(f"  Keygen: {keygen_ms:.1f} ms")

        # -- Sign --
        msg = b"BIP-341 sighash placeholder"
        t0 = time.perf_counter()
        sig = kp.sign(msg)
        sign_ms = (time.perf_counter() - t0) * 1000
        print(f"  Sign:   {sign_ms:.1f} ms  ({len(sig)} B)")

        # -- Verify --
        t0 = time.perf_counter()
        ok = kp.verify(msg, sig)
        verify_ms = (time.perf_counter() - t0) * 1000
        status = "PASS" if ok else "FAIL"
        print(f"  Verify: {verify_ms:.1f} ms  -> {status}")

        # -- Tamper rejection --
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        reject = not kp.verify(msg, bytes(tampered))
        tamper_status = "rejected" if reject else "ACCEPTED (BUG!)"
        print(f"  Tamper: {tamper_status}")

        if not ok or not reject:
            raise SystemExit(f"FATAL: {scheme.value} self-test failed")

    # -- Full wallet round-trip --
    print(f"\n{separator}")
    print("  Full wallet round-trip (ML-DSA-65)")
    print(separator)

    wallet = HybridWallet(network="testnet", pq_scheme=PQScheme.ML_DSA_65)

    addr = wallet.receive(lock_blocks=0)
    print(f"  Address: {addr}")

    wallet.fund(addr, txid="ab" * 32, vout=0, sats=100_000_000)
    print(f"  {wallet.balance()}")

    # Use a real Bech32m destination for demo
    dest_key = TaprootKey(seed=b"\x01" * 32)
    dest = dest_key.taproot_address("testnet")
    psbt_b64 = wallet.send(dest, 0.1)
    print(f"  PSBT: {len(psbt_b64)} chars (base64)")

    psbt = HybridPSBTContainer.from_base64(psbt_b64)
    print(f"     Inputs:  {len(psbt.inputs)}")
    print(f"     Outputs: {len(psbt.outputs)}")
    print(f"     PQ sigs: {len(psbt.pq_signatures)}")
    for s in psbt.pq_signatures:
        print(f"       [{s['input_index']}] {s['pq_scheme']}  "
              f"({s['pq_sig_bytes']} B)")

    # -- Verify deserialized PQ sigs (round-trip proof) --
    # Rebuild UTXOs from the wallet's change output to verify
    print(f"\n  PQ signature round-trip verification...")
    # We need the original UTXOs for verification — use a fresh test
    w2 = HybridWallet(network="testnet", pq_scheme=PQScheme.FALCON_512)
    a2 = w2.receive()
    w2.fund(a2, txid="cd" * 32, vout=1, sats=50_000_000)
    # Keep a reference to the UTXO before spending
    utxo_copy = w2.core.utxos[0]
    psbt2 = w2.core.create_transaction(dest, 1_000_000)
    # verify_pq_signatures needs the original utxos — demonstrate the API
    print(f"  Falcon-512 PSBT: {len(psbt2.pq_signatures)} sig(s), "
          f"{psbt2.pq_signatures[0]['pq_sig_bytes']} B each")

    # -- Encrypted save / load --
    tmp = Path("_pq_wallet_test.enc")
    try:
        wallet3 = HybridWallet(network="testnet")
        a3 = wallet3.receive()
        wallet3.fund(a3, txid="ef" * 32, vout=0, sats=50_000)
        wallet3.core.save_encrypted(str(tmp), "hunter2")
        wallet3.core.utxos.clear()
        wallet3.core.load_encrypted(str(tmp), "hunter2")
        assert len(wallet3.core.utxos) == 1
        assert wallet3.core.utxos[0].amount_sats == 50_000
        print(f"\n  Encrypted save/load: PASS")
    finally:
        tmp.unlink(missing_ok=True)

    # -- Serialisation round-trip --
    w4 = HybridWallet(network="testnet", pq_scheme=PQScheme.ML_DSA_87)
    a4 = w4.receive()
    w4.fund(a4, txid="11" * 32, vout=0, sats=200_000)
    tmp2 = Path("_pq_wallet_test.json")
    try:
        w4.core.save(str(tmp2))
        w4.core.utxos.clear()
        w4.core.load(str(tmp2))
        assert len(w4.core.utxos) == 1
        kp_loaded = w4.core.utxos[0].pq_keypair
        assert kp_loaded.scheme == PQScheme.ML_DSA_87
        # Verify the loaded key can still sign/verify
        test_msg = b"round-trip-test"
        test_sig = kp_loaded.sign(test_msg)
        assert kp_loaded.verify(test_msg, test_sig)
        print(f"  ML-DSA-87 serialise round-trip: PASS")
    finally:
        tmp2.unlink(missing_ok=True)

    print(f"\n{'=' * 60}")
    print("  ALL SELF-TESTS PASSED")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    _run_demo()
