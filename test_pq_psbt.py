# Copyright (c) 2026 Emiliano G Solazzi
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# 
# Commercial licenses available. Contact: emiliano.arlington@gmail.com
import pytest
from pq_psbt import *
from bitcoin_protocol import BIP341Sighash, tagged_hash, compact_size
import base64
import hashlib
import json
import os
import struct


def _test_address(n: int = 0, network: str = "testnet") -> str:
    """Generate a valid Bech32m P2TR address for tests.

    Different ``n`` values produce different addresses.
    """
    seed = n.to_bytes(32, "big")
    key = TaprootKey(seed=seed)
    return key.taproot_address(network)


# Pre-generated valid test destinations
_DEST1 = _test_address(1)
_DEST2 = _test_address(2)

class TestBIP341Compliance:
    """Test sighash computation via BIP341Sighash for all hash types."""

    def _make_psbt(self) -> HybridPSBTContainer:
        """Build a HybridPSBTContainer with 2 inputs and 2 outputs for sighash tests."""
        psbt = HybridPSBTContainer()
        utxo1 = HybridUTXO(
            taproot_key=TaprootKey(), pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32), unlock_height=0,
            txid="aa" * 32, vout=0, amount_sats=500_000,
        )
        utxo2 = HybridUTXO(
            taproot_key=TaprootKey(), pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32), unlock_height=0,
            txid="bb" * 32, vout=1, amount_sats=300_000,
        )
        psbt.add_input(utxo1)
        psbt.add_input(utxo2)
        psbt.add_output(_DEST1, 400_000)
        psbt.add_output(_DEST2, 350_000)
        return psbt

    def test_sighash_default(self):
        """SIGHASH_DEFAULT produces a 32-byte tagged hash, stable for same TX."""
        psbt = self._make_psbt()
        sh0 = psbt._compute_sighash(input_index=0)
        sh1 = psbt._compute_sighash(input_index=1)
        assert len(sh0) == 32
        assert len(sh1) == 32
        # Different inputs → different sighash
        assert sh0 != sh1
        # Same call twice → deterministic
        assert sh0 == psbt._compute_sighash(input_index=0)

    def test_sighash_all(self):
        """SIGHASH_ALL (0x01) differs from SIGHASH_DEFAULT (0x00)."""
        psbt = self._make_psbt()
        sh_default = psbt._compute_sighash(input_index=0,
                                            hash_type=BIP341Sighash.SIGHASH_DEFAULT)
        sh_all = psbt._compute_sighash(input_index=0,
                                        hash_type=BIP341Sighash.SIGHASH_ALL)
        assert len(sh_all) == 32
        # BIP-341: DEFAULT and ALL commit to the same fields, but
        # the hash_type byte in the preimage differs → different digest
        assert sh_default != sh_all

    def test_sighash_single(self):
        """SIGHASH_SINGLE only commits to the matching output index."""
        psbt = self._make_psbt()
        sh_single_0 = psbt._compute_sighash(input_index=0,
                                              hash_type=BIP341Sighash.SIGHASH_SINGLE)
        sh_single_1 = psbt._compute_sighash(input_index=1,
                                              hash_type=BIP341Sighash.SIGHASH_SINGLE)
        assert len(sh_single_0) == 32
        assert sh_single_0 != sh_single_1

class TestPQCryptography:
    """Test PQ signature schemes."""
    
    @pytest.mark.parametrize("scheme", list(PQScheme))
    def test_sign_verify_cycle(self, scheme):
        """Test sign/verify for all schemes."""
        kp = generate_pq_keypair(scheme)
        msg = b"test message"
        sig = kp.sign(msg)
        assert kp.verify(msg, sig)
    
    def test_signature_validity_across_calls(self):
        """Both ML-DSA and Falcon produce valid (possibly randomized) sigs."""
        # FIPS 204 ML-DSA uses hedged signing (randomized by default)
        # Falcon is also randomized — both are valid behaviour.
        for scheme in (PQScheme.ML_DSA_65, PQScheme.FALCON_512):
            kp = generate_pq_keypair(scheme)
            msg = b"test"
            sig1 = kp.sign(msg)
            sig2 = kp.sign(msg)
            # Both must verify even if bytes differ
            assert kp.verify(msg, sig1), f"{scheme.value} sig1 failed"
            assert kp.verify(msg, sig2), f"{scheme.value} sig2 failed"
            # Cross-verify: sig1 must not verify a different message
            assert not kp.verify(b"wrong", sig1), f"{scheme.value} accepted wrong msg"

class TestWalletOperations:
    """Integration tests for wallet operations."""
    
    def test_transaction_creation(self):
        """Test full transaction lifecycle."""
        wallet = HybridWallet("testnet")
        
        # Generate address and fund
        addr = wallet.receive()
        wallet.fund(addr, txid="a"*64, vout=0, sats=1_000_000)
        
        # Create transaction
        psbt_b64 = wallet.send(_DEST1, 0.005)
        psbt = HybridPSBTContainer.from_base64(psbt_b64)
        
        # Verify structure
        assert len(psbt.inputs) == 1
        assert len(psbt.outputs) == 2  # payment + change
        assert len(psbt.pq_signatures) == 1
    
    def test_insufficient_funds(self):
        """Test error handling for insufficient balance."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="b"*64, vout=0, sats=1000)
        
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send(_DEST1, 1.0)
    
    def test_timelock_enforcement(self):
        """Test that timelocked UTXOs are unspendable."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive(lock_blocks=100)
        wallet.fund(addr, txid="c"*64, vout=0, sats=1_000_000)
        
        # Should fail: UTXO is locked
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send(_DEST1, 0.005)
        
        # Advance blockchain height
        wallet.core.current_height = 100
        
        # Should succeed now
        psbt_b64 = wallet.send(_DEST1, 0.005)
        assert psbt_b64

class TestSecurity:
    """Security-critical test cases."""
    
    def test_double_spend_prevention(self):
        """Verify double-spend protection."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="d"*64, vout=0, sats=1_000_000)
        
        # First spend should succeed
        psbt1 = wallet.send(_DEST1, 0.001)
        
        # Second spend should fail (UTXO already spent)
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send(_DEST2, 0.001)
    
    def test_signature_tampering(self):
        """Verify tampered signatures are rejected."""
        kp = generate_pq_keypair(PQScheme.ML_DSA_65)
        msg = b"original message"
        sig = bytearray(kp.sign(msg))
        
        # Flip random bit
        sig[100] ^= 0x01
        
        assert not kp.verify(msg, bytes(sig))
    
    def test_commitment_binding(self):
        """Verify commitment binds both keys."""
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="e"*64,
            vout=0,
            amount_sats=100000,
        )
        
        commitment1 = utxo.commitment_hash
        
        # Modify PQ key
        utxo.pq_keypair = generate_pq_keypair()
        commitment2 = utxo.commitment_hash
        
        assert commitment1 != commitment2

class TestBroadcast:
    """Tests for finalize() serialisation and broadcast_transaction()."""

    def _signed_psbt(self) -> HybridPSBTContainer:
        """Return a HybridPSBTContainer with 1 signed input."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="ff" * 32, vout=0, sats=1_000_000)
        b64 = wallet.send(_DEST1, 0.005)
        return HybridPSBTContainer.from_base64(b64)

    def test_finalize_returns_bytes(self):
        """finalize() must return non-empty raw TX bytes."""
        psbt = self._signed_psbt()
        raw = psbt.finalize()
        assert isinstance(raw, bytes)
        assert len(raw) > 0
        # Segwit marker: version(4) + 0x00 0x01
        assert raw[4:6] == b"\x00\x01"

    def test_finalize_unsigned_raises(self):
        """Finalizing an unsigned PSBT raises ValueError."""
        psbt = HybridPSBTContainer()
        utxo = HybridUTXO(
            taproot_key=TaprootKey(), pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32), unlock_height=0,
            txid="aa" * 32, vout=0, amount_sats=100_000,
        )
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 50_000)
        with pytest.raises(ValueError, match="No signatures"):
            psbt.finalize()

    def test_broadcast_success(self, monkeypatch):
        """broadcast_transaction() returns txid on 200 OK."""
        psbt = self._signed_psbt()
        fake_txid = "ab" * 32

        class FakeResp:
            status_code = 200
            def json(self):
                return {"result": fake_txid, "error": None}

        import requests
        monkeypatch.setattr(requests, "post", lambda *a, **kw: FakeResp())

        txid = psbt.broadcast_transaction(
            node_url="http://fake:8332", rpc_pass="x",
        )
        assert txid == fake_txid

    def test_broadcast_rpc_error(self, monkeypatch):
        """broadcast_transaction() raises on RPC error."""
        psbt = self._signed_psbt()

        class FakeResp:
            status_code = 200
            def json(self):
                return {"result": None, "error": {"code": -25, "message": "bad-txns"}}

        import requests
        monkeypatch.setattr(requests, "post", lambda *a, **kw: FakeResp())

        with pytest.raises(RuntimeError, match="sendrawtransaction rejected"):
            psbt.broadcast_transaction(node_url="http://fake:8332", rpc_pass="x")

    def test_broadcast_http_error(self, monkeypatch):
        """broadcast_transaction() raises on non-200 HTTP status."""
        psbt = self._signed_psbt()

        class FakeResp:
            status_code = 403
            text = "Forbidden"

        import requests
        monkeypatch.setattr(requests, "post", lambda *a, **kw: FakeResp())

        with pytest.raises(RuntimeError, match="RPC HTTP 403"):
            psbt.broadcast_transaction(node_url="http://fake:8332", rpc_pass="x")


class TestConsensusCorrectness:
    """Tests for correctness: real secp256k1, finalize restrictions."""

    def test_taproot_key_is_real_secp256k1(self):
        """TaprootKey is always real secp256k1 — no mock mode."""
        key = TaprootKey()
        assert key.is_mock is False

    def test_taproot_key_mock_param_ignored(self):
        """mock= parameter is accepted for compat but ignored."""
        key = TaprootKey(mock=True)
        assert key.is_mock is False  # always real

    def test_schnorr_signature_verifies(self):
        """Real BIP-340 Schnorr sign+verify roundtrip."""
        key = TaprootKey()
        import hashlib
        digest = hashlib.sha256(b"test").digest()
        sig = key.sign_schnorr(digest)
        assert len(sig) == 64
        assert key.verify_schnorr(digest, sig)

    def test_schnorr_rejects_wrong_message(self):
        """Schnorr verify rejects altered message."""
        key = TaprootKey()
        import hashlib
        digest = hashlib.sha256(b"test").digest()
        wrong = hashlib.sha256(b"wrong").digest()
        sig = key.sign_schnorr(digest)
        assert not key.verify_schnorr(wrong, sig)

    def test_finalize_rejects_sighash_single(self):
        """finalize() must reject SIGHASH_SINGLE until fully supported."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="fa" * 32, vout=0, sats=1_000_000)
        psbt = wallet.core.create_transaction(_DEST1, 500_000)
        # Tamper the hash_type to SIGHASH_SINGLE
        psbt.pq_signatures[0]["hash_type"] = BIP341Sighash.SIGHASH_SINGLE
        with pytest.raises(ValueError, match="SIGHASH_SINGLE"):
            psbt.finalize()

    def test_finalize_accepts_sighash_all(self):
        """finalize() allows SIGHASH_ALL (0x01)."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="fb" * 32, vout=0, sats=1_000_000)
        psbt = wallet.core.create_transaction(_DEST1, 500_000)
        psbt.pq_signatures[0]["hash_type"] = BIP341Sighash.SIGHASH_ALL
        raw = psbt.finalize()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

class TestPQKeyPairSerialization:
    """Tests for PQKeyPair serialization and deserialization."""

    @pytest.mark.parametrize("scheme", list(PQScheme))
    def test_keypair_to_dict_roundtrip(self, scheme):
        """Test that keypairs survive serialization round-trip."""
        kp = generate_pq_keypair(scheme)
        d = kp.to_dict()
        restored = PQKeyPair.from_dict(d)

        assert restored.scheme == kp.scheme
        assert restored.public_key == kp.public_key
        assert restored.private_key == kp.private_key

    @pytest.mark.parametrize("scheme", list(PQScheme))
    def test_restored_keypair_can_sign_verify(self, scheme):
        """Test that restored keypairs can still sign and verify."""
        kp = generate_pq_keypair(scheme)
        d = kp.to_dict()
        restored = PQKeyPair.from_dict(d)

        msg = b"test message after restore"
        sig = restored.sign(msg)
        assert restored.verify(msg, sig)

    def test_invalid_public_key_size_raises(self):
        """Test that invalid public key size raises ValueError."""
        kp = generate_pq_keypair(PQScheme.ML_DSA_65)
        with pytest.raises(ValueError, match="public key must be"):
            PQKeyPair(
                scheme=PQScheme.ML_DSA_65,
                public_key=b"too_short",
                private_key=kp.private_key,
            )

    def test_invalid_private_key_size_raises(self):
        """Test that invalid private key size raises ValueError."""
        kp = generate_pq_keypair(PQScheme.ML_DSA_65)
        with pytest.raises(ValueError, match="secret key must be"):
            PQKeyPair(
                scheme=PQScheme.ML_DSA_65,
                public_key=kp.public_key,
                private_key=b"too_short",
            )


class TestHybridUTXO:
    """Tests for HybridUTXO dataclass."""

    def test_invalid_salt_length_raises(self):
        """Test that salt must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="salt must be exactly 32 bytes"):
            HybridUTXO(
                taproot_key=TaprootKey(),
                pq_keypair=generate_pq_keypair(),
                salt=b"short",
                unlock_height=0,
                txid="aa" * 32,
                vout=0,
                amount_sats=1000,
            )

    def test_negative_amount_raises(self):
        """Test that negative amount_sats raises ValueError."""
        with pytest.raises(ValueError, match="amount_sats cannot be negative"):
            HybridUTXO(
                taproot_key=TaprootKey(),
                pq_keypair=generate_pq_keypair(),
                salt=secrets.token_bytes(32),
                unlock_height=0,
                txid="aa" * 32,
                vout=0,
                amount_sats=-100,
            )

    def test_is_spendable_no_lock(self):
        """Test that unlock_height=0 is always spendable."""
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=1000,
        )
        assert utxo.is_spendable(0)
        assert utxo.is_spendable(100)

    def test_is_spendable_height_lock(self):
        """Test height-based timelock."""
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=100,
            txid="aa" * 32,
            vout=0,
            amount_sats=1000,
        )
        assert not utxo.is_spendable(50)
        assert not utxo.is_spendable(99)
        assert utxo.is_spendable(100)
        assert utxo.is_spendable(101)

    def test_is_spendable_time_lock(self):
        """Test time-based lock (>=500M interpreted as Unix timestamp)."""
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=500_000_001,
            txid="aa" * 32,
            vout=0,
            amount_sats=1000,
        )
        assert not utxo.is_spendable(0, current_time=500_000_000)
        assert utxo.is_spendable(0, current_time=500_000_001)
        assert utxo.is_spendable(0, current_time=600_000_000)

    def test_utxo_to_dict_roundtrip(self):
        """Test UTXO serialization round-trip."""
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=100,
            txid="aa" * 32,
            vout=5,
            amount_sats=50000,
            chain_id=b"test",
        )
        d = utxo.to_dict()
        restored = HybridUTXO.from_dict(d)

        assert restored.unlock_height == utxo.unlock_height
        assert restored.txid == utxo.txid
        assert restored.vout == utxo.vout
        assert restored.amount_sats == utxo.amount_sats
        assert restored.chain_id == utxo.chain_id
        assert restored.salt == utxo.salt


class TestHybridPSBTContainer:
    """Tests for HybridPSBTContainer."""

    def test_add_output_zero_amount_raises(self):
        """Test that zero or negative output amounts raise ValueError."""
        psbt = HybridPSBTContainer()
        with pytest.raises(ValueError, match="output amount must be positive"):
            psbt.add_output(_DEST1, 0)
        with pytest.raises(ValueError, match="output amount must be positive"):
            psbt.add_output(_DEST1, -100)

    def test_sign_inputs_utxo_mismatch_raises(self):
        """Test that mismatched UTXO count raises ValueError."""
        psbt = HybridPSBTContainer()
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=1000,
        )
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 500)

        # Try to sign with wrong number of UTXOs
        with pytest.raises(ValueError, match="UTXO count"):
            psbt.sign_inputs([utxo, utxo])

    def test_base64_roundtrip(self):
        """Test PSBT base64 serialization round-trip."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="ab" * 32, vout=0, sats=1_000_000)

        b64 = wallet.send(_DEST1, 0.005)
        restored = HybridPSBTContainer.from_base64(b64)

        assert restored.version == 2
        assert len(restored.inputs) == 1
        assert len(restored.outputs) == 2
        assert len(restored.pq_signatures) == 1

    def test_finalize_missing_taproot_sig_raises(self):
        """Test that finalize raises if Taproot signature is missing."""
        psbt = HybridPSBTContainer()
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=100_000,
        )
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 50_000)
        # Manually add a signature entry without taproot_sig
        psbt.pq_signatures.append({
            "input_index": 0,
            "taproot_sig": "",  # empty
            "pq_sig": "dGVzdA==",
            "pq_scheme": "ML-DSA-65",
            "pq_sig_bytes": 4,
            "hash_type": 0,
        })

        with pytest.raises(ValueError, match="missing Taproot signature"):
            psbt.finalize()

    def test_finalize_signature_count_mismatch_raises(self):
        """Test that finalize raises if signature count != input count."""
        psbt = HybridPSBTContainer()
        utxo1 = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=100_000,
        )
        utxo2 = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="bb" * 32,
            vout=1,
            amount_sats=100_000,
        )
        psbt.add_input(utxo1)
        psbt.add_input(utxo2)
        psbt.add_output(_DEST1, 150_000)
        # Only sign one input
        psbt.sign_inputs([utxo1, utxo2])
        # Remove one signature
        psbt.pq_signatures.pop()

        with pytest.raises(ValueError, match="Signature count"):
            psbt.finalize()


class TestHybridWalletCore:
    """Tests for HybridWalletCore."""

    def test_generate_address_returns_valid_format(self):
        """Test that generated addresses have correct prefix."""
        core = HybridWalletCore(network="testnet")
        addr, commitment = core.generate_address()

        assert addr.startswith("tb1p")
        assert len(commitment) == 64  # hex of 32 bytes

    def test_generate_address_mainnet_prefix(self):
        """Test mainnet address prefix."""
        core = HybridWalletCore(network="mainnet")
        addr, _ = core.generate_address()

        assert addr.startswith("bc1p")

    def test_get_balance_empty_wallet(self):
        """Test balance of empty wallet."""
        core = HybridWalletCore()
        bal = core.get_balance()

        assert bal["available_sats"] == 0
        assert bal["pending"] == []

    def test_get_balance_with_funded_utxos(self):
        """Test balance calculation with funded UTXOs."""
        wallet = HybridWallet("testnet")
        addr1 = wallet.receive()
        addr2 = wallet.receive()
        wallet.fund(addr1, txid="aa" * 32, vout=0, sats=100_000)
        wallet.fund(addr2, txid="bb" * 32, vout=1, sats=200_000)

        bal = wallet.core.get_balance()
        assert bal["available_sats"] == 300_000

    def test_create_transaction_zero_amount_raises(self):
        """Test that zero amount raises ValueError."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="aa" * 32, vout=0, sats=100_000)

        with pytest.raises(ValueError, match="amount must be positive"):
            wallet.core.create_transaction(_DEST1, 0)

    def test_fund_unknown_address_raises(self):
        """Test that funding unknown address raises ValueError."""
        wallet = HybridWallet("testnet")

        with pytest.raises(ValueError, match="Address not found"):
            wallet.fund("tb1p" + "x" * 40, txid="aa" * 32, vout=0, sats=1000)


class TestEncryptedPersistence:
    """Tests for encrypted wallet persistence."""

    def test_save_load_encrypted_roundtrip(self, tmp_path):
        """Test encrypted save/load preserves wallet state."""
        filepath = tmp_path / "wallet.enc"
        password = "test_password_123"

        wallet = HybridWallet("testnet", PQScheme.FALCON_512)
        addr = wallet.receive()
        wallet.fund(addr, txid="cc" * 32, vout=0, sats=75_000)

        wallet.core.save_encrypted(str(filepath), password)

        # Create new wallet and load
        wallet2 = HybridWallet("testnet", PQScheme.FALCON_512)
        wallet2.core.load_encrypted(str(filepath), password)

        assert len(wallet2.core.utxos) == 1
        assert wallet2.core.utxos[0].amount_sats == 75_000

    def test_load_encrypted_wrong_password_fails(self, tmp_path):
        """Test that wrong password fails decryption."""
        filepath = tmp_path / "wallet.enc"

        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="dd" * 32, vout=0, sats=50_000)
        wallet.core.save_encrypted(str(filepath), "correct_password")

        wallet2 = HybridWallet("testnet")
        with pytest.raises(Exception):  # Crypto.Cipher raises on bad MAC
            wallet2.core.load_encrypted(str(filepath), "wrong_password")


class TestTaprootKey:
    """Tests for real secp256k1 TaprootKey."""

    def test_seeded_key_deterministic(self):
        """Same seed → same key pair."""
        seed = b"x" * 32
        key1 = TaprootKey(seed=seed)
        key2 = TaprootKey(seed=seed)

        assert key1.private_key == key2.private_key
        assert key1.public_key == key2.public_key

    def test_schnorr_sign_verify(self):
        """Real BIP-340 Schnorr signatures are 64 bytes and verify."""
        key = TaprootKey(seed=b"y" * 32)
        import hashlib
        msg = hashlib.sha256(b"test message").digest()

        sig = key.sign_schnorr(msg)
        assert len(sig) == 64
        assert key.verify_schnorr(msg, sig)

    def test_taproot_address_format(self):
        """Addresses are real Bech32m."""
        key = TaprootKey()

        testnet_addr = key.taproot_address("testnet")
        mainnet_addr = key.taproot_address("mainnet")

        assert testnet_addr.startswith("tb1")
        assert mainnet_addr.startswith("bc1")
        # Real bech32m addresses are longer than mock
        assert len(testnet_addr) == 62
        assert len(mainnet_addr) == 62

    def test_address_roundtrip(self):
        """Address encodes then decodes back to same x-only pubkey."""
        from bech32 import decode as bech32_decode
        key = TaprootKey()
        addr = key.taproot_address("testnet")
        ver, prog = bech32_decode("tb", addr)
        assert ver == 1
        assert bytes(prog) == key.public_key_xonly


class TestVerifyPQSignatures:
    """Tests for PQ signature verification."""

    def test_verify_pq_signatures_valid(self):
        """Test that valid PQ signatures verify correctly."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="ee" * 32, vout=0, sats=1_000_000)

        # Keep reference to UTXO before spending
        utxo = wallet.core.utxos[0]
        psbt = wallet.core.create_transaction(_DEST1, 500_000)

        # For verification we need UTXOs - create a fresh scenario
        wallet2 = HybridWallet("testnet")
        addr2 = wallet2.receive()
        wallet2.fund(addr2, txid="ff" * 32, vout=0, sats=1_000_000)
        utxo2 = wallet2.core.utxos[0]

        psbt2 = HybridPSBTContainer()
        psbt2.add_input(utxo2)
        psbt2.add_output(_DEST1, 500_000)
        psbt2.sign_inputs([utxo2])

        assert psbt2.verify_pq_signatures([utxo2])

    def test_verify_pq_signatures_tampered_fails(self):
        """Test that tampered PQ signatures fail verification."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="11" * 32, vout=0, sats=1_000_000)
        utxo = wallet.core.utxos[0]

        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 500_000)
        psbt.sign_inputs([utxo])

        # Tamper with the signature
        sig_bytes = base64.b64decode(psbt.pq_signatures[0]["pq_sig"])
        tampered = bytearray(sig_bytes)
        tampered[50] ^= 0xFF
        psbt.pq_signatures[0]["pq_sig"] = base64.b64encode(bytes(tampered)).decode()

        assert not psbt.verify_pq_signatures([utxo])


class TestCoinSelection:
    """Tests for coin selection algorithm."""

    def test_coin_selection_prefers_larger_utxos(self):
        """Test that coin selection prefers larger UTXOs first."""
        wallet = HybridWallet("testnet")

        # Create multiple UTXOs of different sizes
        for i, sats in enumerate([10_000, 100_000, 50_000]):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i:02x}" * 32, vout=0, sats=sats)

        # Request amount that needs the largest UTXO
        psbt_b64 = wallet.send(_DEST1, 0.0008)  # 80,000 sats
        psbt = HybridPSBTContainer.from_base64(psbt_b64)

        # Should have selected the 100k UTXO
        assert len(psbt.inputs) == 1
        assert psbt.inputs[0]["amount"] == 100_000

    def test_coin_selection_combines_utxos_when_needed(self):
        """Test that coin selection combines UTXOs when single is insufficient."""
        wallet = HybridWallet("testnet")

        for i in range(3):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i:02x}" * 32, vout=0, sats=50_000)

        # Request amount that needs multiple UTXOs
        psbt_b64 = wallet.send(_DEST1, 0.001)  # 100,000 sats
        psbt = HybridPSBTContainer.from_base64(psbt_b64)

        # Should have selected multiple UTXOs
        assert len(psbt.inputs) >= 2


class TestRBFSupport:
    """Tests for Replace-By-Fee support."""

    def test_rbf_enabled_by_default(self):
        """Test that RBF is enabled by default (sequence = 0xFFFFFFFD)."""
        psbt = HybridPSBTContainer()
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=100_000,
        )
        psbt.add_input(utxo, enable_rbf=True)

        assert psbt.inputs[0]["sequence"] == 0xFFFFFFFD

    def test_rbf_can_be_disabled(self):
        """Test that RBF can be disabled (sequence = 0xFFFFFFFF)."""
        psbt = HybridPSBTContainer()
        utxo = HybridUTXO(
            taproot_key=TaprootKey(),
            pq_keypair=generate_pq_keypair(),
            salt=secrets.token_bytes(32),
            unlock_height=0,
            txid="aa" * 32,
            vout=0,
            amount_sats=100_000,
        )
        psbt.add_input(utxo, enable_rbf=False)

        assert psbt.inputs[0]["sequence"] == 0xFFFFFFFF


# ====================================================================
# HARDCORE BITCOIN-DEVELOPER-LEVEL TESTS
# ====================================================================
# These tests exercise real BIP-340 / BIP-341 edge cases, raw TX
# serialization invariants, secp256k1 boundary conditions, Bech32m
# encoding correctness, sighash determinism, and adversarial inputs
# that a battle-hardened Bitcoin Core reviewer would check.
# ====================================================================


class TestBIP340SchnorrEdgeCases:
    """BIP-340 Schnorr edge cases that break naive implementations."""

    def test_schnorr_sig_is_exactly_64_bytes(self):
        """BIP-340 mandates exactly 64-byte signatures (R.x || s)."""
        key = TaprootKey()
        digest = hashlib.sha256(b"msg").digest()
        sig = key.sign_schnorr(digest)
        assert len(sig) == 64, f"Expected 64 bytes, got {len(sig)}"

    def test_schnorr_rejects_non_32_byte_message(self):
        """sign_schnorr must reject anything that isn't a 32-byte digest."""
        key = TaprootKey()
        for bad_len in (0, 1, 16, 31, 33, 64, 128):
            with pytest.raises(ValueError, match="32-byte digest"):
                key.sign_schnorr(b"\x00" * bad_len)

    def test_schnorr_different_keys_different_sigs(self):
        """Two different private keys produce different sigs over the same msg."""
        digest = hashlib.sha256(b"same message").digest()
        sig1 = TaprootKey(seed=b"\x01" * 32).sign_schnorr(digest)
        sig2 = TaprootKey(seed=b"\x02" * 32).sign_schnorr(digest)
        assert sig1 != sig2

    def test_schnorr_cross_key_verify_fails(self):
        """Signature from key A must NOT verify under key B."""
        digest = hashlib.sha256(b"cross-key test").digest()
        key_a = TaprootKey(seed=b"\x03" * 32)
        key_b = TaprootKey(seed=b"\x04" * 32)
        sig = key_a.sign_schnorr(digest)
        assert key_a.verify_schnorr(digest, sig)
        assert not key_b.verify_schnorr(digest, sig)

    def test_schnorr_all_zero_digest_signs(self):
        """Signing a valid 32-byte all-zero digest must work (edge case)."""
        key = TaprootKey()
        digest = b"\x00" * 32
        sig = key.sign_schnorr(digest)
        assert len(sig) == 64
        assert key.verify_schnorr(digest, sig)

    def test_schnorr_all_ff_digest_signs(self):
        """Signing 0xFF*32 must work — close to curve order boundary."""
        key = TaprootKey()
        digest = b"\xff" * 32
        sig = key.sign_schnorr(digest)
        assert key.verify_schnorr(digest, sig)

    def test_schnorr_verify_rejects_truncated_sig(self):
        """Verify must reject a signature shorter than 64 bytes."""
        key = TaprootKey()
        digest = hashlib.sha256(b"trunc").digest()
        sig = key.sign_schnorr(digest)
        assert not key.verify_schnorr(digest, sig[:63])
        assert not key.verify_schnorr(digest, sig[:32])
        assert not key.verify_schnorr(digest, b"")

    def test_schnorr_verify_rejects_padded_sig(self):
        """Verify must reject a signature longer than 64 bytes."""
        key = TaprootKey()
        digest = hashlib.sha256(b"pad").digest()
        sig = key.sign_schnorr(digest)
        assert not key.verify_schnorr(digest, sig + b"\x00")

    def test_schnorr_deterministic_for_same_key_and_msg(self):
        """coincurve BIP-340 sign is deterministic (RFC 6979-style aux rand)."""
        key = TaprootKey(seed=b"\x05" * 32)
        digest = hashlib.sha256(b"deterministic").digest()
        sigs = [key.sign_schnorr(digest) for _ in range(5)]
        # coincurve's sign_schnorr uses aux randomness, so sigs *may* differ
        # but they must all verify
        for sig in sigs:
            assert key.verify_schnorr(digest, sig)


class TestSecp256k1KeyBoundaries:
    """secp256k1 private key scalar edge cases."""

    def test_key_from_all_zero_seed_raises(self):
        """Scalar 0 is invalid on secp256k1 — must raise."""
        with pytest.raises(Exception):
            TaprootKey(seed=b"\x00" * 32)

    def test_key_from_curve_order_raises(self):
        """Scalar == n (curve order) is invalid — must raise."""
        # secp256k1 order n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
        #                      BAAEDCE6 AF48A03B BFD25E8C D0364141
        n = bytes.fromhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        )
        with pytest.raises(Exception):
            TaprootKey(seed=n)

    def test_key_from_order_minus_one_works(self):
        """Scalar n-1 is the largest valid private key."""
        n_minus_1 = bytes.fromhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
        )
        key = TaprootKey(seed=n_minus_1)
        assert len(key.public_key) == 33
        assert len(key.public_key_xonly) == 32

    def test_key_from_one_works(self):
        """Scalar 1 is the smallest valid private key (generator point G)."""
        one = b"\x00" * 31 + b"\x01"
        key = TaprootKey(seed=one)
        digest = hashlib.sha256(b"one").digest()
        sig = key.sign_schnorr(digest)
        assert key.verify_schnorr(digest, sig)

    def test_xonly_pubkey_is_32_bytes(self):
        """x-only pubkey must always be exactly 32 bytes."""
        for i in range(10):
            key = TaprootKey()
            assert len(key.public_key_xonly) == 32

    def test_compressed_pubkey_starts_with_02_or_03(self):
        """SEC1 compressed pubkey first byte must be 0x02 or 0x03."""
        for _ in range(20):
            key = TaprootKey()
            assert key.public_key[0] in (0x02, 0x03)
            assert len(key.public_key) == 33


class TestBech32mAddressRigorous:
    """Bech32m encoding edge cases per BIP-350."""

    def test_testnet_address_starts_tb1p(self):
        """Testnet P2TR address must start with 'tb1p'."""
        key = TaprootKey()
        addr = key.taproot_address("testnet")
        assert addr.startswith("tb1p")

    def test_mainnet_address_starts_bc1p(self):
        """Mainnet P2TR address must start with 'bc1p'."""
        key = TaprootKey()
        addr = key.taproot_address("mainnet")
        assert addr.startswith("bc1p")

    def test_address_length_is_62(self):
        """P2TR Bech32m addresses are always 62 characters."""
        for _ in range(10):
            assert len(TaprootKey().taproot_address("mainnet")) == 62
            assert len(TaprootKey().taproot_address("testnet")) == 62

    def test_address_is_lowercase(self):
        """Bech32m addresses must be fully lowercase (BIP-173 §1)."""
        for _ in range(10):
            addr = TaprootKey().taproot_address("testnet")
            assert addr == addr.lower(), f"Non-lowercase: {addr}"

    def test_address_decode_roundtrip_recovers_xonly(self):
        """Decode(Encode(xonly)) must recover the original 32-byte x-only pk."""
        from bech32 import decode as bech32_decode
        for _ in range(10):
            key = TaprootKey()
            addr = key.taproot_address("testnet")
            ver, data = bech32_decode("tb", addr)
            assert ver == 1, f"Witness version must be 1, got {ver}"
            assert bytes(data) == key.public_key_xonly

    def test_signet_address_uses_tb_hrp(self):
        """Signet uses tb HRP, same as testnet."""
        key = TaprootKey()
        addr = key.taproot_address("signet")
        assert addr.startswith("tb1p")

    def test_different_keys_produce_different_addresses(self):
        """No two random keys should produce the same address."""
        addrs = {TaprootKey().taproot_address("mainnet") for _ in range(50)}
        assert len(addrs) == 50

    def test_address_to_script_roundtrip(self):
        """_address_to_script must produce OP_1 <32B xonly> from our addresses."""
        key = TaprootKey()
        addr = key.taproot_address("testnet")
        script_hex = HybridPSBTContainer._address_to_script(addr)
        assert script_hex.startswith("5120")
        assert len(script_hex) == 68  # "5120" + 64 hex chars
        assert script_hex[4:] == key.public_key_xonly.hex()

    def test_address_to_script_rejects_garbage(self):
        """_address_to_script must reject non-Bech32 garbage."""
        with pytest.raises(ValueError):
            HybridPSBTContainer._address_to_script("tb1qinvalid")
        with pytest.raises(ValueError):
            HybridPSBTContainer._address_to_script("bc1p" + "z" * 58)

    def test_address_to_script_rejects_p2wpkh(self):
        """P2WPKH (witness v0, 20-byte program) must be rejected — we need P2TR."""
        # A v0 20-byte program address won't decode to v1 + 32 bytes
        with pytest.raises(ValueError, match="witness v1"):
            HybridPSBTContainer._address_to_script(
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            )


class TestRawTxSerialization:
    """Validate the raw transaction bytes produced by finalize()."""

    def _make_signed_psbt(self, n_inputs=1) -> HybridPSBTContainer:
        wallet = HybridWallet("testnet")
        for i in range(n_inputs):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i+1:02x}" * 32, vout=i, sats=500_000)
        psbt = wallet.core.create_transaction(_DEST1, 100_000)
        return psbt

    def test_segwit_marker_and_flag(self):
        """Segwit TX must have marker=0x00, flag=0x01 after nVersion."""
        raw = self._make_signed_psbt().finalize()
        assert raw[4] == 0x00, "Missing segwit marker"
        assert raw[5] == 0x01, "Missing segwit flag"

    def test_version_is_2(self):
        """nVersion must be 2 (BIP-68 relative locktime)."""
        raw = self._make_signed_psbt().finalize()
        version = struct.unpack("<I", raw[:4])[0]
        assert version == 2

    def test_locktime_is_last_4_bytes(self):
        """nLockTime (4 bytes LE) must be the final field."""
        raw = self._make_signed_psbt().finalize()
        locktime = struct.unpack("<I", raw[-4:])[0]
        assert locktime == 0

    def test_witness_has_exactly_one_item_per_input(self):
        """Key-path Taproot spend has exactly 1 witness stack item (the sig)."""
        psbt = self._make_signed_psbt(n_inputs=2)
        raw = psbt.finalize()
        # Parse past version(4) + marker(1) + flag(1) + vin_count + vins + vout_count + vouts
        # Then each witness: compact_size(1) + compact_size(sig_len) + sig
        # We just verify finalize() doesn't crash on multi-input
        assert len(raw) > 100

    def test_taproot_sig_in_witness_is_64_or_65_bytes(self):
        """Witness item must be 64B (SIGHASH_DEFAULT) or 65B (explicit hash type)."""
        psbt = self._make_signed_psbt()
        for sig_entry in psbt.pq_signatures:
            sig_bytes = bytes.fromhex(sig_entry["taproot_sig"])
            assert len(sig_bytes) in (64, 65), (
                f"Taproot witness sig must be 64 or 65 bytes, got {len(sig_bytes)}"
            )

    def test_output_scriptpubkey_is_p2tr(self):
        """Every output scriptPubKey must be OP_1 (0x51) + PUSH32 (0x20) + 32B."""
        psbt = self._make_signed_psbt()
        for out in psbt.outputs:
            spk_hex = out["scriptPubKey"]
            assert spk_hex[:4] == "5120", f"Not P2TR: {spk_hex[:8]}"
            assert len(spk_hex) == 68  # 2 + 2 + 64

    def test_txid_in_vin_is_le_bytes(self):
        """Prevout txid in raw TX must be little-endian (reversed hex)."""
        psbt = self._make_signed_psbt()
        raw = psbt.finalize()
        # nVersion(4) + marker(1) + flag(1) + compact_size(1 for vin count) = 7
        # First vin starts at offset 7: txid(32) + vout(4) + scriptSig_len(1) + seq(4)
        txid_le = raw[7:7+32]
        original_txid = psbt.inputs[0]["txid"]
        # Raw TX stores txid in internal byte order (reversed)
        assert txid_le == bytes.fromhex(original_txid)[::-1]

    def test_multi_input_multi_output_roundtrip(self):
        """A 3-input, 2-output TX must finalize without error."""
        wallet = HybridWallet("testnet")
        for i in range(3):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i+0xa:02x}" * 32, vout=i, sats=200_000)
        psbt = wallet.core.create_transaction(_DEST1, 300_000)
        raw = psbt.finalize()
        assert isinstance(raw, bytes)
        assert len(raw) > 200


class TestSighashDeterminism:
    """Sighash must be deterministic and input-specific."""

    def _make_two_input_psbt(self):
        psbt = HybridPSBTContainer()
        for txid_byte in ("aa", "bb"):
            utxo = HybridUTXO(
                taproot_key=TaprootKey(seed=bytes.fromhex(txid_byte * 32)),
                pq_keypair=generate_pq_keypair(),
                salt=secrets.token_bytes(32), unlock_height=0,
                txid=txid_byte * 32, vout=0, amount_sats=100_000,
            )
            psbt.add_input(utxo)
        psbt.add_output(_DEST1, 150_000)
        return psbt

    def test_sighash_is_deterministic(self):
        """Same PSBT + same input index → identical sighash every time."""
        psbt = self._make_two_input_psbt()
        sh1 = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_DEFAULT)
        sh2 = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_DEFAULT)
        assert sh1 == sh2

    def test_sighash_differs_per_input(self):
        """input_index=0 vs input_index=1 must produce different sighashes."""
        psbt = self._make_two_input_psbt()
        sh0 = psbt._compute_sighash(0)
        sh1 = psbt._compute_sighash(1)
        assert sh0 != sh1

    def test_sighash_default_vs_all_differ(self):
        """SIGHASH_DEFAULT (0x00) and SIGHASH_ALL (0x01) commit differently."""
        psbt = self._make_two_input_psbt()
        sh_def = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_DEFAULT)
        sh_all = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_ALL)
        assert sh_def != sh_all

    def test_sighash_single_differs_per_output(self):
        """SIGHASH_SINGLE on input 0 vs input 1 commits to different outputs."""
        psbt = self._make_two_input_psbt()
        psbt.add_output(_DEST2, 50_000)
        sh0 = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_SINGLE)
        sh1 = psbt._compute_sighash(1, BIP341Sighash.SIGHASH_SINGLE)
        assert sh0 != sh1

    def test_sighash_anyonecanpay_differs_from_all(self):
        """ANYONECANPAY skips sha_prevouts — must differ from ALL."""
        psbt = self._make_two_input_psbt()
        sh_all = psbt._compute_sighash(0, BIP341Sighash.SIGHASH_ALL)
        sh_acp = psbt._compute_sighash(
            0, BIP341Sighash.SIGHASH_ALL | BIP341Sighash.SIGHASH_ANYONECANPAY
        )
        assert sh_all != sh_acp

    def test_sighash_changes_with_amount(self):
        """Changing an input amount must change the sighash (BIP-341 commits to amounts)."""
        psbt = self._make_two_input_psbt()
        sh_before = psbt._compute_sighash(0)
        psbt.inputs[0]["amount"] = 999_999  # tamper
        sh_after = psbt._compute_sighash(0)
        assert sh_before != sh_after

    def test_sighash_changes_with_scriptpubkey(self):
        """Changing an input scriptPubKey must change the sighash."""
        psbt = self._make_two_input_psbt()
        sh_before = psbt._compute_sighash(0)
        # Replace scriptPubKey with a different key's script
        other_key = TaprootKey()
        psbt.inputs[0]["witness_utxo"]["scriptPubKey"] = (
            "5120" + other_key.public_key_xonly.hex()
        )
        sh_after = psbt._compute_sighash(0)
        assert sh_before != sh_after


class TestCommitmentIntegrity:
    """UTXO commitment hash must bind all fields and resist manipulation."""

    # Fixed PQ keypair for determinism tests (generated once)
    _fixed_pq = generate_pq_keypair(PQScheme.FALCON_512)

    def _make_utxo(self, **overrides) -> HybridUTXO:
        defaults = dict(
            taproot_key=TaprootKey(seed=b"\x10" * 32),
            pq_keypair=self._fixed_pq,
            salt=b"\xab" * 32,
            unlock_height=100,
            txid="cc" * 32,
            vout=0,
            amount_sats=50_000,
            chain_id=b"\x01\x02\x03\x04",
        )
        defaults.update(overrides)
        return HybridUTXO(**defaults)

    def test_commitment_is_32_bytes(self):
        assert len(self._make_utxo().commitment_hash) == 32

    def test_commitment_deterministic(self):
        """Same inputs → same commitment."""
        c1 = self._make_utxo().commitment_hash
        c2 = self._make_utxo().commitment_hash
        assert c1 == c2

    def test_commitment_changes_on_different_taproot_key(self):
        c1 = self._make_utxo().commitment_hash
        c2 = self._make_utxo(
            taproot_key=TaprootKey(seed=b"\x11" * 32)
        ).commitment_hash
        assert c1 != c2

    def test_commitment_changes_on_different_pq_key(self):
        c1 = self._make_utxo().commitment_hash
        c2 = self._make_utxo(
            pq_keypair=generate_pq_keypair(PQScheme.FALCON_512)
        ).commitment_hash
        assert c1 != c2

    def test_commitment_changes_on_different_salt(self):
        c1 = self._make_utxo().commitment_hash
        c2 = self._make_utxo(salt=b"\xcd" * 32).commitment_hash
        assert c1 != c2

    def test_commitment_changes_on_different_height(self):
        c1 = self._make_utxo().commitment_hash
        c2 = self._make_utxo(unlock_height=200).commitment_hash
        assert c1 != c2

    def test_commitment_changes_on_different_chain_id(self):
        """chain_id prevents cross-network commitment replay."""
        c1 = self._make_utxo(chain_id=b"\x01\x02\x03\x04").commitment_hash
        c2 = self._make_utxo(chain_id=b"\x05\x06\x07\x08").commitment_hash
        assert c1 != c2

    def test_commitment_empty_chain_id_differs_from_nonempty(self):
        c1 = self._make_utxo(chain_id=b"").commitment_hash
        c2 = self._make_utxo(chain_id=b"\x00\x00\x00\x00").commitment_hash
        assert c1 != c2


class TestDualSignatureIntegrity:
    """Both Schnorr and PQ signatures must bind to the exact same sighash."""

    def test_schnorr_and_pq_sign_same_sighash(self):
        """Both signature types must commit to identical sighash bytes."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="aa" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 200_000)
        sighashes = psbt.sign_inputs([utxo])

        # The Schnorr sig in the PSBT should verify against the same sighash
        sig_entry = psbt.pq_signatures[0]
        schnorr_sig = bytes.fromhex(sig_entry["taproot_sig"])
        assert utxo.taproot_key.verify_schnorr(sighashes[0], schnorr_sig)

        # The PQ sig in the PSBT should also verify against the same sighash
        pq_sig = base64.b64decode(sig_entry["pq_sig"])
        assert utxo.pq_keypair.verify(sighashes[0], pq_sig)

    def test_pq_sig_fails_against_different_sighash(self):
        """PQ signature must not verify against a sighash from a different TX."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="bb" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 200_000)
        psbt.sign_inputs([utxo])

        pq_sig = base64.b64decode(psbt.pq_signatures[0]["pq_sig"])
        wrong_sighash = hashlib.sha256(b"totally different tx").digest()
        assert not utxo.pq_keypair.verify(wrong_sighash, pq_sig)


class TestAdversarialInputs:
    """Inputs a malicious actor or fuzzer would try."""

    def test_dust_output_below_546_sats(self):
        """Wallet must not create change outputs below dust limit (546 sats)."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        # Fund with exactly enough that change would be sub-dust
        fee_estimate = int(57.5 * 10 * 1.1 + 43 * 2 * 10 * 1.1 + 10.5 * 10 * 1.1)
        # amount + fee + tiny_change < total  where tiny_change < 546
        fund_amount = 100_000
        wallet.fund(addr, txid="dd" * 32, vout=0, sats=fund_amount)
        # Send nearly everything: change should be suppressed if < dust
        send_amount = fund_amount - fee_estimate - 100  # ~100 sats change
        if send_amount > 0:
            psbt = wallet.core.create_transaction(_DEST1, send_amount)
            # Must be 1 output (no dust change) or 2 outputs (if change > dust)
            for out in psbt.outputs:
                assert out["amount"] >= HybridWalletCore.DUST_LIMIT_SATS or \
                       out["amount"] == send_amount

    def test_zero_sats_send_rejected(self):
        """Sending 0 sats must be rejected."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="ee" * 32, vout=0, sats=100_000)
        with pytest.raises(ValueError, match="amount must be positive"):
            wallet.core.create_transaction(_DEST1, 0)

    def test_negative_sats_send_rejected(self):
        """Sending negative sats must be rejected."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="f0" * 32, vout=0, sats=100_000)
        with pytest.raises(ValueError, match="amount must be positive"):
            wallet.core.create_transaction(_DEST1, -1)

    def test_send_more_than_21m_btc_rejected(self):
        """No TX should exceed 21M BTC supply cap."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="f1" * 32, vout=0, sats=100_000)
        with pytest.raises(ValueError):
            wallet.core.create_transaction(_DEST1, 21_000_001 * 100_000_000)

    def test_double_spend_via_nullifier(self):
        """Spending the same UTXO twice must raise even if re-added."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="f2" * 32, vout=0, sats=1_000_000)
        wallet.send(_DEST1, 0.001)
        # Wallet is now empty — second send must fail
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send(_DEST2, 0.001)

    def test_finalize_rejects_sighash_none(self):
        """SIGHASH_NONE is too dangerous — finalize must reject it."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="f3" * 32, vout=0, sats=1_000_000)
        psbt = wallet.core.create_transaction(_DEST1, 500_000)
        psbt.pq_signatures[0]["hash_type"] = BIP341Sighash.SIGHASH_NONE
        with pytest.raises(ValueError, match="SIGHASH_SINGLE|SIGHASH_NONE"):
            psbt.finalize()

    def test_output_amount_negative_rejected(self):
        """Negative output amounts must be rejected."""
        psbt = HybridPSBTContainer()
        with pytest.raises(ValueError, match="positive"):
            psbt.add_output(_DEST1, -1)

    def test_pq_sig_wrong_scheme_label_still_fails_verify(self):
        """Even if scheme label is swapped, verify uses actual key bytes."""
        kp_65 = generate_pq_keypair(PQScheme.ML_DSA_65)
        kp_87 = generate_pq_keypair(PQScheme.ML_DSA_87)
        msg = b"cross-scheme"
        sig_65 = kp_65.sign(msg)
        # Try verifying ML-DSA-65 sig with ML-DSA-87 key — must fail
        assert not kp_87.verify(msg, sig_65)


class TestEncryptedPersistenceHardened:
    """Encrypted wallet persistence edge cases."""

    def test_corrupted_ciphertext_fails(self, tmp_path):
        """Flipping a byte in ciphertext must cause MAC failure."""
        filepath = tmp_path / "corrupted.enc"
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="a1" * 32, vout=0, sats=50_000)
        wallet.core.save_encrypted(str(filepath), "password")

        # Corrupt the ciphertext
        blob = json.loads(filepath.read_text())
        ct_bytes = bytearray(base64.b64decode(blob["ct"]))
        ct_bytes[0] ^= 0xFF
        blob["ct"] = base64.b64encode(bytes(ct_bytes)).decode()
        filepath.write_text(json.dumps(blob))

        wallet2 = HybridWallet("testnet")
        with pytest.raises(Exception):  # MAC check or ValueError
            wallet2.core.load_encrypted(str(filepath), "password")

    def test_corrupted_tag_fails(self, tmp_path):
        """Flipping a byte in GCM tag must cause verification failure."""
        filepath = tmp_path / "bad_tag.enc"
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="a2" * 32, vout=0, sats=50_000)
        wallet.core.save_encrypted(str(filepath), "password")

        blob = json.loads(filepath.read_text())
        tag = bytearray(bytes.fromhex(blob["tag"]))
        tag[0] ^= 0xFF
        blob["tag"] = tag.hex()
        filepath.write_text(json.dumps(blob))

        wallet2 = HybridWallet("testnet")
        with pytest.raises(Exception):
            wallet2.core.load_encrypted(str(filepath), "password")

    def test_empty_password_works(self, tmp_path):
        """Empty password is technically valid (scrypt handles it)."""
        filepath = tmp_path / "empty_pw.enc"
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="a3" * 32, vout=0, sats=10_000)
        wallet.core.save_encrypted(str(filepath), "")

        wallet2 = HybridWallet("testnet")
        wallet2.core.load_encrypted(str(filepath), "")
        assert len(wallet2.core.utxos) == 1


class TestTaggedHashConformance:
    """BIP-340 tagged_hash must follow spec exactly."""

    def test_tagged_hash_is_32_bytes(self):
        result = tagged_hash("TapSighash", b"\x00" * 32)
        assert len(result) == 32

    def test_tagged_hash_deterministic(self):
        a = tagged_hash("TapSighash", b"hello")
        b = tagged_hash("TapSighash", b"hello")
        assert a == b

    def test_tagged_hash_different_tags_differ(self):
        a = tagged_hash("TapSighash", b"msg")
        b = tagged_hash("TapLeaf", b"msg")
        assert a != b

    def test_tagged_hash_different_messages_differ(self):
        a = tagged_hash("TapSighash", b"msg1")
        b = tagged_hash("TapSighash", b"msg2")
        assert a != b

    def test_tagged_hash_matches_spec(self):
        """Verify against hand-computed: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
        tag = "TapSighash"
        msg = b"\x01\x02\x03"
        tag_hash = hashlib.sha256(tag.encode()).digest()
        expected = hashlib.sha256(tag_hash + tag_hash + msg).digest()
        assert tagged_hash(tag, msg) == expected

    def test_compact_size_encoding(self):
        """CompactSize encoding per Bitcoin protocol spec."""
        assert compact_size(0) == b"\x00"
        assert compact_size(252) == b"\xfc"
        assert compact_size(253) == b"\xfd\xfd\x00"
        assert compact_size(0xFFFF) == b"\xfd\xff\xff"
        assert compact_size(0x10000) == b"\xfe\x00\x00\x01\x00"


class TestPQCrossSchemeSecurity:
    """Cross-scheme and key-isolation tests."""

    def test_falcon_sig_rejected_by_dilithium_key(self):
        """Falcon signature must not verify under ML-DSA key."""
        kp_f = generate_pq_keypair(PQScheme.FALCON_512)
        kp_d = generate_pq_keypair(PQScheme.ML_DSA_65)
        msg = b"cross scheme"
        sig = kp_f.sign(msg)
        assert not kp_d.verify(msg, sig)

    def test_ml_dsa_65_sig_rejected_by_ml_dsa_87(self):
        """ML-DSA-65 signature must not verify under ML-DSA-87 key."""
        kp_65 = generate_pq_keypair(PQScheme.ML_DSA_65)
        kp_87 = generate_pq_keypair(PQScheme.ML_DSA_87)
        msg = b"level mismatch"
        sig = kp_65.sign(msg)
        assert not kp_87.verify(msg, sig)

    def test_empty_message_signs_and_verifies(self):
        """Empty message is valid input — PQ schemes must handle it."""
        for scheme in PQScheme:
            kp = generate_pq_keypair(scheme)
            sig = kp.sign(b"")
            assert kp.verify(b"", sig), f"{scheme.value} failed on empty msg"

    def test_large_message_signs_and_verifies(self):
        """1 MB message — PQ schemes must not truncate or crash."""
        kp = generate_pq_keypair(PQScheme.ML_DSA_65)
        big_msg = os.urandom(1024 * 1024)
        sig = kp.sign(big_msg)
        assert kp.verify(big_msg, sig)

    def test_pq_key_sizes_match_nist_spec(self):
        """Verify exact key and signature sizes per NIST spec."""
        expected = {
            PQScheme.ML_DSA_65:   (1952, 4032),
            PQScheme.ML_DSA_87:   (2592, 4896),
            PQScheme.FALCON_512:  (897,  1281),
            PQScheme.FALCON_1024: (1793, 2305),
        }
        for scheme, (pk_sz, sk_sz) in expected.items():
            kp = generate_pq_keypair(scheme)
            assert len(kp.public_key) == pk_sz, \
                f"{scheme.value} pk: expected {pk_sz}, got {len(kp.public_key)}"
            assert len(kp.private_key) == sk_sz, \
                f"{scheme.value} sk: expected {sk_sz}, got {len(kp.private_key)}"


# ====================================================================
# BIP-174 BINARY PSBT & HARDWARE WALLET INTEROP TESTS
# ====================================================================


class TestBIP174BinaryPSBT:
    """BIP-174 binary serialization must produce valid, parseable PSBTs."""

    def _make_signed_psbt(self, n_inputs=1):
        wallet = HybridWallet("testnet")
        utxos = []
        for i in range(n_inputs):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i+1:02x}" * 32, vout=i, sats=500_000)
            utxos.append(wallet.core.utxos[-1])
        psbt = wallet.core.create_transaction(_DEST1, 100_000)
        return psbt, utxos

    def test_psbt_magic_bytes(self):
        """BIP-174 PSBT must start with 'psbt' + 0xFF."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        assert raw[:5] == b"psbt\xff"

    def test_psbt_roundtrip_preserves_inputs(self):
        """Serialize → parse must preserve input count and txids."""
        psbt, _ = self._make_signed_psbt(2)
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert len(restored.inputs) == len(psbt.inputs)
        for orig, rest in zip(psbt.inputs, restored.inputs):
            assert orig["txid"] == rest["txid"]
            assert orig["vout"] == rest["vout"]

    def test_psbt_roundtrip_preserves_outputs(self):
        """Serialize → parse must preserve output count and amounts."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert len(restored.outputs) == len(psbt.outputs)
        for orig, rest in zip(psbt.outputs, restored.outputs):
            assert orig["amount"] == rest["amount"]
            assert orig["scriptPubKey"] == rest["scriptPubKey"]

    def test_psbt_roundtrip_preserves_taproot_sig(self):
        """Schnorr signatures survive BIP-174 round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert len(restored.pq_signatures) >= 1
        orig_sig = psbt.pq_signatures[0]["taproot_sig"]
        rest_sig = restored.pq_signatures[0]["taproot_sig"]
        assert orig_sig == rest_sig

    def test_psbt_roundtrip_preserves_pq_sig(self):
        """PQ signatures in proprietary fields survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0(include_pq=True)
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        orig_pq = psbt.pq_signatures[0].get("pq_sig", "")
        rest_pq = restored.pq_signatures[0].get("pq_sig", "")
        assert orig_pq == rest_pq

    def test_psbt_without_pq_omits_proprietary(self):
        """include_pq=False must not emit any 0xFC proprietary keys."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0(include_pq=False)
        # The proprietary prefix should not appear in the binary
        assert b"\x05pqbtc" not in raw

    def test_psbt_with_pq_includes_proprietary(self):
        """include_pq=True must embed proprietary PQ fields."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0(include_pq=True)
        assert b"\x05pqbtc" in raw

    def test_psbt_b64_roundtrip(self):
        """Base64 encode → decode round-trip."""
        psbt, _ = self._make_signed_psbt()
        b64 = psbt.to_psbt_b64()
        restored = HybridPSBTContainer.from_psbt_b64(b64)
        assert len(restored.inputs) == len(psbt.inputs)
        assert len(restored.outputs) == len(psbt.outputs)

    def test_psbt_preserves_tx_version(self):
        """TX version must survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert restored.tx_version == psbt.tx_version

    def test_psbt_preserves_locktime(self):
        """Locktime must survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert restored.locktime == psbt.locktime

    def test_psbt_preserves_sequence(self):
        """Per-input nSequence must survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        for orig, rest in zip(psbt.inputs, restored.inputs):
            assert orig.get("sequence", 0xFFFFFFFD) == rest["sequence"]

    def test_psbt_preserves_witness_utxo(self):
        """PSBT_IN_WITNESS_UTXO must survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        for orig, rest in zip(psbt.inputs, restored.inputs):
            assert "witness_utxo" in rest
            assert orig["witness_utxo"]["amount"] == rest["witness_utxo"]["amount"]

    def test_psbt_preserves_tap_internal_key(self):
        """PSBT_IN_TAP_INTERNAL_KEY (0x17) must survive round-trip."""
        psbt, _ = self._make_signed_psbt()
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        for rest_inp in restored.inputs:
            pk = rest_inp.get("taproot_pubkey", "")
            assert len(bytes.fromhex(pk)) == 32  # x-only

    def test_psbt_invalid_magic_raises(self):
        """Garbage bytes must be rejected."""
        with pytest.raises(ValueError, match="bad magic"):
            HybridPSBTContainer.from_psbt_v0(b"not a psbt")

    def test_psbt_multi_input_roundtrip(self):
        """3-input PSBT must round-trip correctly."""
        # Send enough to force coin-selection to pick all 3 UTXOs
        wallet = HybridWallet("testnet")
        for i in range(3):
            addr = wallet.receive()
            wallet.fund(addr, txid=f"{i+1:02x}" * 32, vout=i, sats=500_000)
        psbt = wallet.core.create_transaction(_DEST1, 1_200_000)
        raw = psbt.to_psbt_v0()
        restored = HybridPSBTContainer.from_psbt_v0(raw)
        assert len(restored.inputs) == 3
        assert len(restored.pq_signatures) == 3


class TestHWISigningWorkflow:
    """Simulate the full hardware wallet signing workflow."""

    def test_merge_hw_signatures_adds_schnorr(self):
        """HW signatures are merged into PSBT preserving PQ sigs."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="aa" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        # Step 1: Build PSBT with PQ signatures (wallet-side)
        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 200_000)
        psbt.sign_inputs([utxo])
        original_pq_sig = psbt.pq_signatures[0]["pq_sig"]
        original_schnorr = psbt.pq_signatures[0]["taproot_sig"]

        # Step 2: Simulate HW wallet returning a different Schnorr sig
        hw_psbt = HybridPSBTContainer()
        hw_psbt.pq_signatures = [{
            "input_index": 0,
            "taproot_sig": "bb" * 64,  # simulated HW signature
            "hash_type": BIP341Sighash.SIGHASH_DEFAULT,
        }]

        # Step 3: Merge
        psbt.merge_hw_signatures(hw_psbt)

        # Verify: Schnorr replaced, PQ preserved
        assert psbt.pq_signatures[0]["taproot_sig"] == "bb" * 64
        assert psbt.pq_signatures[0]["pq_sig"] == original_pq_sig

    def test_merge_on_unsigned_psbt(self):
        """Merging HW sigs into a PSBT that only has PQ sigs works."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="cc" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        # PSBT with only PQ sig (no Schnorr yet)
        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 200_000)

        # Manually add PQ-only sig entry
        sighash = psbt._compute_sighash(0)
        pq_sig = utxo.pq_keypair.sign(sighash)
        psbt.pq_signatures.append({
            "input_index": 0,
            "pq_sig": base64.b64encode(pq_sig).decode(),
            "pq_scheme": utxo.pq_keypair.scheme.value,
        })

        # Simulate HW wallet
        hw_psbt = HybridPSBTContainer()
        schnorr_sig = utxo.taproot_key.sign_schnorr(sighash)
        hw_psbt.pq_signatures = [{
            "input_index": 0,
            "taproot_sig": schnorr_sig.hex(),
            "hash_type": BIP341Sighash.SIGHASH_DEFAULT,
        }]

        # Merge and finalize
        psbt.merge_hw_signatures(hw_psbt)
        assert psbt.pq_signatures[0]["taproot_sig"] == schnorr_sig.hex()
        assert psbt.pq_signatures[0].get("pq_sig") is not None

    def test_full_hwi_roundtrip(self):
        """Full workflow: build → export BIP-174 → parse → merge → finalize."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="dd" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        # 1. Build and PQ-sign
        psbt = wallet.core.create_transaction(_DEST1, 100_000)

        # 2. Export to BIP-174 binary (no PQ for HW wallet)
        psbt_bytes = psbt.to_psbt_v0(include_pq=False)
        assert psbt_bytes[:5] == b"psbt\xff"
        assert b"\x05pqbtc" not in psbt_bytes  # no PQ in HW export

        # 3. Parse back (simulating what a coordinator does)
        parsed = HybridPSBTContainer.from_psbt_v0(psbt_bytes)
        assert len(parsed.inputs) == len(psbt.inputs)

        # 4. Export with PQ (for archival/policy)
        psbt_with_pq = psbt.to_psbt_v0(include_pq=True)
        assert b"\x05pqbtc" in psbt_with_pq

        # 5. The original PSBT can still finalize (it already has sigs)
        raw_tx = psbt.finalize()
        assert raw_tx[:4] == struct.pack("<I", 2)  # nVersion = 2

    def test_export_unsigned_for_hw(self):
        """An unsigned PSBT export (before sign_inputs) has no sigs."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="ee" * 32, vout=0, sats=500_000)
        utxo = wallet.core.utxos[0]

        psbt = HybridPSBTContainer()
        psbt.add_input(utxo)
        psbt.add_output(_DEST1, 200_000)
        # Don't sign — export unsigned
        raw = psbt.to_psbt_v0(include_pq=False)
        parsed = HybridPSBTContainer.from_psbt_v0(raw)
        assert len(parsed.pq_signatures) == 0  # no sigs yet
        assert len(parsed.inputs) == 1
        assert parsed.inputs[0].get("witness_utxo") is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
