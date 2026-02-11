import pytest
from pq_psbt import *
from bitcoin_protocol import BIP341Sighash

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
        psbt.add_output("tb1p" + "0" * 40, 400_000)
        psbt.add_output("tb1p" + "1" * 40, 350_000)
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
        psbt_b64 = wallet.send("tb1p" + "0"*40, 0.005)
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
            wallet.send("tb1p" + "0"*40, 1.0)
    
    def test_timelock_enforcement(self):
        """Test that timelocked UTXOs are unspendable."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive(lock_blocks=100)
        wallet.fund(addr, txid="c"*64, vout=0, sats=1_000_000)
        
        # Should fail: UTXO is locked
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send("tb1p" + "0"*40, 0.005)
        
        # Advance blockchain height
        wallet.core.current_height = 100
        
        # Should succeed now
        psbt_b64 = wallet.send("tb1p" + "0"*40, 0.005)
        assert psbt_b64

class TestSecurity:
    """Security-critical test cases."""
    
    def test_double_spend_prevention(self):
        """Verify double-spend protection."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="d"*64, vout=0, sats=1_000_000)
        
        # First spend should succeed
        psbt1 = wallet.send("tb1p" + "0"*40, 0.001)
        
        # Second spend should fail (UTXO already spent)
        with pytest.raises(ValueError, match="Insufficient balance"):
            wallet.send("tb1p" + "1"*40, 0.001)
    
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
        b64 = wallet.send("tb1p" + "0" * 40, 0.005)
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
        psbt.add_output("tb1p" + "0" * 40, 50_000)
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
    """Tests for correctness fixes: mock isolation, finalize restrictions."""

    def test_taproot_key_mock_flag(self):
        """TaprootKey exposes is_mock so callers can gate on-chain use."""
        key = TaprootKey(mock=True)
        assert key.is_mock is True

    def test_taproot_key_auto_mock_without_bitcoinlib(self):
        """Without bitcoinlib, TaprootKey auto-selects mock mode."""
        import pq_psbt as _mod
        key = TaprootKey()
        # In our test env bitcoinlib is not installed → must be mock
        if not _mod._HAS_BITCOINLIB:
            assert key.is_mock is True

    def test_finalize_rejects_sighash_single(self):
        """finalize() must reject SIGHASH_SINGLE until fully supported."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="fa" * 32, vout=0, sats=1_000_000)
        psbt = wallet.core.create_transaction("tb1p" + "0" * 40, 500_000)
        # Tamper the hash_type to SIGHASH_SINGLE
        psbt.pq_signatures[0]["hash_type"] = BIP341Sighash.SIGHASH_SINGLE
        with pytest.raises(ValueError, match="SIGHASH_SINGLE"):
            psbt.finalize()

    def test_finalize_accepts_sighash_all(self):
        """finalize() allows SIGHASH_ALL (0x01)."""
        wallet = HybridWallet("testnet")
        addr = wallet.receive()
        wallet.fund(addr, txid="fb" * 32, vout=0, sats=1_000_000)
        psbt = wallet.core.create_transaction("tb1p" + "0" * 40, 500_000)
        psbt.pq_signatures[0]["hash_type"] = BIP341Sighash.SIGHASH_ALL
        raw = psbt.finalize()
        assert isinstance(raw, bytes)
        assert len(raw) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
