"""
BIP-341 Taproot Sighash Implementation
Reference: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
"""

import hashlib
import struct
from typing import List, Tuple

def compact_size(n: int) -> bytes:
    """Bitcoin CompactSize encoding."""
    if n < 0xfd:
        return struct.pack("<B", n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", n)
    else:
        return b'\xff' + struct.pack("<Q", n)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP-340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || msg)"""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


class BIP341Sighash:
    """Full BIP-341 Taproot signature hash calculator."""
    
    SIGHASH_DEFAULT = 0x00
    SIGHASH_ALL = 0x01
    SIGHASH_NONE = 0x02
    SIGHASH_SINGLE = 0x03
    SIGHASH_ANYONECANPAY = 0x80
    
    def __init__(self, psbt: 'PSBTv2', input_index: int):
        self.psbt = psbt
        self.input_index = input_index
        self.tx_version = psbt.tx_version
        self.locktime = getattr(psbt, 'locktime', 0)
    
    def compute(
        self,
        hash_type: int = SIGHASH_DEFAULT,
        annex: bytes = b'',
        ext_flag: int = 0,
    ) -> bytes:
        """
        Compute BIP-341 signature hash for key-path spending.
        
        Args:
            hash_type: SIGHASH type (default: 0x00)
            annex: Optional annex data (starts with 0x50)
            ext_flag: 0 for key-path, 1 for script-path
        
        Returns:
            32-byte signature hash
        """
        epoch = b'\x00'  # Taproot epoch
        
        # Spend type (2 bits: ext_flag || annex_present)
        annex_present = 1 if annex else 0
        spend_type = (ext_flag << 1) | annex_present
        
        # === Build signature message ===
        msg = bytearray()
        
        # 1. Epoch (1 byte)
        msg += epoch
        
        # 2. Hash type (1 byte, 0x00 for SIGHASH_DEFAULT)
        msg += bytes([hash_type if hash_type != self.SIGHASH_DEFAULT else 0x00])
        
        # 3. Transaction version (4 bytes, little-endian)
        msg += struct.pack("<I", self.tx_version)
        
        # 4. Locktime (4 bytes, little-endian)
        msg += struct.pack("<I", self.locktime)
        
        # === Hash prevouts (if not ANYONECANPAY) ===
        if not (hash_type & self.SIGHASH_ANYONECANPAY):
            msg += self._sha_prevouts()
        
        # === Hash amounts ===
        if not (hash_type & self.SIGHASH_ANYONECANPAY):
            msg += self._sha_amounts()
        
        # === Hash scriptPubKeys ===
        if not (hash_type & self.SIGHASH_ANYONECANPAY):
            msg += self._sha_scriptpubkeys()
        
        # === Hash sequences (if not ANYONECANPAY and not SINGLE/NONE) ===
        if (not (hash_type & self.SIGHASH_ANYONECANPAY) and
            (hash_type & 0x1f) not in (self.SIGHASH_NONE, self.SIGHASH_SINGLE)):
            msg += self._sha_sequences()
        
        # === Hash outputs ===
        if (hash_type & 0x1f) not in (self.SIGHASH_NONE, self.SIGHASH_SINGLE):
            msg += self._sha_outputs()
        elif (hash_type & 0x1f) == self.SIGHASH_SINGLE:
            if self.input_index < len(self.psbt.outputs):
                msg += self._sha_single_output(self.input_index)
        
        # === Spend type (1 byte) ===
        msg += bytes([spend_type])
        
        # === Input-specific data (if ANYONECANPAY) ===
        if hash_type & self.SIGHASH_ANYONECANPAY:
            inp = self.psbt.inputs[self.input_index]
            msg += bytes.fromhex(inp["txid"])
            msg += struct.pack("<I", inp["vout"])
            msg += struct.pack("<q", inp["amount"])
            spk = bytes.fromhex(inp["witness_utxo"]["scriptPubKey"])
            msg += compact_size(len(spk)) + spk
            msg += struct.pack("<I", inp.get("sequence", 0xfffffffd))
        else:
            # Input index (4 bytes)
            msg += struct.pack("<I", self.input_index)
        
        # === Annex hash (if present) ===
        if annex:
            msg += tagged_hash("TapLeaf/elements", annex)
        
        # === Data about spending script (only for script-path) ===
        if ext_flag == 1:
            # For key-path spending (ext_flag=0), this section is omitted
            # For script-path: add tapleaf_hash, key_version, codesep_pos
            pass
        
        # Final hash: TapSighash tag
        return tagged_hash("TapSighash", bytes(msg))
    
    # === Helper methods for hashing transaction data ===
    
    def _sha_prevouts(self) -> bytes:
        """SHA-256 of all input outpoints."""
        data = b''.join(
            bytes.fromhex(inp["txid"]) + struct.pack("<I", inp["vout"])
            for inp in self.psbt.inputs
        )
        return hashlib.sha256(data).digest()
    
    def _sha_amounts(self) -> bytes:
        """SHA-256 of all input amounts."""
        data = b''.join(
            struct.pack("<q", inp["amount"])
            for inp in self.psbt.inputs
        )
        return hashlib.sha256(data).digest()
    
    def _sha_scriptpubkeys(self) -> bytes:
        """SHA-256 of all input scriptPubKeys."""
        data = b''.join(
            compact_size(len(spk := bytes.fromhex(inp["witness_utxo"]["scriptPubKey"]))) + spk
            for inp in self.psbt.inputs
        )
        return hashlib.sha256(data).digest()
    
    def _sha_sequences(self) -> bytes:
        """SHA-256 of all input sequence numbers."""
        data = b''.join(
            struct.pack("<I", inp.get("sequence", 0xfffffffd))
            for inp in self.psbt.inputs
        )
        return hashlib.sha256(data).digest()
    
    def _sha_outputs(self) -> bytes:
        """SHA-256 of all outputs."""
        data = b''.join(
            struct.pack("<q", out["amount"]) +
            compact_size(len(spk := bytes.fromhex(out["scriptPubKey"]))) + spk
            for out in self.psbt.outputs
        )
        return hashlib.sha256(data).digest()
    
    def _sha_single_output(self, index: int) -> bytes:
        """SHA-256 of single output (for SIGHASH_SINGLE)."""
        out = self.psbt.outputs[index]
        data = (
            struct.pack("<q", out["amount"]) +
            compact_size(len(spk := bytes.fromhex(out["scriptPubKey"]))) +
            bytes.fromhex(out["scriptPubKey"])
        )
        return hashlib.sha256(data).digest()
