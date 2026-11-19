"""
ledger.py — Lightweight append-only ledger for IoT device identity provisioning.

Each block records a device's provisioning event: device ID, public key,
signature over the provisioning request, timestamp, and a hash linking it
to the previous block (classic blockchain-style chaining).

Supports PROVISION and REVOKE block types for basic identity lifecycle
management, alongside PQC (Dilithium) signatures instead of classical ECDSA.

Run: python ledger.py
"""

import hashlib
import json
import time
from pathlib import Path

LEDGER_FILE = Path("ledger.json")


class Ledger:
    def __init__(self):
        self.chain = []
        self._add_genesis_block()

    def _hash_block(self, block: dict) -> str:
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def _add_genesis_block(self):
        genesis = {
            "index": 0,
            "block_type": "GENESIS",
            "device_id": "GENESIS",
            "pubkey_hex": "",
            "signature_hex": "",
            "timestamp": time.time(),
            "prev_hash": "0" * 64,
        }
        genesis["hash"] = self._hash_block(genesis)
        self.chain.append(genesis)

    def add_block(self, device_id: str, pubkey: bytes, signature: bytes,
                  block_type: str = "PROVISION") -> dict:
        """block_type: 'PROVISION' registers a new device identity,
        'REVOKE' marks an existing device's identity as revoked."""
        prev_block = self.chain[-1]
        block = {
            "index": len(self.chain),
            "block_type": block_type,
            "device_id": device_id,
            "pubkey_hex": pubkey.hex() if pubkey else "",
            "signature_hex": signature.hex() if signature else "",
            "timestamp": time.time(),
            "prev_hash": prev_block["hash"],
        }
        block["hash"] = self._hash_block({k: v for k, v in block.items() if k != "hash"})
        self.chain.append(block)
        return block

    def revoke_device(self, device_id: str, signature: bytes) -> dict:
        """Append a REVOKE block for a device. `signature` should be an
        authority signature over the revocation (kept minimal here)."""
        return self.add_block(device_id, pubkey=b"", signature=signature, block_type="REVOKE")

    def is_device_active(self, device_id: str) -> bool:
        """A device is active if its latest PROVISION/REVOKE block is a
        PROVISION with no later REVOKE."""
        status = None
        for block in self.chain:
            if block["device_id"] == device_id and block["block_type"] in ("PROVISION", "REVOKE"):
                status = block["block_type"]
        return status == "PROVISION"

    def is_valid(self) -> bool:
        """Verify the chain's integrity: each block's prev_hash must match
        the actual hash of the block before it, and each block's own hash
        must be recomputable from its contents."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current["prev_hash"] != previous["hash"]:
                return False

            recomputed = self._hash_block({k: v for k, v in current.items() if k != "hash"})
            if recomputed != current["hash"]:
                return False
        return True

    def save(self, path: Path = LEDGER_FILE):
        with open(path, "w") as f:
            json.dump(self.chain, f, indent=2)

    def load(self, path: Path = LEDGER_FILE):
        with open(path, "r") as f:
            self.chain = json.load(f)


if __name__ == "__main__":
    from dilithium_py.dilithium import Dilithium2

    ledger = Ledger()

    device_ids = [f"IoT-device-{i:03d}" for i in range(1, 6)]

    for device_id in device_ids:
        pk, sk = Dilithium2.keygen()
        provisioning_msg = f"{device_id}:provisioning-request".encode()
        sig = Dilithium2.sign(sk, provisioning_msg)

        block = ledger.add_block(device_id, pk, sig)
        print(f"Provisioned {device_id} -> block #{block['index']} (hash {block['hash'][:12]}...)")

    print(f"\nChain length: {len(ledger.chain)} blocks")
    print(f"Chain valid? : {ledger.is_valid()}")

    ledger.save()
    print(f"Ledger written to {LEDGER_FILE.resolve()}")

    print("\n--- Tamper test ---")
    ledger.chain[2]["device_id"] = "TAMPERED-DEVICE"
    print(f"Chain valid after tampering block #2? : {ledger.is_valid()}")