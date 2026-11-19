"""
consensus.py — Simple majority-vote consensus over multiple validator nodes.

Simulates N validator nodes. Before a device's provisioning block is
committed to the ledger, each validator independently re-verifies the
Dilithium signature on the provisioning request. The block is only
committed if a majority of validators agree it's valid.

Run: python consensus.py
"""

from dilithium_py.dilithium import Dilithium2
from ledger import Ledger

N_VALIDATORS = 5
QUORUM = N_VALIDATORS // 2 + 1


class ValidatorNode:
    def __init__(self, node_id: int):
        self.node_id = node_id

    def validate(self, device_id: str, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return Dilithium2.verify(pubkey, message, signature)
        except Exception:
            return False


class ConsensusNetwork:
    def __init__(self, n_validators: int = N_VALIDATORS):
        self.validators = [ValidatorNode(i) for i in range(n_validators)]
        self.ledger = Ledger()

    def propose_provisioning(self, device_id: str, pubkey: bytes, message: bytes, signature: bytes):
        votes = [v.validate(device_id, pubkey, message, signature) for v in self.validators]
        approvals = sum(votes)

        print(f"  Votes: {approvals}/{len(self.validators)} validators approved "
              f"(quorum needed: {QUORUM})")

        if approvals >= QUORUM:
            block = self.ledger.add_block(device_id, pubkey, signature, block_type="PROVISION")
            print(f"  -> COMMITTED as block #{block['index']}")
            return block
        else:
            print(f"  -> REJECTED (insufficient consensus)")
            return None


if __name__ == "__main__":
    network = ConsensusNetwork()

    print(f"Consensus network: {N_VALIDATORS} validators, quorum = {QUORUM}\n")

    device_ids = [f"IoT-device-{i:03d}" for i in range(1, 4)]
    keys = {}

    for device_id in device_ids:
        pk, sk = Dilithium2.keygen()
        keys[device_id] = (pk, sk)
        message = f"{device_id}:provisioning-request".encode()
        sig = Dilithium2.sign(sk, message)

        print(f"Proposing provisioning for {device_id}...")
        network.propose_provisioning(device_id, pk, message, sig)
        print()

    print("Proposing FORGED provisioning for IoT-device-999 (bad signature)...")
    fake_pk, _ = Dilithium2.keygen()
    fake_message = b"IoT-device-999:provisioning-request"
    fake_sig = b"\x00" * 2420
    network.propose_provisioning("IoT-device-999", fake_pk, fake_message, fake_sig)
    print()

    revoke_target = device_ids[0]
    print(f"Revoking {revoke_target}...")
    network.ledger.revoke_device(revoke_target, signature=b"authority-sig-placeholder")
    print()

    print("=== Device status check ===")
    for device_id in device_ids:
        active = network.ledger.is_device_active(device_id)
        print(f"{device_id}: {'ACTIVE' if active else 'REVOKED'}")

    print(f"\nLedger valid overall? : {network.ledger.is_valid()}")
    network.ledger.save()
    print("Ledger written to ledger.json")