"""
Sanity check: Dilithium (PQC) vs ECDSA (classical) — keygen, sign, verify.
Run: python test_pqc.py
"""

import time

# ---------- Dilithium (post-quantum) ----------
from dilithium_py.dilithium import Dilithium2

print("=== Dilithium2 (Post-Quantum) ===")
t0 = time.perf_counter()
pk, sk = Dilithium2.keygen()
t1 = time.perf_counter()

message = b"IoT-device-001:provisioning-request"
sig = Dilithium2.sign(sk, message)
t2 = time.perf_counter()

valid = Dilithium2.verify(pk, message, sig)
t3 = time.perf_counter()

print(f"Keygen time : {(t1 - t0) * 1000:.3f} ms")
print(f"Sign time   : {(t2 - t1) * 1000:.3f} ms")
print(f"Verify time : {(t3 - t2) * 1000:.3f} ms")
print(f"Pubkey size : {len(pk)} bytes")
print(f"Sig size    : {len(sig)} bytes")
print(f"Valid?      : {valid}")

# ---------- ECDSA (classical) ----------
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

print("\n=== ECDSA (Classical, P-256) ===")
t0 = time.perf_counter()
priv_key = ec.generate_private_key(ec.SECP256R1())
pub_key = priv_key.public_key()
t1 = time.perf_counter()

signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
t2 = time.perf_counter()

try:
    pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    ec_valid = True
except Exception:
    ec_valid = False
t3 = time.perf_counter()

pub_bytes = pub_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)

print(f"Keygen time : {(t1 - t0) * 1000:.3f} ms")
print(f"Sign time   : {(t2 - t1) * 1000:.3f} ms")
print(f"Verify time : {(t3 - t2) * 1000:.3f} ms")
print(f"Pubkey size : {len(pub_bytes)} bytes")
print(f"Sig size    : {len(signature)} bytes")
print(f"Valid?      : {ec_valid}")

print("\n=== Summary ===")
print("If both show 'Valid? True', your PQC + classical crypto stack is working.")
print("Notice: Dilithium pubkey/sig sizes are MUCH larger than ECDSA — that's your")
print("core trade-off story for IoT (bandwidth/storage constrained devices).")