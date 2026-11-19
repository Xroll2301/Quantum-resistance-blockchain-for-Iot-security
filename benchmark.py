"""
benchmark.py — Benchmark Dilithium (PQC) vs ECDSA (classical) over N runs.

Measures keygen/sign/verify time and key/signature sizes, then plots
a comparison bar chart. This is the core "trade-off" evidence for the
project: PQC signatures are larger and slower, but quantum-resistant —
relevant for IoT identity provisioning where bandwidth/storage are
constrained but long-term security matters.

Run: python benchmark.py
"""

import time
import statistics
import matplotlib.pyplot as plt

from dilithium_py.dilithium import Dilithium2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

N_RUNS = 50
MESSAGE = b"IoT-device:provisioning-request"


def benchmark_dilithium(n=N_RUNS):
    keygen_times, sign_times, verify_times = [], [], []
    pk_size = sig_size = 0

    for _ in range(n):
        t0 = time.perf_counter()
        pk, sk = Dilithium2.keygen()
        t1 = time.perf_counter()

        sig = Dilithium2.sign(sk, MESSAGE)
        t2 = time.perf_counter()

        Dilithium2.verify(pk, MESSAGE, sig)
        t3 = time.perf_counter()

        keygen_times.append((t1 - t0) * 1000)
        sign_times.append((t2 - t1) * 1000)
        verify_times.append((t3 - t2) * 1000)
        pk_size, sig_size = len(pk), len(sig)

    return {
        "keygen": statistics.mean(keygen_times),
        "sign": statistics.mean(sign_times),
        "verify": statistics.mean(verify_times),
        "pk_size": pk_size,
        "sig_size": sig_size,
    }


def benchmark_ecdsa(n=N_RUNS):
    keygen_times, sign_times, verify_times = [], [], []
    pk_size = sig_size = 0

    for _ in range(n):
        t0 = time.perf_counter()
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_key = priv_key.public_key()
        t1 = time.perf_counter()

        signature = priv_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
        t2 = time.perf_counter()

        pub_key.verify(signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
        t3 = time.perf_counter()

        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        keygen_times.append((t1 - t0) * 1000)
        sign_times.append((t2 - t1) * 1000)
        verify_times.append((t3 - t2) * 1000)
        pk_size, sig_size = len(pub_bytes), len(signature)

    return {
        "keygen": statistics.mean(keygen_times),
        "sign": statistics.mean(sign_times),
        "verify": statistics.mean(verify_times),
        "pk_size": pk_size,
        "sig_size": sig_size,
    }


def print_table(dilithium, ecdsa):
    print(f"\n{'Metric':<18}{'Dilithium2':<15}{'ECDSA(P-256)':<15}{'Ratio (PQC/ECDSA)'}")
    print("-" * 65)
    for key, label, unit in [
        ("keygen", "Keygen (ms)", ""),
        ("sign", "Sign (ms)", ""),
        ("verify", "Verify (ms)", ""),
        ("pk_size", "Pubkey (bytes)", ""),
        ("sig_size", "Signature (bytes)", ""),
    ]:
        d, e = dilithium[key], ecdsa[key]
        ratio = d / e if e else float("inf")
        print(f"{label:<18}{d:<15.3f}{e:<15.3f}{ratio:.1f}x")


def plot_comparison(dilithium, ecdsa):
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))

    # Timing chart
    metrics = ["keygen", "sign", "verify"]
    labels = ["Keygen", "Sign", "Verify"]
    dil_vals = [dilithium[m] for m in metrics]
    ec_vals = [ecdsa[m] for m in metrics]

    x = range(len(labels))
    width = 0.35
    axes[0].bar([i - width / 2 for i in x], dil_vals, width, label="Dilithium2 (PQC)")
    axes[0].bar([i + width / 2 for i in x], ec_vals, width, label="ECDSA P-256")
    axes[0].set_xticks(list(x))
    axes[0].set_xticklabels(labels)
    axes[0].set_ylabel("Time (ms)")
    axes[0].set_title(f"Operation Time (avg of {N_RUNS} runs)")
    axes[0].legend()

    # Size chart
    size_labels = ["Pubkey", "Signature"]
    dil_sizes = [dilithium["pk_size"], dilithium["sig_size"]]
    ec_sizes = [ecdsa["pk_size"], ecdsa["sig_size"]]

    x2 = range(len(size_labels))
    axes[1].bar([i - width / 2 for i in x2], dil_sizes, width, label="Dilithium2 (PQC)")
    axes[1].bar([i + width / 2 for i in x2], ec_sizes, width, label="ECDSA P-256")
    axes[1].set_xticks(list(x2))
    axes[1].set_xticklabels(size_labels)
    axes[1].set_ylabel("Size (bytes)")
    axes[1].set_title("Key / Signature Size")
    axes[1].legend()

    plt.tight_layout()
    plt.savefig("benchmark_comparison.png", dpi=150)
    print("\nChart saved to benchmark_comparison.png")
    plt.show()


if __name__ == "__main__":
    print(f"Running {N_RUNS} iterations each for Dilithium2 and ECDSA...")
    dilithium_results = benchmark_dilithium()
    ecdsa_results = benchmark_ecdsa()

    print_table(dilithium_results, ecdsa_results)
    plot_comparison(dilithium_results, ecdsa_results)