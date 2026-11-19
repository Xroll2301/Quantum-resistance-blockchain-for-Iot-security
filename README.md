# Quantum-Resistant Blockchain for IoT Device Identity Provisioning

A working system that replaces classical cryptographic signatures (ECDSA)
with post-quantum signatures (CRYSTALS-Dilithium) in the process of
provisioning identities for IoT devices, secured on a lightweight
tamper-evident ledger with multi-node consensus.

## Why this project exists

IoT devices are typically given a cryptographic identity — a public/private
keypair — when they're provisioned, signed using classical algorithms like
ECDSA or RSA. Those algorithms are secure against today's computers, but
would be broken by a sufficiently powerful quantum computer running Shor's
algorithm. Since IoT devices are often deployed for 10-15 years, and
encrypted/signed traffic can be recorded today and broken later
("harvest now, decrypt later"), identities provisioned today need to
survive a threat that doesn't fully exist yet.

This project provisions IoT device identities using **Dilithium**
(NIST-standardized as ML-DSA / FIPS 204 in August 2024) instead of ECDSA,
and records that provisioning on a **hash-chained ledger** that requires
**multi-node consensus** before any identity is accepted — so no single
compromised node can admit a forged device.

## What it does

1. **Generates PQC identities** — each device gets a Dilithium keypair and
   signs its own provisioning request.
2. **Records provisioning on a tamper-evident ledger** — every block links
   to the previous one via SHA-256; altering any past record invalidates
   the whole chain.
3. **Requires consensus to provision** — 5 simulated validator nodes each
   independently re-verify a device's signature; a device is only
   provisioned if a majority (3/5) agree it's valid. A forged signature is
   unanimously rejected.
4. **Supports revocation** — a compromised or retired device can be marked
   inactive without breaking the ledger's integrity.
5. **Benchmarks the trade-off** — measures exactly how much slower/larger
   Dilithium is versus ECDSA, since that overhead matters for
   bandwidth- and power-constrained IoT devices.

## Project structure

| File | What it does |
|---|---|
| `test_pqc.py` | Sanity check: one Dilithium and one ECDSA sign/verify cycle |
| `ledger.py` | The hash-chained ledger — blocks, tamper detection, revocation, active-status checks |
| `consensus.py` | 5-validator majority-vote consensus layer on top of the ledger |
| `benchmark.py` | Runs 50 iterations of both algorithms, prints a comparison table, saves a chart |
| `demo.py` | **Runs everything end-to-end with narration** — the script to use for a live demo |
| `requirements.txt` | All dependencies, installable in one command |

## Setup

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
```

## Running it

For a full narrated walkthrough of the whole system (recommended for demos):
```bash
python demo.py
```

To run pieces individually:
```bash
python test_pqc.py     # basic crypto sanity check
python ledger.py       # ledger + tamper-detection demo
python consensus.py    # consensus + forgery rejection + revocation demo
python benchmark.py    # full 50-run benchmark + chart (benchmark_comparison.png)
```

## Results so far

Averaged over 50 runs, comparing Dilithium2 against ECDSA P-256:

| Metric | Dilithium2 (PQC) | ECDSA P-256 | Ratio |
|---|---|---|---|
| Keygen | ~5 ms | ~0.1 ms | ~50-160x slower |
| Sign | ~28 ms | ~0.1-0.2 ms | ~160-500x slower |
| Verify | ~6 ms | ~0.1 ms | ~50-100x slower |
| Public key size | 1312 bytes | 65 bytes | ~20x larger |
| Signature size | 2420 bytes | ~70 bytes | ~34x larger |

**Interpretation:** Dilithium is significantly heavier than ECDSA on every
axis, but it's the cost of remaining secure against a quantum adversary.
Whether that overhead is acceptable depends on the specific IoT device's
constraints (bandwidth, power, latency tolerance) — which is part of what
this project is quantifying.

Consensus and revocation behavior (see `consensus.py` / `demo.py` output):
- Legitimate provisioning requests: unanimously approved (5/5 validators)
- A forged signature: unanimously rejected (0/5 validators)
- Revocation correctly flips a device to inactive without breaking chain
  integrity

## What's not built yet (roadmap)

- Deeper literature review (target: 10+ papers, sharper positioning
  against related PQC-blockchain-IoT work)
- Testing on real constrained hardware (e.g. Raspberry Pi) rather than
  simulated timing/size overhead
- A formal threat model — what this system resists (forgery, tampering)
  vs. what it doesn't yet address (Sybil attacks, denial-of-service on
  the consensus layer)
- Packaging results toward a publishable paper (Outcome-Based Project
  component)

## Author

Kaustubh — Final Year B.Tech CSE (Cybersecurity)
