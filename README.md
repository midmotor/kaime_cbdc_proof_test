# KAIME: Central Bank Digital Currency with Realistic and Modular Privacy

This repository contains the testing of the proofs used in the "KAIME: Central Bank Digital Currency with Realistic and Modular Privacy"  (https://eprint.iacr.org/2023/713) paper.

The results of the tests performed on a computer with i7-1165g7 @ 2.80ghz and 16gb ram are as follows:

| Test                  | Prover (ms)       | Verifier (ms)    |
|-----------------------|-------------------|-------------------|
| Equality Proof (p256) | 2.309 ms          | 1.216 ms          |
| Equality Proof (ed25519) | 0.130 ms        | 0.243 ms          |
| Zero Proof (p256)     | 0.672 ms          | 1.749 ms          |
| Zero Proof (ed25519)  | 0.121 ms          | 0.252 ms          |
| Range Proof (p256)   | 292.965ms        | 121.516ms        |
| Range Proof (25519)   | 32.209 ms         | 18.072 ms         |
| Elgamal Enc (p256)        | 1.083 ms          | -                 |
| Elgamal Enc (ed25519)        | 0.147 ms          | -                 |

