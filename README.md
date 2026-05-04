<div align="center">

```
██████╗ ███████╗ █████╗     ██╗      █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗   ██║     ██╔══██╗██╔══██╗
██████╔╝███████╗███████║   ██║     ███████║██████╔╝
██╔══██╗╚════██║██╔══██║   ██║     ██╔══██║██╔══██╗
██║  ██║███████║██║  ██║   ███████╗██║  ██║██████╔╝
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝
```

# RSA Cryptography System

**Full RSA pipeline built from mathematical primitives — no cryptography shortcuts.**

[![C](https://img.shields.io/badge/Language-C-blue?style=flat-square&logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![OpenSSL BIGNUM](https://img.shields.io/badge/Library-OpenSSL_BIGNUM-orange?style=flat-square)](https://www.openssl.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![SEED Lab](https://img.shields.io/badge/SEED_Lab-RSA_Encryption_%26_Signature-purple?style=flat-square)](https://seedsecuritylabs.org/)

</div>

---

## What This Is

A complete, from-scratch implementation of the RSA cryptosystem using only big-number arithmetic — no `RSA_encrypt()`, no `EVP_*` shortcuts. Every mathematical operation is implemented explicitly: modular exponentiation, modular inverse, key derivation, signing, and X.509 certificate verification.

Built as part of the **SEED Labs RSA Public-Key Encryption and Signature Lab** (Information & Network Security course).

---

## The Math Behind It

RSA security rests on the practical impossibility of factoring large integers. The system is built on three elegant equations:

```
Key Generation:    n = p × q,   φ(n) = (p−1)(q−1),   e·d ≡ 1 (mod φ(n))
Encryption:        C = Mᵉ mod n
Decryption:        M = Cᵈ mod n
Sign:              S = Mᵈ mod n
Verify:            M = Sᵉ mod n
```

The private key `d` is the modular inverse of `e` with respect to `φ(n)` — computationally trivial to compute when you know `p` and `q`, and computationally intractable to recover otherwise.

---

## Tasks

| # | Task | Core Operation | Key Insight |
|---|------|---------------|-------------|
| [1](#task-1--key-derivation) | Private Key Derivation | `d = e⁻¹ mod φ(n)` | Extended Euclidean Algorithm |
| [2](#task-2--encryption) | Message Encryption | `C = Mᵉ mod n` | Public key transforms plaintext |
| [3](#task-3--decryption) | Message Decryption | `M = Cᵈ mod n` | Only private key inverts it |
| [4](#task-4--digital-signature) | Digital Signature | `S = Mᵈ mod n` | Avalanche effect — 1 byte change → entirely different signature |
| [5](#task-5--signature-verification) | Signature Verification | `M = Sᵉ mod n`, compare | Even 1 flipped bit fails verification |
| [6](#task-6--x509-certificate-verification) | X.509 Certificate Verify | `S^e mod n` vs `SHA256(cert_body)` | How HTTPS trust actually works |

---

## Project Structure

```
rsa-lab/
├── src/
│   ├── task1_keygen.c        ← Private key derivation
│   ├── task2_encrypt.c       ← RSA encryption
│   ├── task3_decrypt.c       ← RSA decryption
│   ├── task4_sign.c          ← Digital signature generation
│   ├── task5_verify.c        ← Signature verification + tampering demo
│   └── task6_x509.c          ← Manual X.509 certificate verification
├── scripts/
│   └── extract_cert.sh       ← Download & parse TLS cert chain
├── Makefile
└── README.md
```

---

## Getting Started

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install gcc libssl-dev

# macOS
brew install openssl
```

### Build & Run

```bash
# Compile all tasks
make all

# Run everything at once
make run-all

# Or run individually
./bin/task1_keygen
./bin/task2_encrypt
./bin/task3_decrypt
./bin/task4_sign
./bin/task5_verify
./bin/task6_x509
```

---

## Task 1 — Key Derivation

Given prime factors `p`, `q` and public exponent `e`, compute private key `d`.

```c
// n = p * q
BN_mul(n, p, q, ctx);

// φ(n) = (p-1)(q-1)
BN_sub(sub1, p, BN_value_one());
BN_sub(sub2, q, BN_value_one());
BN_mul(phi, sub1, sub2, ctx);

// d = e⁻¹ mod φ(n)
BN_mod_inverse(d, e, phi, ctx);
```

**Input:**
```
p = F7E75FDC469067FFDC4E847C51F452DF
q = E85CED54AF57E53E092113E62F436F4F
e = 0D88C3
```

**Output:**
```
d = 3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
```

---

## Task 2 — Encryption

Encrypt `"A top secret!"` using the public key `(e, n)`.

```c
// Convert ASCII to hex: 4120746f702073656372657421
BN_hex2bn(&M, "4120746F702073656372657421");

// C = M^e mod n
BN_mod_exp(C, M, e, n, ctx);
```

**Output:**
```
Ciphertext C = 6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
```

---

## Task 3 — Decryption

Decrypt ciphertext back to plaintext using private key `d`.

```c
// M = C^d mod n
BN_mod_exp(decrypted, ciphertext, d, n, ctx);
```

Recovered plaintext hex → ASCII:
```bash
python3 -c 'print(bytes.fromhex("50617373776f726420697320646565...").decode("utf-8"))'
# Password is dees
```

---

## Task 4 — Digital Signature

Sign `"I owe you $2000."` vs `"I owe you $3000."` — demonstrates the **avalanche effect**.

```c
// S = M^d mod n
BN_mod_exp(s2000, m2000, d, n, ctx);
BN_mod_exp(s3000, m3000, d, n, ctx);
```

**Output — observe how a single digit change produces a completely different signature:**
```
S($2000) = 55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB
S($3000) = BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822
```

> This is the avalanche effect in action — a cryptographic guarantee that you cannot forge or modify a signed document without detection.

---

## Task 5 — Signature Verification

Bob verifies Alice's signature on `"Launch a missile."` using her public key.

```c
// Verify: M_verify = S^e mod n
BN_mod_exp(M_verify, S, e, n, ctx);

if (BN_cmp(M_verify, M) == 0)
    printf("VERIFIED — Message is from Alice.\n");
```

**Tampered signature (last byte `2F` → `3F`, a 1-bit change):**
```
Decrypted tampered sig = 91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294
Result: FAILED — Signature verification failed. Message tampered!
```

The entire decrypted value transforms — **one flipped bit propagates through 256 bytes** of output via modular exponentiation.

---

## Task 6 — X.509 Certificate Verification

Manually verifying the TLS certificate of `www.python.org` — the exact process your browser performs silently on every HTTPS connection.

### Step-by-step

```bash
# 1. Download the certificate chain
bash scripts/extract_cert.sh www.python.org

# 2. This extracts:
#    c0.pem  — server certificate (www.python.org)
#    c1.pem  — issuer certificate (GlobalSign Atlas R3 DV TLS CA 2024 Q2)
```

The verification logic:

```c
// Decrypt the CA's signature using its own public key
BN_mod_exp(decs, s, e, n, ctx);          // decs = S^e mod n

// Mask to 256 bits to isolate the embedded SHA-256 hash
BN_mask_bits(decs, 256);

// Compare with SHA-256 of the certificate body
if (BN_cmp(decs, m) == 0)
    printf("CERTIFICATE VALID\n");
```

**Result:**
```
Decrypted s (256b) = 13F5C5878B0AE14E94E7E3C6DC4B62E7F5C8B6D198EBAF17E14EA0C04AFADD90
Certificate body   = 13F5C5878B0AE14E94E7E3C6DC4B62E7F5C8B6D198EBAF17E14EA0C04AFADD90

Result: CERTIFICATE VALID — Signature matches certificate body hash.
```

The entire HTTPS trust model — certificate authorities, chain of trust, TLS handshake — reduces to this single comparison.

---

## Key Concepts Demonstrated

**Modular Exponentiation** — The foundation of RSA. `BN_mod_exp()` uses fast repeated-squaring, making it feasible to raise 2048-bit numbers to 65537th powers in milliseconds.

**Modular Inverse** — The Extended Euclidean Algorithm finds `d` such that `e·d ≡ 1 (mod φ(n))`. This relationship is what makes encryption reversible only by the key holder.

**Avalanche Effect** — Observed in Task 4 and 5: any change to input, however small, produces an unrecognizable output. This isn't a side effect — it's a security requirement.

**PKCS#1 Padding** — Visible in Task 6's decrypted signature: the long sequence of `FF` bytes before the hash is PKCS#1 v1.5 padding — a standardized prefix that prevents certain padding oracle attacks.

**X.509 / ASN.1 Structure** — Certificates are ASN.1-encoded DER structures. The "body" that gets hashed excludes the signature field itself, which is why `openssl asn1parse -strparse 4` is used to extract only the TBS (To Be Signed) portion.

---

## Authors

**Ayah Husam Omar Sa'deh** — ID: 0215258
**Kamelia Salameh Micheal Qumsieh** — ID: 2212189

*Information and Network Security — Dr. Ramzi Saifan*

---

<div align="center">
<sub>Built with OpenSSL BIGNUM · SEED Security Labs · Jordan University of Science and Technology</sub>
</div>
