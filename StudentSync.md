# CTF Challenge Writeup: StudentSync

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** StudentSync  
**Points:** 400  
**Category:** Cryptography / Incident Forensics  

---

## Challenge Description
An incident investigation of StudentSync's internal release infrastructure recovered encrypted message tickets, cryptographic key registrations, and signed release attestations:

> "A security incident has been reported in StudentSync's internal release infrastructure. Investigators recovered encrypted message tickets, cryptographic key registrations, signed release attestations, and a suspicious backup artifact. The infrastructure uses multiple cryptographic mechanisms to protect sensitive release communications. Inconsistencies across the evidence suggest that some mechanisms may have been implemented or configured incorrectly. Recover the hidden flag."

Required flag format: `VOID{...}`

---

## Step-by-Step Solution

### Step 1: Discover and Map Artifacts
We examined the extracted artifacts:
* `services.json`: Key registrations containing public keys for services (RSA moduli and exponents, ECDSA public keys).
* `messages.jsonl`: Encrypted tickets (`msg-0001`, `msg-0002`) destined for specific services.
* `signed_records.json`: Attestations signed by `release-bot` over curve `secp256r1`.
* `backup.json`: System metadata and key provisioning history.

---

### Step 2: Shared RSA Modulus Factor (Batch GCD)
In `services.json`, two RSA services were provisioned by the same administrator:
* `rsa-f10091d49ddc` assigned to `file-relay` ($n_1, e=65537$)
* `rsa-18e07b496b3e` assigned to `archive-sync` ($n_2, e=65537$)

Computing the greatest common divisor between the two moduli revealed a shared prime factor:
$$p = \gcd(n_1, n_2) > 1$$

With $p$ discovered:
$$q_1 = \frac{n_1}{p}, \quad \phi(n_1) = (p - 1)(q_1 - 1), \quad d_1 \equiv e^{-1} \pmod{\phi(n_1)}$$

This completely broke the private key for `file-relay`. Using the recovered private key, we decrypted ticket `msg-0002` (encrypted with RSA-OAEP SHA-256). Decrypting `msg-0002` revealed a 73-byte binary payload:
* **IV (12 bytes):** `2b81cce64137e1e68c21b36d`
* **Ciphertext (45 bytes):** `3117396c30508cf4580656aaf021fc49bd3e477838643dfb0bbe474ca8b026ad004188a468c84ffc6666a90785`
* **GCM Tag (16 bytes):** `5a0fcd817bd5d209b966db7f3e44e0d6`

This payload was protected using AES-256-GCM, but we needed the symmetric key.

---

### Step 3: ECDSA Nonce-Reuse Exploitation
Next, we analyzed `signed_records.json` containing attestations signed by `release-bot` (`ecdsa-668ebc7e5e4a`) on curve `secp256r1`.

Comparing signatures `att-0001` and `att-0002`:
* Both signatures had the exact same $r$ coordinate:
  $$r = \text{0xe7ebce215eda43229f6257d1d74e95828c4a1eeba395e9052caaf565b5124332}$$

In ECDSA, the signature pair is computed as:
$$s \equiv k^{-1}(z + r \cdot d) \pmod n$$
where $k$ is the per-signature ephemeral nonce, $z = \text{SHA-256}(m)$, and $d$ is the private signing key.

Because $r$ was identical across two different messages $m_1$ and $m_2$, the signer reused the exact same nonce $k$:
$$s_1 \equiv k^{-1}(z_1 + r \cdot d) \pmod n$$
$$s_2 \equiv k^{-1}(z_2 + r \cdot d) \pmod n$$

Subtracting the two equations:
$$s_1 - s_2 \equiv k^{-1}(z_1 - z_2) \pmod n$$
$$k \equiv (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n$$

Once $k$ was recovered, the private signing key $d$ was computed directly:
$$d \equiv r^{-1}(s_1 \cdot k - z_1) \pmod n$$

Executing this yielded:
$$d = \text{0xb02bebae48ed101150fa4371a7034fba22755d9c849c719c69dee663434ac058}$$

Validating against the public key $Q = d \cdot G$ confirmed an exact match with the registered public key for `release-bot`.

---

### Step 4: AES-256-GCM Payload Decryption
According to system convention, release secrets were protected with a key derived from the release bot's private signing key:
$$K = \text{SHA-256}(d)$$

We initialized AES-256-GCM with key $K$, the 12-byte IV, and verified the 16-byte authentication tag. Decrypting the 45-byte ciphertext produced the plaintext flag.

---

## Exploit Script

```python
import hashlib
import json
import math
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# 1. Recover RSA Private Key via GCD
with open("services.json", "r") as f:
    services = json.load(f)

n1 = int(services["file-relay"]["modulus"], 16)
n2 = int(services["archive-sync"]["modulus"], 16)
e = 65537

p = math.gcd(n1, n2)
q1 = n1 // p
phi = (p - 1) * (q1 - 1)
d1 = pow(e, -1, phi)

rsa_key = RSA.construct((n1, e, d1, p, q1))
cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=hashlib.sha256)

# Read msg-0002
with open("messages.jsonl", "r") as f:
    for line in f:
        ticket = json.loads(line)
        if ticket["id"] == "msg-0002":
            enc_data = bytes.fromhex(ticket["payload"])

inner_blob = cipher_rsa.decrypt(enc_data)
iv = inner_blob[:12]
ciphertext = inner_blob[12:-16]
tag = inner_blob[-16:]

# 2. Recover ECDSA Private Key via Nonce Reuse
n_curve = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

with open("signed_records.json", "r") as f:
    records = json.load(f)

r1 = int(records["att-0001"]["r"], 16)
s1 = int(records["att-0001"]["s"], 16)
z1 = int(
    hashlib.sha256(records["att-0001"]["message"].encode()).hexdigest(), 16
)

r2 = int(records["att-0002"]["r"], 16)
s2 = int(records["att-0002"]["s"], 16)
z2 = int(
    hashlib.sha256(records["att-0002"]["message"].encode()).hexdigest(), 16
)

assert r1 == r2

# Recover k and d
k = ((z1 - z2) * pow(s1 - s2, -1, n_curve)) % n_curve
d = (pow(r1, -1, n_curve) * (s1 * k - z1)) % n_curve
d_bytes = d.to_bytes(32, "big")

# 3. Decrypt AES-256-GCM Payload
aes_key = hashlib.sha256(d_bytes).digest()
cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

print("Decrypted Flag:", plaintext.decode("utf-8"))
```

---

## Verification
* $p \cdot q_1 == n_1$ verified exactly.
* Computed $d \cdot G$ on `secp256r1` matches public key point $(x, y)$ of `release-bot` byte-for-byte.
* AES-GCM MAC tag matched and verified cleanly without authentication error.

---

## Flag
```
VOID{stolen_signer_unlocked_90d59306cb0bd8f2}
```
