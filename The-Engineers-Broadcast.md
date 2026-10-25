# CTF Challenge Writeup: The Engineer's Broadcast

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** The Engineer's Broadcast  
**Points:** 200  
**Category:** Cryptography  

---

## Challenge Description
We were given three sets of RSA public parameters and ciphertexts, along with the following operator note:

> "A legacy signer says the message was encrypted independently for three recipients. The dump contains three public RSA moduli and ciphertexts. The operator log says the same payload was sent to all three recipients. Determine whether the encoding actually provides independent security, then recover the payload. No private keys are provided."

Required flag format: `VOID{...}`

---

## Step-by-Step Solution

### Step 1: Analyze the Parameters
We inspected `recipients.csv`:

| Recipient | Public Exponent ($e$) | Modulus ($n$) Bit Length | Ciphertext ($c$) |
|---|---|---|---|
| `key_1` | 3 | ~320 bits | $c_1$ |
| `key_2` | 3 | ~320 bits | $c_2$ |
| `key_3` | 3 | ~320 bits | $c_3$ |

Key observations:
1. All three recipients share the exact same small public exponent $e = 3$.
2. The exact same plaintext payload $m$ was broadcast to all three recipients without padding:
   $$c_1 \equiv m^3 \pmod{n_1}$$
   $$c_2 \equiv m^3 \pmod{n_2}$$
   $$c_3 \equiv m^3 \pmod{n_3}$$
3. We checked pairwise greatest common divisors $\gcd(n_i, n_j) = 1$, confirming the moduli are pairwise coprime.

This is the textbook scenario for **Håstad's Broadcast Attack**.

---

### Step 2: Håstad's Broadcast Attack with CRT
Because the moduli $n_1, n_2, n_3$ are pairwise coprime, we can combine the three modular equations using the **Chinese Remainder Theorem (CRT)** to find $C$ such that:

$$C \equiv c_i \pmod{n_i} \quad \text{for } i \in \{1, 2, 3\}$$

Modulo $N = n_1 \cdot n_2 \cdot n_3$:
$$C \equiv m^3 \pmod{N}$$

Since the original plaintext message $m$ is smaller than each individual modulus ($m < n_i$), its cube is strictly smaller than the product of the moduli:
$$m^3 < n_1 \cdot n_2 \cdot n_3 = N$$

Because $m^3 < N$, modular reduction modulo $N$ does not wrap around! $C$ is the **exact integer cube** of the message:
$$C = m^3$$

---

### Step 3: Compute Integer Cube Root
We compute the exact integer cube root of $C$ over $\mathbb{Z}$:

```python
def integer_cbrt(n):
    low = 0
    high = 1 << ((n.bit_length() + 2) // 3)
    while low < high:
        mid = (low + high) // 2
        if mid ** 3 < n:
            low = mid + 1
        else:
            high = mid
    return low

m = integer_cbrt(C)
assert m ** 3 == C
```

Converting $m$ to ASCII bytes yields the original broadcast payload:

```python
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(plaintext.decode('utf-8'))
```

Output:
```
VOID{BROADCAST_WITHOUT_PADDING}
```

---

## Verification
Re-encrypting $m^3 \pmod{n_i}$ for $i=1, 2, 3$ matches $c_1, c_2, c_3$ byte-for-byte.

---

## Flag
```
VOID{BROADCAST_WITHOUT_PADDING}
```
