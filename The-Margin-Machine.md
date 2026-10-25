# CTF Challenge Writeup: The Margin Machine

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** The Margin Machine  
**Points:** 350  
**Category:** Cryptography / Classical Ciphers  

---

## Challenge Description
We were provided an archive of historical notes and test logs:

> "An archivist left a message encoded by a hand-built letter machine. The machine card is incomplete, and the logbook contains three sample input/output pairs. Reconstruct the rule and recover the message. The margin note is part of the evidence; do not assume every printed instruction is current."

Required flag format: `VOID{...}`

---

## Step-by-Step Solution

### Step 1: Analyze the Machine Card and Operator Log
From `machine_card.txt` and `operator_log.txt`:
* Key: The word `LANTERN` (length 7).
* Alphabet: $A=0, B=1, \dots, Z=25$. Non-alphabet characters are preserved verbatim.
* Three test pairs:
  * **Sample 1:** `ATTACK AT DAWN` $\rightarrow$ `PTGHYT NI DNDJ`
  * **Sample 2:** `MEET AT NOON` $\rightarrow$ `BERA WC ADOA`
  * **Sample 3:** `VOID{READ_THE_MARGIN_TWICE}` $\rightarrow$ `GOVW{VVNO_TUX_QRERIA_MAZPP}`

---

### Step 2: Identify the Rule Discrepancy
The printed machine card instructed adding the key values modulo 26:
$$c_i = (p_i + k_i) \pmod{26}$$

Testing this forward rule on Sample 3:
$$\text{encode\_old}(\text{"VOID\{READ\_THE\_MARGIN\_TWICE\}"}) = \text{"GOVW\{VVNO\_TUX\_QRERIA\_MAZPP\}"}$$
This matches Sample 3's output.

However, testing the card rule on Samples 1 and 2 failed. Examining the hand-written margin note on the card:
> *"Wheel reversed after gear swap — turns back, not forward."*

When the wheel turns backward, encryption subtracts the key value modulo 26:
$$c_i = (p_i - k_i) \pmod{26}$$

Testing the revised rule:
* `ATTACK AT DAWN` $\rightarrow$ `PTGHYT NI DNDJ` (Matches Sample 1)
* `MEET AT NOON` $\rightarrow$ `BERA WC ADOA` (Matches Sample 2)

---

### Step 3: Reconstruct the Decoder and Recover the Flag
Because Sample 3 was encoded under the old forward addition rule $(p + k) \pmod{26}$, decoding it requires subtracting the key:
$$p_i = (c_i - k_i) \pmod{26}$$

Remarkably, this decoding operation is identical to the machine's revised margin rule. Passing the ciphertext `GOVW{VVNO_TUX_QRERIA_MAZPP}` through the revised machine yields the plaintext flag:

```python
KEY = "LANTERN"

def decode(ciphertext: str) -> str:
    res = []
    ki = 0
    for ch in ciphertext:
        if 'A' <= ch <= 'Z':
            c = ord(ch) - ord('A')
            k = ord(KEY[ki % len(KEY)]) - ord('A')
            res.append(chr(ord('A') + (c - k) % 26))
            ki += 1
        else:
            res.append(ch)
    return "".join(res)

flag = decode("GOVW{VVNO_TUX_QRERIA_MAZPP}")
print(flag)
```

Output:
```
VOID{READ_THE_MARGIN_TWICE}
```

---

## Flag
```
VOID{READ_THE_MARGIN_TWICE}
```
