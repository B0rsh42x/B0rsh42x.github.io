+++
title = "MIX (Reverse) | Luxor Finals CTF"
date = "2026-04-01"
author = "B0rsh42x"
tags = ["ctf", "reverse-engineering", "writeup"]
description = "Writeup for a reverse engineering CTF challenge from Luxor Finals involving a custom XOR-based cipher with rotating bitwise shifts."
+++

This writeup documents solving a reverse engineering challenge from Luxor Finals. The challenge involved analyzing a 64-bit Linux executable that required decrypting data using a custom XOR-based cipher.

## Initial Analysis

The executable accepted hex-formatted keys as input. Using radare2, I examined the binary's sections and strings.

## Key Findings

Through radare2 inspection, I identified:
- Encrypted data stored at memory address `0x4060`
- A 16-byte encryption key at address `0x40a0`: `f13d729c71062e1729978e005cdc90d7`
- Ciphertext: `b2038ac8a4631b4a92f4253238dc75b58692475dfc343a381e4e5e37db41f59da15e8040433edd723068b93414bf4266c348f9f8d02c1e1d95f4296469c4`

## Encryption Logic

Initial XOR decryption attempts failed. Further analysis at memory address `0x1240` revealed the actual encryption mechanism:

```
key_byte = key[i % 16]
rotated  = key_byte << (i % 3)
data[i]  = data[i] ^ rotated
```

The cipher applied a rotating left bitwise shift to each key byte before XORing with the ciphertext.

## Solution

```python
data = bytes.fromhex("b2038ac8a4631b4a92f4253238dc75b58692475dfc343a381e4e5e37db41f59da15e8040433edd723068b93414bf4266c348f9f8d02c1e1d95f4296469c40000")
key  = bytes.fromhex("f13d729c71062e1729978e005cdc90d7")

def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

result = bytearray()
for i in range(len(data)):
    key_byte = key[i % len(key)]
    rotated  = rol8(key_byte, i % 3)
    result.append(data[i] ^ rotated)

print(result.decode(errors="ignore"))
```

## Flag

```
CyCTF{5d6c82de7bef5d92fd7ad7c2e2fcd222eeb674ecc9220d24031c4d5}
```

*Solved with Omar El Fakhrany (z3r0s6)*
