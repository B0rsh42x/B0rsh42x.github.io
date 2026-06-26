+++
title = "MIX (reverse) | Luxor Finals CTF"
date = "2026-04-01"
author = "B0rsh42x"
tags = ["reverse-engineering", "ctf", "writeup", "radare2"]
description = "Writeup for a reverse engineering challenge from Luxor Finals CTF involving radare2 analysis and a custom XOR cipher with rotating bitwise shifts."
+++

the Authors forbidden the AI in this CTF

lets see the file

---

shows it is It is a **64-bit Linux executable**

First lets run the program and see how it works

so, the program takes hex format valid key to run in normal behavior

lets analyze it by `R2` , while no AI to help us in command we use this repo from github

- https://gist.github.com/werew/cad8f30bc930bfca385554b443eec2a7
- https://github.com/radareorg/radare2/blob/master/doc/intro.md

---

## 1 — Opening the file in radare2

I started by opening the file in radare2 and checking its basic information:

```
r2 -q -c 'iI; izz~Invalid; izz~normal; izz~encryption; iS~data' mix.zip
```

- `iI` → shows general information about the binary
- `izz` → lists all strings inside the file
- `~` → filters the output (like grep)
- `iS` → shows the binary sections

**Findings:**

- we have in `0x00002000` ⇒ .rodata
- we have in `0x00004040` ⇒ .data

---

## 2 — Dumping the data section

lets dump the all data

```
r2 -q -c 'px @ section..data' mix.zip
```

- `px` ⇒ show raw bytes in hex
- `@ section..data` → start from the `.data` section

At address `0x4060`, there is a large block of random-looking bytes. This likely represents the encrypted data (ciphertext).

At address `0x40a0`, there is a 16-byte value: looks like key lets try it

and yess it is the key

---

## 3 — First decryption attempt (XOR)

```python
sdata = bytes.fromhex("b2038ac8a4631b4a92f4253238dc75b58692475dfc343a381e4e5e37db41f59da15e8040433edd723068b93414bf4266c348f9f8d02c1e1d95f4296469c4")
key  = bytes.fromhex("f13d729c71062e1729978e005cdc90d7")

result = bytearray()

for i in range(len(data)):
    result.append(data[i] ^ key[i % len(key)])

print(result)
print(result.decode(errors="ignore"))
```

The script performs **XOR decryption**:

1. `sdata` is a hex string converted to bytes (the encrypted data)
2. `key` is another hex string converted to bytes (the encryption key)
3. It XORs each byte of `sdata` with a corresponding byte from the key (cycling through the key using modulo)
4. The result is printed as raw bytes and as a decoded string (ignoring errors)

it doesn't work, This confirmed the key isn't used directly — there's an additional transformation ,, it means there are missing piece

---

## 4 — Going deeper at 0x1240

after long time in analyzing and trying to get the logic of the challenge we go **at 0x1240**

```
[0x00001140]> s 0x1240
[0x00001240]> pd 150
```

**The real logic discovered:**

```
key_byte = key[i % 16]
rotated  = key_byte << (i % 3)
data[i]  = data[i] ^ rotated
```

real code should be

`cipher ^ (shifted key)`

---

## 5 — Final solution

my friend z3r0s6 wrote the python script for full mask we should have

```python
data = bytes.fromhex("b2038ac8a4631b4a92f4253238dc75b58692475dfc343a381e4e5e37db41f59da15e8040433edd723068b93414bf4266c348f9f8d02c1e1d95f4296469c40000")
key = bytes.fromhex("f13d729c71062e1729978e005cdc90d7")

def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

mask = bytearray()
result = bytearray()

for i in range(len(data)):
    key_byte = key[i % len(key)]
    rotated = rol8(key_byte, i % 3)
    mask.append(rotated)
    result.append(data[i] ^ rotated)

print(mask.hex())
print(result.decode(errors="ignore"))
```

How the algorithm works:

1. take one byte from the 16-byte key
2. shift it by `i % 3`
3. store it in the full mask
4. XOR it with the ciphertext byte

---

## Flag

```
CyCTF{5d6c82de7bef5d92fd7ad7c2e2fcd222eeb674ecc9220d24031c4d5}
```

solved with my teammate (omar el fakhrany) *z3r0s6*
