**Category:** Misc  
**Challenge Name:** Encryption Service

---

## Challenge Description

> We made an encryption service. We forgot to make the decryption though.  
> As compensation we are giving free encrypted flags.

The service allows users to submit plaintexts, which are then encrypted using AES-CBC with a user-supplied key. As a bonus, the flag is appended to the plaintext and encrypted as well.

---

## Provided Files

### `enc.py`

```python
#!/usr/local/bin/python3

import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <hex_key> <plaintext...>")
        sys.exit(1)

    key_hex = sys.argv[1]
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("Invalid hex key")
        sys.exit(1)

    if len(key) != 16:
        sys.exit(1)

    pt = "\n".join(sys.argv[2:]).encode()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, AES.block_size))

    print(iv.hex() + ct.hex())

if __name__ == "__main__":
	main()
```
## `run.sh`

```bash
#!/bin/sh

OUTFILE="/tmp/input.txt"

head -c 16 /dev/urandom | od -An -tx1 | tr -d ' ' > "$OUTFILE"

echo "Welcome to the encryption service"
echo "Please put in all your plaintexts"
echo "End with EOF"

while true; do
    read -r line

    if [ "$line" = "EOF" ]; then
        break
    fi

    echo "$line" >> "$OUTFILE"
done

echo "As a bonus we will also encrypt the flag for you"

cat /flag.txt >> "$OUTFILE"

echo "Here is the encryption."
echo "$(cat "$OUTFILE" | xargs /app/enc.py)"
```
## Vulnerability Analysis

At first glance, this looks like a standard AES-CBC encryption service. However, the real vulnerability has **nothing to do with cryptography**.

### Root Cause: `xargs`

The service invokes:

```bash
cat "$OUTFILE" | xargs /app/enc.py
```

Important properties of `xargs`:

- It **splits input into multiple command executions** if the argument size exceeds the system limit (~128KB).
    
- Each execution calls `enc.py` **again**, independently.
    
- The first argument to `enc.py` is interpreted as the **AES key**.

### Why This Is Bad

- The first line of `OUTFILE` is a random 16-byte hex string → used as the AES key.
    
- All following lines are treated as plaintext.
    
- If we make the input large enough, `xargs` will:
    
    - Execute `enc.py` multiple times
        
    - Use attacker-controlled data as the AES key for later executions
        
    - Re-append the flag for each execution


This means we can:

1. Force a **known AES key**
    
2. Get the flag encrypted under that key
    
3. Decrypt it locally

No oracle. No brute force. Just Unix behavior.

## Exploitation Strategy

1. Send **thousands of fake keys** (valid 16-byte hex strings).
    
2. Overflow the `xargs` buffer.
    
3. Force `xargs` to split into multiple executions.
    
4. Capture the **last encryption**, which:
    
    - Uses our controlled AES key
        
    - Contains the flag
        
5. Decrypt locally.

## Exploit Script
## `solution.py`

```python
from pwn import *
from Crypto.Cipher import AES

context.log_level = 'info'

def solve():
    conn = remote('34.86.4.154', 5000)

    FAKE_KEY_HEX = "0" * 32
    FAKE_KEY_BYTES = bytes.fromhex(FAKE_KEY_HEX)

    PAYLOAD_LINES = 6000

    for _ in range(PAYLOAD_LINES):
        conn.sendline(FAKE_KEY_HEX.encode())

    conn.sendline(b"EOF")

    conn.recvuntil(b"Here is the encryption.\n")
    output = conn.recvall().decode().strip()

    encrypted_lines = output.split('\n')

    if len(encrypted_lines) < 2:
        log.error("xargs did not split")
        sys.exit(1)

    target = encrypted_lines[-1]

    iv = bytes.fromhex(target[:32])
    ct = bytes.fromhex(target[32:])

    cipher = AES.new(FAKE_KEY_BYTES, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)

    pt_str = pt.decode(errors="ignore")
    print(pt_str)

if __name__ == "__main__":
    solve()
```

## Output

```plaintext
00000000000000000000000000000000
00000000000000000000000000000000
...
uoftctf{x4rgs_d03sn7_run_in_0n3_pr0c3ss}
```

## Flag

`uoftctf{x4rgs_d03sn7_run_in_0n3_pr0c3ss}`

## Takeaways

- `xargs` **does not guarantee a single execution**
    
- Never use `xargs` with security-sensitive arguments
    
- Crypto code can be perfectly fine and still be useless if the **wrapper script is broken**
    
- Sometimes the best crypto attack is just… **Unix trivia**

## TL;DR

> The encryption was secure.  
> The shell script was not.  
> `xargs` snitched the flag.

