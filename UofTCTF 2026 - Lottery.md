# Lottery

> Can you help Han Shangyan win the lottery?

We are provided with a Bash script that simulates a lottery game. Here is the source code:

```bash
#!/bin/bash

echo "Today's lottery!"
echo "Guess the winning ticket (hex):"
read guess

# Validation Check
if [[ "$guess" =~ ^[0-9a-fA-F]+ ]]; then
    let "g = 0x$guess" 2>/dev/null
else
    echo "Invalid guess."
    exit 1
fi

# Ticket Generation
ticket=$(head -c 16 /dev/urandom | md5sum | cut -c1-16)
let "t = 0x$ticket" 2>/dev/null

# Comparison
if [[ $g -eq $t ]]; then
    cat /flag.txt
else
    echo "Not a winner. Better luck next time!"
fi
```

#### The Vulnerabilities

There are two distinct vulnerabilities that, when chained together, allow for Remote Code Execution (RCE).

**A. Regex Bypass**

The script attempts to validate the input using a Regular Expression:

```bash
if [[ "$guess" =~ ^[0-9a-fA-F]+ ]]; then
```

The regex `^[0-9a-fA-F]+` checks if the input **starts** (`^`) with one or more hexadecimal characters. Critically, it lacks the end-of-string anchor (`$`). This means that as long as our input begins with a valid hex digit (e.g., `0`or `A`), we can append arbitrary characters afterwards (like spaces, symbols, and commands), and the check will pass.

**B. `let` Arithmetic Injection**

The script uses the `let` command to convert the hex string to a decimal value:

```bash
let "g = 0x$guess" 2>/dev/null
```

**let** is a Bash builtin for arithmetic evaluation. It has a known quirk: it allows array indexing.

If you pass a variable like arr\[index], Bash evaluates the expression inside the brackets to determine the index.

If that expression is a command substitution ($(command)), Bash executes the command before the arithmetic operation takes place.

### 2. Exploitation Strategy

We cannot simply guess the random number. We must use the `let` injection to execute code and read the flag.

#### The Problem: Blind Injection

The script redirects standard error (stderr) to `/dev/null`:

```bash
2>/dev/null
```

Furthermore, because the injection happens inside a variable assignment (`g = ...`), the standard output (stdout) of our command is captured by the arithmetic expression parser or simply lost if the command doesn't return a number. We won't see the output of `cat /flag.txt` on the screen.

#### The Solution: File Descriptor Redirection

To bypass the "blindness," we need to force the output of our command to write directly to the terminal, bypassing the script's internal capturing.

In Linux/Bash, the current process's Standard Output (stdout) is linked to file descriptor `1`. We can access this via `/proc/$$/fd/1`, where `$$` represents the Process ID (PID) of the current script.

#### Constructing the Payload

1. **Pass Regex:** Start with `0` (valid hex).
2. **Arithmetic Syntax:** Use an operator (like `+`) to append our injection cleanly.
3. **Array Injection:** Use `a[...]` (variable `a` doesn't need to exist, it evaluates to 0).
4. **Command Execution:** Use `$(...)` inside the array index.
5. **Exfiltration:** Redirect the command output to `/proc/$$/fd/1`.

**Draft Payload:** `0 + a[$(cat /flag.txt > /proc/$$/fd/1)]`

When the script runs `let "g = 0x$guess"`, it effectively executes:

```bash
let "g = 0x0 + a[$(cat /flag.txt > /proc/$$/fd/1)]"
```

### 3. Final Exploit

To solve the challenge, run the script (or connect to the server) and input the payload when prompted.

**Input:**

```bash
0 + a[$(cat /flag.txt > /proc/$$/fd/1)]
```

Result:

```plaintext
Guess the winning ticket (hex):
0 a[$(cat /flag.txt > /proc/$$/fd/1)]
uoftctf{you_won_the_LETtery_(hahahaha_get_it???)}Not a winner. Better luck next time!
```

The `cat` command executes, reads the flag, and forces it directly to your terminal via the file descriptor redirect. The script might subsequently crash or print "Not a winner," but the flag will have already been revealed.
