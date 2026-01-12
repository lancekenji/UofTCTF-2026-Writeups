# Firewall

## Challenge Overview

This CTF challenge presents an eBPF-based network firewall that filters TCP traffic for the keyword "flag" and the character '%'. The objective is to retrieve a flag from an nginx web server at `35.227.38.232:5000` serving `/flag.html`.

### Vulnerability Analysis

#### Firewall Implementation

The firewall is implemented as an eBPF program (`firewall.c`) attached to both ingress and egress TC (Traffic Control) hooks. Key observations:

```c
#define KW_LEN 4
static const char blocked_kw[KW_LEN] = "flag";
static const char blocked_char = '%';

__u32 __always_inline has_blocked_kw(struct __sk_buff *skb, __u32 off, __u32 len)
{
    // Cannot match when length is shorter than KW_LEN
    if (len < KW_LEN) {
        return 0;
    }
    // ... pattern matching logic
}
```

#### Critical Vulnerability

**The firewall examines each TCP packet individually.** If a packet has `len < 4 bytes`, it cannot possibly contain the 4-byte string "flag" and will pass through unchecked.

This creates an exploitable weakness:

* Packets smaller than 4 bytes are **automatically allowed**
* The firewall has no state tracking across packets
* No reassembly or stream inspection is performed

### Exploitation Strategy

#### Phase 1: Request Fragmentation

Split the HTTP request into chunks of ≤3 bytes to avoid the word "flag" appearing in any single packet:

```
GET /flag.html → ["GET", " /f", "lag", ".ht", "ml ", ...]
```

Breaking "flag" across packet boundaries:

* Packet 1: `" /f"` (3 bytes)
* Packet 2: `"lag"` (3 bytes)

Neither packet contains "flag" when inspected individually.

#### Phase 2: Response Fragmentation via TCP Window Control

The server's response will also contain "flag" in the HTML. To bypass egress filtering, we must force the server to send small packets.

**TCP Window Size** is the key mechanism:

* The TCP window advertises how much data the receiver can accept
* The sender **must respect** this window size
* By setting `window=1` or `window=4`, we force the server to send tiny segments

Implementation:

1. Send `window=5` in SYN packet (small initial window)
2. Send `window=1` in handshake ACK
3. Send `window=4` in all data ACKs

This guarantees server responses are ≤4 bytes, preventing "flag" from appearing in a single packet.

#### Phase 3: Response Reassembly

Since we receive fragmented data:

1. Capture all TCP packets using Scapy
2. Store packets by sequence number
3. Send ACK for each packet with small window
4. Reassemble data in sequence order
5. Parse Content-Length to detect completion

### Technical Implementation

#### Key Components

```python
# TCP Handshake with window control
syn = TCP(sport=sport, dport=TARGET_PORT, flags="S", seq=seq_num, window=5)
ack = TCP(..., window=1)  # Force small segments from start

# Fragmented request (19 parts, each ≤3 bytes)
request_parts = [b"GET", b" /f", b"lag", b".ht", b"ml ", ...]

# ACK with small window for each response packet
ack_pkt = TCP(..., ack=my_ack, window=4)
```

#### Packet Flow

```
Client → Server: SYN (window=5)
Server → Client: SYN-ACK
Client → Server: ACK (window=1)
Client → Server: "GET" (3 bytes, PSH+ACK)
Client → Server: " /f" (3 bytes, PSH+ACK)
Client → Server: "lag" (3 bytes, PSH+ACK)
...
Server → Client: HTTP headers (232 bytes in small chunks)
Server → Client: "<!D" (3 bytes) ✓ Passes firewall
Server → Client: "OCT" (3 bytes) ✓ Passes firewall
Server → Client: "YPE" (3 bytes) ✓ Passes firewall
...
```

Each packet is ≤4 bytes, so "flag" never appears in a single packet at either ingress or egress.

### Attack Constraints

#### What Doesn't Work

1. **IP Fragmentation**: Blocked by firewall (`IP_MF | IP_OFFSET`)
2. **MSS Option**: Server (nginx) often ignores TCP MSS suggestions
3. **Large Initial Window**: Allows server to send large packets containing "flag"

#### What Works

* **TCP Window Advertisement**: Server MUST respect this (RFC 793)
* **Sub-4-byte packets**: Cannot match 4-byte keyword
* **Bidirectional fragmentation**: Both request and response are safe

### Results

Running the exploit:

```bash
$ sudo python3 test.py
[*] Targeting 35.227.38.232:5000
[*] Strategy: Fragmenting request into sub-4-byte packets
[+] Connection established
[*] Sending HTTP request in 19 fragments...
[+] Content-Length: 213 bytes
[+] Captured 141+ packets
[+] Unique sequences: 141+

============================================================
SUCCESS! Response received:
============================================================
HTTP/1.1 200 OK
...
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Flag!</title>
</head>
<body>
  <h1>Here is your free flag: uofctf{...}</h1>
</body>
</html>
```

### Lessons Learned

1. **Per-packet inspection is insufficient** for stream-based protocols like TCP
2. **TCP window control** is a powerful, often overlooked mechanism
3. **State tracking** is essential for effective network filtering
4. eBPF firewalls must perform **stream reassembly** to detect patterns across packets

### Mitigation Recommendations

To fix this vulnerability:

1. **Implement stateful inspection**: Track TCP streams and reassemble data
2. **Use conntrack/nfconntrack**: Maintain connection state
3. **Deep Packet Inspection at stream level**: Inspect reassembled application data
4. **Layer 7 filtering**: Use application-aware proxies (e.g., Envoy, HAProxy)
5. **Consider existing solutions**: Use established firewalls like iptables with conntrack, nftables, or Cilium with proper stream tracking
