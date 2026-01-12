# Gambler's Fallacy

### Challenge Overview

A dice-based gambling game where you start with $800 and need to reach $10,000 to buy the flag. The game allows you to:

* Bet on dice rolls (0-99)
* Set a "greed" threshold (2-98)
* Win if the roll ≤ greed, with multiplier = 99/greed
* Play multiple games in sequence

#### Key Files

* `chall.py` - The challenge server code
* `solve.py` - The exploit script
* `serverseed` - Random seed file (unknown to us)

### The Vulnerability

#### Provably Fair System Gone Wrong

The game implements a "provably fair" dice system where:

1. Server generates a random 32-bit seed using Python's `random.getrandbits(32)`
2. Dice roll is deterministic: `HMAC-SHA256(server_seed, client_seed-nonce)`
3. **After each game, the server reveals the server\_seed used**

#### The Critical Flaw

Python's `random` module uses the **Mersenne Twister (MT19937)** PRNG, which has a well-known property:

* Given **624 consecutive outputs** of `getrandbits(32)`, you can completely reconstruct the internal state
* Once you have the state, you can predict all future outputs

Since the server reveals each server seed after every game, we can:

1. Collect 624 server seeds
2. Reverse-engineer the MT19937 state
3. Predict all future server seeds
4. Calculate future dice rolls
5. Only bet on guaranteed wins

### The Mathematics

#### Dice Roll Generation

```python
nonce_client_msg = f"{client_seed}-{nonce}".encode()
sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()

# Extract lucky number from first 5 hex chars < 1,000,000
index = 0
lucky = int(sig[index*5:index*5+5], 16)
while lucky >= 1e6:
    index += 1
    lucky = int(sig[index * 5:index * 5 + 5], 16)
    
roll = round((lucky % 1e4) * 1e-2)  # Result: 0-99
```

#### Win Probability & Multiplier

* **Win condition**: `roll ≤ greed`
* **Win probability**: `(greed + 1) / 100`
* **Multiplier**: `99 / greed`

Examples:

* `greed=10`: 11% win chance, 9.9x multiplier
* `greed=20`: 21% win chance, 4.95x multiplier
* `greed=50`: 51% win chance, 1.98x multiplier

### Exploitation Strategy

#### Phase 1: State Recovery (624 games)

```python
from randcrack import RandCrack

# Play 624 games with minimum wager to collect server seeds
min_wager = 800 / 800  # $1 per game
collected_seeds = play_games(wager=1.0, games=624, greed=98)

# Clone the MT19937 state
rc = RandCrack()
for seed in collected_seeds:
    rc.submit(seed)

# Now we can predict all future seeds!
future_seeds = [rc.predict_getrandbits(32) for _ in range(5000)]
```

**Cost**: \~$624 in wagers, but we'll win some back with greed=98 (\~98% win rate)

#### Phase 2: Prediction Generation

```python
# Predict all future dice rolls
def predict_roll(server_seed, client_seed, nonce):
    nonce_client_msg = f"{client_seed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
    # ... (same logic as server)
    return roll

all_predictions = [
    predict_roll(future_seeds[i], "1337awesome", nonce+i) 
    for i in range(len(future_seeds))
]
```

#### Phase 3: Exploitation Loop

Find sequences where **ALL** games are guaranteed wins:

```python
def find_guaranteed_wins(start_nonce):
    # Try different greed levels (lower = higher profit)
    for greed in [10, 15, 20, 25, 30, 35, 40]:
        for length in range(3, 50):
            rolls = predictions[start_nonce:start_nonce+length]
            
            # Check if ALL rolls ≤ greed (guaranteed wins)
            if all(roll <= greed for roll in rolls):
                return {
                    "length": length,
                    "greed": greed,
                    "multiplier": 99/greed,
                    "rolls": rolls
                }
```

**Aggressive Betting Strategy**:

* Lower greed = higher multiplier = safer to bet more
* Bet 30-50% of balance per game when greed ≤ 30
* Compound winnings exponentially

Example sequence:

```
Nonce 624-633: [8, 12, 18, 9, 15, 20, 10, 14, 7, 19]
All ≤ 20, so use greed=20 (4.95x multiplier)
Bet $100/game → Win $495/game → Profit $395/game
Total profit: $3,950 from $1,000 wagered
```

### Running the Exploit

```bash
# Install dependencies
pip3 install pwntools randcrack

# Run the exploit
python3 solve.py
```

#### Exploit Flow

1. **Connect** to challenge server
2. **Collect** 624 server seeds (\~$100 balance remaining)
3. **Crack** MT19937 state using RandCrack
4. **Predict** future rolls for 5000+ games
5. **Find** guaranteed win sequences
6. **Bet aggressively** on those sequences
7. **Compound** winnings until $10,000+
8. **Buy flag**

#### Expected Output

```
[*] Connecting to challenge...
[*] Collecting 624 server seeds to crack Mersenne Twister...
[+] Collected 624 server seeds
[+] Current balance: $127.34

[*] Cracking Mersenne Twister state...
[+] Successfully cloned random state!

[*] Generating future server seed predictions...
[+] Generated 5624 total server seed predictions

[*] Starting exploitation...
[*] Bet 1 (nonce 624-631):
    Balance: $127.34
    Sequence: 8 games @ greed=20 (all rolls ≤ 20)
    Wager: $7.14/game → Profit: $224.73
[+] New balance: $352.07

[*] Bet 2 (nonce 632-640):
    Balance: $352.07
    Sequence: 9 games @ greed=15 (all rolls ≤ 15)
    Wager: $19.56/game → Profit: $940.44
[+] New balance: $1,292.51

... (continues compounding) ...

[+] SUCCESS! Balance: $10,247.83
[*] Buying flag...

[+] FLAG: flag{pr0v4bly_un41r_g4mbl1ng_ftw}
```

### Key Takeaways

#### Why This Vulnerability Exists

1. **Cryptographically Weak PRNG**: MT19937 is not cryptographically secure
2. **State Recovery**: 624 outputs fully determine future behavior
3. **Information Leak**: Server reveals the sensitive seed after each game
4. **Deterministic**: HMAC makes rolls predictable once seed is known

#### Proper Implementation

For a secure provably fair system:

```python
# Use cryptographically secure random
import secrets
server_seed = secrets.token_bytes(32)  # Not predictable!

# Don't reveal seeds until game series ends
# Or use commitment scheme (hash first, reveal later)
```

#### Real-World Impact

This vulnerability pattern appears in:

* **Gambling sites** using weak PRNGs
* **Blockchain games** with predictable randomness
* **CTF challenges** testing crypto knowledge
* **Any system** leaking MT19937 outputs

### Tools Used

* **pwntools**: Remote connection and interaction
* **randcrack**: MT19937 state recovery library
* **Python's random**: Understanding the vulnerable PRNG
* **hashlib/hmac**: Replicating dice roll calculation

### References

* [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
* [randcrack Library](https://github.com/tna0y/Python-random-module-cracker)
* [Provably Fair Gaming](https://en.bitcoin.it/wiki/Provably_Fair)
* [PRNG Attacks](https://www.schneier.com/blog/archives/2007/11/the_strange_sto.html)

***

**Flag**: Successfully captured after reaching $10,000+ balance through MT19937 state exploitation.
