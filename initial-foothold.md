# Initial Foothold Methodology

A repeatable path from in-scope target to a stable low-privilege shell. Work from evidence, keep scans and outputs per target, and stop broad enumeration once a tested foothold is available. Use the PE runbook immediately after capturing the user flag.

## 0. Scope, notes, and workspace

Record the exam VPN interface/address, target IP, discovered names, time, and any credentials supplied by OffSec. Keep raw command output and a short rationale for each exploit attempt. Never scan outside the assigned scope.

```bash
export target=<target-ip>
export LHOST=<exam-vpn-ip>
mkdir -p ~/oscp/$target/{scans,web,loot,exploits}
nmap -Pn -n -p- --min-rate 3000 -oN ~/oscp/$target/scans/tcp-all.txt "$target"
nmap -Pn -n -sC -sV -p <open-ports> -oN ~/oscp/$target/scans/tcp-services.txt "$target"
sudo nmap -Pn -n -sU --top-ports 100 -oN ~/oscp/$target/scans/udp-top.txt "$target"
```

If a fast scan is incomplete or unstable, repeat more conservatively. Run version/default scripts on every open port and keep the exact output. Use the [Port Scanning](Enumeration/Port%20Scanning.md) checklist for scan variants and common ports references for service-specific scripts.

## 1. Orient and branch by service

| Observation | First actions and next branch |
|---|---|
| DNS/WHOIS/SMTP/POP3/IMAP | Attempt AXFR, enumerate SMTP users where allowed, validate known credentials on mail, retrieve mailbox contents after login. Mail often provides the next credential or host. See [Common Ports II](Enumeration/Common%20Ports%20II.md). |
| FTP (21) | Check version, anonymous read/write, and files/configs. If writable FTP maps to a web root, verify upload and execution; otherwise download and search loot. |
| SMB/RPC (139/445) | Test null/guest sessions, shares, users, descriptions, signing, and accessible files. Re-enumerate authenticated shares after every credential. See [SMB Enumeration](Enumeration/SMB%20Enumeration.md). |
| LDAP/Kerberos (389/636/88) | Identify domain/DC, test anonymous bind, collect usernames and descriptions, attempt only evidence-backed username validation/AS-REP checks. If domain creds arrive, hand off to [AD Set Methodology](ad-set.md). |
| Web (80/443/8080/8443) | Fingerprint technology and virtual hosts; crawl, fuzz directories/files/parameters, inspect source/JS/backups, test inputs, uploads, and version-specific CMS branches. See [Web Application Enumeration](Enumeration/Web%20Application.md), [Fuzzing](Web%20Application/Fuzzing.md), [SQL Injection](Web%20Application/SQL%20Injection.md), and [CMS](Web%20Application/CMS.md). |
| MySQL (3306), MSSQL (1433), PostgreSQL (5432+) | Test empty/default credentials only as a low-cost first check; enumerate roles/privileges and data. Choose RCE only when the required database privilege and write path are confirmed. See [Common Ports](Enumeration/Common%20Ports.md), [PostgreSQL](Enumeration/PostgreSQL.md), and the SQLi references. |
| NFS/RPCbind (111/2049) | Enumerate exports; mount readable exports to inspect SSH keys/configs. Confirm `no_root_squash` and write access before considering the root-owned file route. |
| SNMP (UDP/161) | Confirm UDP reachability, test common community strings, walk for users, routes, processes and command-line parameters; credential discoveries feed back into service validation. See [Common Ports II](Enumeration/Common%20Ports%20II.md). |
| SSH/WinRM/RDP | Use supplied or recovered credentials; distinguish authentication success from shell authorization. For RDP, check copy/drive redirection; for Windows, WinRM access is not implied by SMB access. |
| Unusual service/version | Identify exact product/build, search advisories/Exploit-DB, verify the vulnerable configuration and exact version before testing a matching exploit. |

Run `searchsploit <product> <version>` after identifying a credible version-specific lead. Inspect and understand a local PoC before use; avoid firing mismatched exploits or relying on a banner alone.

## 2. Web-to-shell workflow

1. Fingerprint with `whatweb`, headers, cookies, page source, `robots.txt`, sitemap, and likely framework/CMS version. Add discovered virtual hosts to the local name mapping and treat each as a separate web surface.
2. Run directory/file discovery with at least one recursive tool and one complementary fuzzing pass. Include backup/config extensions; note response-size baselines before filtering. Inspect `.git`, `.svn`, exposed archives, source maps, debug logs, and backup files locally.
3. Map every reachable input and test for SQL injection, LFI/RFI, command injection, SSTI, upload validation, authentication flaws, IDOR, XXE, SSRF, and insecure deserialization where the app behavior supports it. Save reproducible requests/responses.
4. For SQL injection, fingerprint the engine first. Consider MySQL `INTO OUTFILE`, MSSQL `xp_cmdshell`, or PostgreSQL `COPY FROM PROGRAM` only after confirming the necessary DB privileges and target paths. Stop if the required privilege is absent; switch to credential/file-read paths.
5. For a confirmed vulnerable CMS/plugin, match its exact version and configuration to a known issue. For authenticated admin access, inspect authorized theme/template/module or upload features for code execution. Do not brute force first when a low-noise file/config or version path is available.
6. For uploads, establish where the file lands and whether it executes; test one controlled request, then upgrade to a shell if it is needed for the next task. Keep payloads within exam rules.

A XAMPP fingerprint should trigger checks for phpMyAdmin/default DB access, `config.inc.php`, `my.ini`, Apache paths, `htdocs`, and `passwords.txt`. Confirm the MySQL account's `FILE` privilege and `secure_file_priv`, and verify whether Apache runs as SYSTEM/root. Detailed chain: [XAMPP](Web%20Application/XAMPP.md).

**Web decision:** confirmed command execution but only a web context? Capture the user flag if readable, then determine the executing identity and run the matching PE methodology. No code execution? Continue with evidence-driven credentials, vulnerable component, or another open service rather than repeatedly fuzzing the same surface.

## 3. Credentials and service access

Treat every discovered credential as a hypothesis to validate. Record its source, username/domain context, password/hash type, and each successful service/host. Check application configs, source-control history, shares, mail, database tables, shell histories, process arguments/environment, unattended install files, scheduled tasks, saved connections, and backup files.

- Test a single recovered credential on directly relevant services before building a password list.
- Use usernames derived from DNS, SMTP, SMB/RPC, LDAP, CMS, or app content; keep domain and local-account formats distinct.
- Check lockout policy before any spray. Prefer a small evidence-based candidate set and stop on lockout warnings or unexpected failures.
- Crack offline hashes using the identified hash format; retain the original hash and source.
- Recheck authenticated SMB shares, SYSVOL/NETLOGON, and app/database access whenever the credential set changes.

For Windows SMB/WinRM validation, `nxc smb <host> -u <user> -p '<password>'` and `nxc winrm <host> -u <user> -p '<password>'` test separate capabilities. If an account must change its password at first login, use the password-change route documented in [Password Attacks](Password%20Attacks/Password%20Attacks.md) and [Other AD Abuse](Active%20Directory/Other.md), then revalidate with the new password.

## 4. Obtain and stabilize a shell

Choose the shell method that fits the target OS and confirmed access. Start the listener before triggering a callback. Prefer a simple, one-shot command check (`whoami`, `id`) before relying on an interactive reverse shell. Transfer tools using an available, authorized path such as HTTP, SMB, or an RDP redirected drive; verify the file arrived intact. See [File Transfers](File%20Transfers/File%20Transfers.md).

Linux TTY upgrade when Python is available:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Suspend the shell, then restore the local terminal:
stty raw -echo; fg
stty rows $(tput lines) columns $(tput cols)
```

For Windows, prefer an authenticated WinRM/RDP session when permitted, otherwise obtain a stable PowerShell/cmd shell using a target-compatible transfer and callback. See [Linux Foothold](Initial%20Foothold/Linux%20Foothold.md), [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md), and [Exploiting](Initial%20Foothold/Exploiting.md) for shell and execution examples.

Impacket utilities should be invoked using the installed entry-point names, for example `impacket-psexec`, `impacket-wmiexec`, and `impacket-mssqlclient`.

## 5. Capture, escalate, and hand off

As soon as the shell is obtained, record `whoami`/`id`, hostname, OS/build, groups/privileges, interfaces, routes, and open local listeners. Locate and read the user flag immediately; record the exact target, path, and value in your evidence log.

- Linux foothold: continue with [Linux Privilege Escalation](linux-pe.md). Check `sudo -l` early, then credentials, SUID/capabilities, cron/services, writable paths, kernel only as a last resort, and internal-only services.
- Windows foothold: continue with [Windows Privilege Escalation](winfows-pe.md). Check `whoami /all`, high-value token privileges, services/tasks, credentials, and application-specific paths.
- AD member/DC foothold: also use [Active Directory Set Methodology](ad-set.md) for domain collection, multi-host credential reuse, and Ligolo-ng pivoting.

After successful PE, verify the elevated identity and immediately capture that machine's elevated flag (`proof.txt`, `root.txt`, or exam-specified path). Do not move on before recording it. Keep local root/SYSTEM separate from domain-admin status.

## Source notes

- [Port Scanning](Enumeration/Port%20Scanning.md)
- [Common Ports](Enumeration/Common%20Ports.md)
- [Common Ports II](Enumeration/Common%20Ports%20II.md)
- [PostgreSQL](Enumeration/PostgreSQL.md)
- [SMB Enumeration](Enumeration/SMB%20Enumeration.md)
- [Web Application Enumeration](Enumeration/Web%20Application.md)
- [Fuzzing](Web%20Application/Fuzzing.md)
- [SQL Injection](Web%20Application/SQL%20Injection.md)
- [CMS Methodology](Web%20Application/CMS.md)
- [XAMPP](Web%20Application/XAMPP.md)
- [File Transfers](File%20Transfers/File%20Transfers.md)
- [Exploiting](Initial%20Foothold/Exploiting.md)
- [Linux Foothold](Initial%20Foothold/Linux%20Foothold.md)
- [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md)
- [Password Attacks](Password%20Attacks/Password%20Attacks.md)
- [Linux Credential Hunting](Password%20Attacks/Credential%20Hunting%20on%20Linux.md)
- [AD Set Methodology](ad-set.md)
- [Code Block Template](templates/Code%20Block.md)
