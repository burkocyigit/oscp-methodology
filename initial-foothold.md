# Initial Foothold Methodology

Use this in priority order: identify the most likely service path, validate the smallest credible credential, establish a shell, immediately capture the user flag, then escalate and hand off.

## 1. Build the scope and targeted scan baseline

- [ ] Record the exam VPN interface, target IP, discovered names, time, and any supplied credentials.
- [ ] Keep all raw command output and a short rationale for each exploit attempt.
- [ ] Start with the [Port Scanning](Enumeration/Port%20Scanning.md) baseline and save the exact results before trying a service-specific abuse path.
- [ ] Re-run the scan more conservatively if the fast pass is incomplete or packet loss is high.

```bash
export target=<target-ip>
export LHOST=<exam-vpn-ip>
mkdir -p ~/oscp/$target/{scans,web,loot,exploits}
nmap -Pn -n -p- --min-rate 3000 -oN ~/oscp/$target/scans/tcp-all.txt "$target"
nmap -Pn -n -sC -sV -p <open-ports> -oN ~/oscp/$target/scans/tcp-services.txt "$target"
sudo nmap -Pn -n -sU --top-ports 100 -oN ~/oscp/$target/scans/udp-top.txt "$target"
```

- [ ] Use [Common Ports](Enumeration/Common%20Ports.md) and [Common Ports II](Enumeration/Common%20Ports%20II.md) for service-specific checks on the resulting ports.
- [ ] Treat each virtual host or discovered alias as a separate target surface when enumerating web or mail.

## 2. Prioritize the most likely service path

- [ ] Branch by the service that has the highest chance of immediate access: web, SMB/RPC, LDAP/Kerberos, SSH/WinRM/RDP, or a local database.
- [ ] For each service, follow the most relevant reference: [SMB Enumeration](Enumeration/SMB%20Enumeration.md), [Web Application Enumeration](Enumeration/Web%20Application.md), [SQL Injection](Web%20Application/SQL%20Injection.md), [CMS](Web%20Application/CMS.md), [XAMPP](Web%20Application/XAMPP.md), or [PostgreSQL](Enumeration/PostgreSQL.md).

| Observation | Next action |
|---|---|
| DNS/SMTP/POP3/IMAP | Check AXFR, mail users, and credential reuse in the mail layer. |
| FTP (21) | Check anonymous access, config files, and writable paths before assuming a web route. |
| SMB/RPC (139/445) | Enumerate shares, null sessions, and writable paths. |
| LDAP/Kerberos (389/636/88) | Identify the domain/DC and collect users and descriptions; hand off to [AD Set Methodology](ad-set.md) if valid credentials appear. |
| Web (80/443/8080/8443) | Fingerprint the app, crawl, fuzz, inspect source, and test the likely input or upload chain. |
| MySQL/MSSQL/PostgreSQL | Confirm roles and write paths before trying SQL-based execution. |
| NFS/RPCbind (111/2049) | Inspect readable or writable exports carefully before using an exported file path. |
| SNMP (UDP/161) | Confirm UDP reachability and walk for users, routes, and process information. |
| Unusual or custom service | Identify the exact version and confirm the exploit before attempting a service-specific chain. |

- [ ] Use `searchsploit <product> <version>` only after a credible, version-specific lead is identified.
- [ ] Inspect and understand a proof-of-concept locally before using it in the exam.

## 3. Run the web-to-shell workflow in order

- [ ] Fingerprint the app with headers, cookies, page source, `robots.txt`, sitemap, framework identifiers, and virtual-host names.
- [ ] Run one recursive discovery pass and one complementary fuzzing pass, including backup and config extensions.
- [ ] Check `.git`, `.svn`, archives, source maps, debug logs, and backup files for secrets or code paths.
- [ ] Map every input and test for SQLi, LFI/RFI, command injection, SSTI, upload validation, IDOR, XXE, SSRF, and insecure deserialization where the behavior supports it.
- [ ] For SQL injection, confirm the database engine and required privileges before trying `INTO OUTFILE`, `xp_cmdshell`, or `COPY FROM PROGRAM`.
- [ ] For CMS or plugin issues, match the exact version and configuration to the known vulnerability before attempting a chain.
- [ ] For upload-based paths, verify where the file lands and whether it executes.

```bash
# Example checks for web and file-oriented discovery
whatweb http://<target>
ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt
curl -I http://<target>/robots.txt
curl http://<target>/index.php
```

- [ ] If the app fingerprint matches XAMPP, inspect `config.inc.php`, `my.ini`, Apache config, `htdocs`, and `passwords.txt` and confirm the local DB account and privileges.
- [ ] If the app is not exploitable, stop broad fuzzing and move to credentialed or service-specific access instead of repeating the same route.

## 4. Validate credentials and service access

- [ ] Treat every recovered credential as a hypothesis and validate it in context.
- [ ] Record username, domain/local context, password or hash type, source, and each service or host it was used against.
- [ ] Check application configs, shell histories, `.env`, `.git`, cron, scheduled tasks, saved sessions, and backups for local credentials.
- [ ] Prioritize the smallest relevant credential check before building a large list.
- [ ] Validate Windows SMB and WinRM separately; SMB and WinRM auth are not equivalent.

```bash
nxc smb <host> -u <user> -p '<password>'
nxc winrm <host> -u <user> -p '<password>'
```

- [ ] If the account must change its password at first login, use the approved password-change route in [Password Attacks](Password%20Attacks/Password%20Attacks.md) and [Other AD Abuse](Active%20Directory/Other.md).
- [ ] Recheck SMB shares, SYSVOL/NETLOGON, and database access whenever the credential set changes.

## 5. Obtain and stabilize a shell

- [ ] Start the listener before triggering the callback.
- [ ] Prefer a one-shot check like `whoami`, `id`, or `hostname` before trusting an interactive shell.
- [ ] Use an approved transfer path such as HTTP, SMB, or redirected RDP drive and verify the file arrived as expected.
- [ ] Use [File Transfers](File%20Transfers/File%20Transfers.md) for the shell or helper transfer path.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg
stty rows $(tput lines) columns $(tput cols)
```

- [ ] For Windows, prefer a valid WinRM/RDP session when allowed; otherwise use the approved shell-creation path from [Windows Foothold](Initial%20Foothold/Windows%20Foothold.md).
- [ ] Invoke Impacket entry points by their installed names such as `impacket-psexec`, `impacket-wmiexec`, and `impacket-mssqlclient`.

## 6. Capture the user flag and escalate immediately

- [ ] Record `whoami`/`id`, hostname, OS/build, groups, privileges, interfaces, and listening ports immediately.
- [ ] Read the user flag at the exam-specified path and record the exact value in the evidence log.
- [ ] Use [Linux Privilege Escalation](linux-pe.md) for Linux shells and [Windows Privilege Escalation](winfows-pe.md) for Windows shells.
- [ ] For AD member or DC access, hand off to [AD Set Methodology](ad-set.md) after the user flag is captured.
- [ ] After successful PE, record the elevated identity and read the elevated flag (`proof.txt`, `root.txt`, or the exam-specified equivalent) before moving on.

- [ ] Keep local root or SYSTEM separate from domain-admin status and do not treat a shell as validated until proof is recorded.
