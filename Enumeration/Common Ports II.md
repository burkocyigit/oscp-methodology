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