# ffuf with request file

- Burp -> Save request to a file
- Insert your FUZZ

```sh
ffuf -request request.txt -request-proto http -w wordlist.txt --ac
```