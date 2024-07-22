Generate keys and output them on the screen.

```
main -g -pb -pr -o
```

Generate private key and output it into the file.

```
main -g -pr -o > bla.pem
```

Show key pair from file. This options allows getting the pub key congruent with given private key.

```
main -k key.pem -pr -pb -o
```

Show just public key

```
main -k key.pem -pb -o
```

Sign file and encode signatute as base64. show it

```
main -k key.pem -s -f go.mod -o -e b
```

Verify file

```
main -k key.pem -f testfile.txt -v testfile.sig -o
```

Generate venera sign pack.

```
main -k key.pem -s -f package.sgn -vnr
```

```
go run . -k ~/.venera_ecdsa.pem -f ../venera-repo/package.yaml -vnr -s -email "farinap5@protonmail.com" -uname "farinap5" > ../venera-repo/package.sgn
```