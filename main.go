package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"time"
)

func main() {
	var gen = flag.Bool("g", false, "Generate key pair.")
	var kfl = flag.String("k", "", "File containing the private key.")
	var pub = flag.String("p", "", "File containing the public key.")
	var fil = flag.String("f", "", "Read file.")
	
	var prk = flag.Bool("pr", false, "Print privare key.")
	var ppk = flag.Bool("pb", false, "Print public key.")
	var out = flag.Bool("o", false, "Output data.")
	
	var sgn = flag.Bool("s", false, "Sign file.")
	var enc = flag.String("e", "r", "Sign encoding `b`ase64|`h`ex|`r`aw.")
	var ver = flag.String("v", "", "File with signature.")

	var vnr = flag.Bool("vnr", false, "Venera signing.")

	var eml = flag.String("email", "", "Email for the signature.")
	var unm = flag.String("uname", "", "User name.")

	flag.Parse()
	
	var keyPair ecdsa.PrivateKey
	var publKey ecdsa.PublicKey
	var signBytes []byte
	if len(*kfl) > 0 {
		keyFile,err := ioutil.ReadFile(*kfl)
		if err != nil {
			fmt.Println(err.Error())
		}
		keyPair = *DecodePrivKey(keyFile)
		publKey = keyPair.PublicKey
	} else if len(*pub) > 0 {
		keyFile,err := ioutil.ReadFile(*pub)
		if err != nil {
			fmt.Println(err.Error())
		}
		publKey = *DecodePubKey(keyFile)
	} else if *gen {
		keyPair = GenKey()
		publKey = keyPair.PublicKey
	} else {
		fmt.Println("Key? Use `-h`")
	}

	if *out {
		if *prk  { // Print private key
			fmt.Print(string(EncodePrivKey(&keyPair)))
		}

		if *ppk { // Print public key
			fmt.Print(string(EncodePubKey(&publKey)))
		}
	}

	// Open file and sign/verify
	if len(*fil) > 0 {
		file, err := ioutil.ReadFile(*fil)
		if err != nil {
			fmt.Println(err.Error())
		}
		reader := bytes.NewReader(file)

		if *sgn {
			signBytes = Sign(reader, &keyPair)
		} else if len(*ver) > 0 {
			file, err := ioutil.ReadFile(*ver)
			if err != nil {
				fmt.Println(err.Error())
			}
			sign,err := base64.StdEncoding.DecodeString(string(file))
			if err != nil {
				fmt.Println(err.Error())
			}
			if *out {
				fmt.Print(Verify(reader, &publKey, sign))
			}
		}
	}

	// Show signin as base64 or hex
	if *out {
		if *enc == "b" {
			fmt.Print(base64.StdEncoding.EncodeToString(signBytes))
		} else if *enc == "h" {
			dst := make([]byte, hex.EncodedLen(len(signBytes)))
			hex.Encode(dst, signBytes)
			fmt.Printf("%s",dst)
		} else {
			fmt.Printf("%s",signBytes)
		}
	}

	// Venera sign
	if *vnr {
		t := time.Now() 
		b := VNRPack(
			*unm+" <"+*eml+">",
			t.Format("2006-01-02 15:04:05.000000"),
			base64.StdEncoding.EncodeToString(signBytes),
		)
		fmt.Print(string(b))
	}
}