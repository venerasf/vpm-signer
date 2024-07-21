package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

func EncodePrivKey(prKey *ecdsa.PrivateKey) []byte {
	encoded, _ := x509.MarshalECPrivateKey(prKey)
	pemBlock := &pem.Block{
		Type: "PRIVATE KEY",
		Bytes: encoded,
	}
	pem := pem.EncodeToMemory(pemBlock)
	return pem
}

func EncodePubKey(pubKey *ecdsa.PublicKey) []byte {
	encoded, _ := x509.MarshalPKIXPublicKey(pubKey)
	pemBlock := &pem.Block{
		Type: "PUBLIC KEY",
		Bytes: encoded,
	}
	pem := pem.EncodeToMemory(pemBlock)
	return pem
}

func DecodePrivKey(pemEncd []byte) *ecdsa.PrivateKey {
	blk, _ := pem.Decode(pemEncd)
	x509Encd := blk.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encd)
	if err != nil {
		println(err.Error())
	}
	return privateKey
}

func DecodePubKey(pemEncd []byte) *ecdsa.PublicKey {
	blk, _ := pem.Decode(pemEncd)
	x509Encd := blk.Bytes
	publicKey, err := x509.ParsePKIXPublicKey(x509Encd) // generic key
	if err != nil {
		println(err.Error())
	}
	return publicKey.(*ecdsa.PublicKey)
}

func GenKey() ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		println(err.Error())
	}
	return *key
}