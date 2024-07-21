package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func Sign(r io.Reader, pk *ecdsa.PrivateKey) []byte {
	h := sha256.New()
	_, err := io.Copy(h,r)
	if err != nil {
		fmt.Println(err.Error())
	}
	hash := h.Sum(nil)
	sign, err := ecdsa.SignASN1(rand.Reader, pk, hash)
	if err != nil {
		fmt.Println(err.Error())
	}
	return sign
}

func Verify(r io.Reader, pk *ecdsa.PublicKey, bsign []byte) bool {
	h := sha256.New()
	_, err := io.Copy(h, r)
	if err != nil {
		fmt.Println(err.Error())
	}
	hash := h.Sum(nil)
	return ecdsa.VerifyASN1(pk, hash, bsign)
}