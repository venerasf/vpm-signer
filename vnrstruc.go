package main

import (
	"encoding/json"
	"fmt"
)

type SignPack struct {
	Author string `json:"Author"`
	Date   string `json:"Date"`
	Sign   string `json:"Sign"`
}

func VNRPack(a string, d string, s string) []byte {
	p := SignPack{
		Author: a,
		Date: d,
		Sign: s,
	}
	b, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err.Error())
	}
	return b
}