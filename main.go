package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/gob"
	"fmt"
)

func main() {
	c := elliptic.P224()
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		fmt.Println("Error gennerating Private key")
	}
	fmt.Println(priv)
	priv509, err2 := x509.MarshalECPrivateKey(priv)
	if err2 != nil {
		fmt.Println("Failed to encode Private Key")
	}
	fmt.Println(priv509)
	fmt.Println(priv.PublicKey)
	buffer := bytes.NewBufferString(fmt.Sprint(priv.PublicKey))
	pubEncoder := gob.NewEncoder(buffer)
	pubEncoder.Encode(priv.PublicKey)
	fmt.Println(buffer)

}
