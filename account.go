// Package implements https://www.csc.kth.se/~bgre/pub/KreitzBGRB12_PasswordsP2P.pdf
package account

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"github.com/ipfs/go-ipfs/p2p/crypto"
)

const (
	defaultKeyType       = crypto.RSA
	defaultKeySize       = 2048 //Defaulting to 2048 keys. Please don't crack me!!
	defaultSecretKeySize = 32
)

//Generate Public and a Private Key for a new User
func GenerateUserKeyPair() (crypto.PrivKey, crypto.PubKey, error) {
	return crypto.GenerateKeyPair(defaultKeyType, defaultKeySize)
}

//Generate a random secret byte array
func NewSecretKey(int size) []byte {
	key := make([]byte, size)

	_, err := rand.Read(key)
	if err != nil {
	}
	return key
}

//Encrypt data with HMAC
func EncryptHMAC(data []byte, key []byte) []byte {
	hm := hmac.New(sha256.New, key)
	hm.Write(data)
	return hm.Sum(nil)
}

//Scrypt a password
func EncryptPassword(pass []byte, salt []byte) []byte {
	ep, err := scrypt.Key(pass, salt, 16384, 8, 1, 32)
	if err != nil {
	}
	return ep
}
//Register a new account
func Register(uname string, pword){
	
}
