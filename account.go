// Package implements https://www.csc.kth.se/~bgre/pub/KreitzBGRB12_PasswordsP2P.pdf
package account

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	proto "github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipfs/p2p/crypto"
	keypb "github.com/ipfs/go-ipfs/p2p/crypto/internal/pb"
	pb "github.com/vijayee/Account/pb"
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
func NewSecretKey(size int) []byte {
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

/*
//Register a new account
func Register(uname string, pword string) {
	priv, pub, err := generateUserKeyPair()
	if err != nil {
		return
	}
	privKeyPb, err2 := crypto.MarshalPrivateKey(priv)
	if err2 != nil {
		return
	}
}*/
//Encode into a protobuf
func MarshalAccount(priv crypto.PrivKey, pub crypto.PubKey, epTime int64) ([]byte, error) {
	acc := new(pb.Account) // make proto account
	acc.RegistrationDate = &epTime
	//Gather up Private key
	cPrivData := crypto.MarshalRsaPrivateKey(priv.(*crypto.RsaPrivateKey))
	cPrivK := new(keypb.PrivateKey)
	typ := keypb.KeyType_RSA
	cPrivK.Type = &typ
	cPrivK.Data = cPrivData
	acc.PrivKey = cPrivK // add proto private key
	//Gather up Public key
	cPubData, err2 := crypto.MarshalRsaPublicKey(pub.(*crypto.RsaPublicKey))
	if err2 != nil {
		return nil, err2
	}
	cPubK := new(keypb.PublicKey)
	cPubK.Type = &typ
	cPubK.Data = cPubData
	acc.PubKey = cPubK // add proto public key
	//Do the damn thing
	return proto.Marshal(acc) //Explosions
}
func UnMarshalAccount(data []byte) (crypto.PrivKey, crypto.PubKey, int64, error) {
	acc := new(pb.Account) // make proto account
	proto.Marshal(acc)     //Implosions
	err := proto.Unmarshal(data, acc)
	if err != nil {
		return nil, nil, 0, err
	}
	//Extract Private Key
	var cPrivK crypto.PrivKey
	var err2 error
	switch acc.PrivKey.GetType() {
	case keypb.KeyType_RSA:
		cPrivK, err2 = crypto.UnmarshalRsaPrivateKey(acc.PrivKey.GetData())
		if err2 != nil {
			return nil, nil, 0, err2
		}
	default:
		return nil, nil, 0, crypto.ErrBadKeyType
	}
	//Extract Public Key
	var cPubK crypto.PubKey
	var err3 error
	switch acc.PubKey.GetType() {
	case keypb.KeyType_RSA:
		cPubK, err3 = crypto.UnmarshalRsaPublicKey(acc.PubKey.GetData())
		if err3 != nil {
			return nil, nil, 0, err3
		}
	default:
		return nil, nil, 0, crypto.ErrBadKeyType
	}
	return cPrivK, cPubK, *acc.RegistrationDate, nil
}
