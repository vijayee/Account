// Package implements https://www.csc.kth.se/~bgre/pub/KreitzBGRB12_PasswordsP2P.pdf
package account

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	proto "github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipfs/p2p/crypto"
	keypb "github.com/ipfs/go-ipfs/p2p/crypto/internal/pb"
	multihash "github.com/jbenet/go-multihash"
	pb "github.com/vijayee/Account/pb"
	"os"
	"time"
)

const (
	defaultKeyType       = crypto.RSA
	defaultKeySize       = 2048 //Defaulting to 2048 keys. Please don't crack me!!
	defaultSecretKeySize = 16
	defaultSaltSize      = 16
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
func EncryptAES(data []byte, key []byte) []byte {
	ciph, err := aes.NewCipher(key)
	if err != nil {
	}
	var enc = make([]byte, aes.BlockSize)
	ciph.Encrypt(enc, data)
	return enc
}

//Scrypt a password
func EncryptPassword(pass []byte, salt []byte) []byte {
	ep, err := scrypt.Key(pass, salt, 16384, 8, 1, 32)
	if err != nil {
	}
	return ep
}
func store(data []byte) string {
	var ch []byte
	ch, err := multihash.EncodeName(data, "sha1")
	if err != nil {
		panic(err)
	}
	can := hex.EncodeToString(ch)
	if _, err := os.Stat("login"); os.IsNotExist(err) {
		os.Mkdir("login", 0777)
	}
	filename := "login/" + can
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		file, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		_, err = file.Write(data)
		if err != nil {
			panic(err)
		}

		file.Sync()
		return can
	}

	return ""
}
func retrieve(hash string) []byte {
	filename := "login/" + hash
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil
	}
	file, err := os.Open(filename)
	if err != nil {
	}
	var data []byte
	data = make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return nil
	}
	return data
}
func put(key string, value string) {
	if _, err := os.Stat("login"); os.IsNotExist(err) {
		os.Mkdir("login", 0777)
	}
	filename := "login/" + key
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		file, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		_, err = file.Write([]byte(value))
		if err != nil {
			panic(err)
		}
		file.Sync()
	}
}
func get(key string) string {
	filename := "login/" + key
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return ""
	}
	file, err := os.Open(filename)
	if err != nil {

	}
	var data []byte
	data = make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return ""
	}
	return string(data)
}

//Register a new account
func Register(uname string, pword string) {
	if stat, _ := os.Stat("login/" + uname); stat != nil {
		return
	}
	priv, pub, err := GenerateUserKeyPair()
	if err != nil {
		return
	}
	acc, err2 := MarshalAccount(priv, pub, time.Now().Unix())
	if err2 != nil {
		return
	}

	kKs := NewSecretKey(defaultSecretKeySize)
	accEnc := EncryptAES(acc, kKs)
	fKs := store(accEnc)
	salt := NewSecretKey(defaultSaltSize)
	kLi := EncryptPassword([]byte(pword), salt)
	Kw := NewSecretKey(defaultSecretKeySize)
	FLi, err := MarshalLogin(salt, fKs, kKs, Kw, kLi)
	if err != nil {

	}
	fli := store(FLi)
	put(uname, fli)

}

func Login(uname string, pword string) {
	fli := get(uname)
	fmt.Println(fli)
}
func MarshalLogin(salt []byte, fKs string, kKs []byte, Kw []byte, kLi []byte) ([]byte, error) {
	creds := new(pb.Credentials)
	creds.File = &fKs
	creds.StorageKey = Kw
	creds.Password = kKs
	credentials, err := proto.Marshal(creds)
	if err != nil {

	}
	crypCreds := EncryptAES(credentials, kLi)
	login := new(pb.Login)
	login.Salt = salt
	login.Credentials = crypCreds
	return proto.Marshal(login)
}

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
