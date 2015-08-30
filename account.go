// Package implements https://www.csc.kth.se/~bgre/pub/KreitzBGRB12_PasswordsP2P.pdf
package account

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	//"encoding/base64"
	"encoding/hex"
	//"fmt"
	proto "github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipfs/p2p/crypto"
	keypb "github.com/ipfs/go-ipfs/p2p/crypto/internal/pb"
	multihash "github.com/jbenet/go-multihash"
	pb "github.com/vijayee/Account/pb"
	"io"
	"os"
	//"reflect"
	"time"
)

const (
	defaultKeyType       = crypto.RSA
	defaultKeySize       = 2048 //Defaulting to 2048 keys. Please don't crack me!!
	defaultSecretKeySize = 16
	defaultSaltSize      = 16
)

type Account struct {
	PubKey           crypto.PubKey
	PrivKey          crypto.PrivKey
	RegistrationDate int64
}

type Login struct {
	Salt             []byte
	LoginCredentials Credentials
	Question1        string
	Question2        string
	Question3        string
	QSalt1           []byte
	QSalt2           []byte
	QSalt3           []byte
	QKenc1           []byte
	QKenc2           []byte
	QKenc3           []byte
	QSenc1           []byte
	QSenc2           []byte
	QSenc3           []byte
}
type Credentials struct {
	Password   []byte
	File       []byte
	StorageKey []byte
}

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

//Encrypt data with AES
func EncryptAES(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	enc := make([]byte, aes.BlockSize+len(data))
	iv := enc[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(enc[aes.BlockSize:], []byte(data))
	return enc
}

//Decrypt data with AES
func DecryptAES(text []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	if len(text) < aes.BlockSize {
		return nil
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	return text
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
	var err error
	if len(data) > 120 {
		ch, err = multihash.EncodeName(data[0:120], "sha1")
		if err != nil {
			panic(err)
		}
	} else {
		ch, err = multihash.EncodeName(data, "sha1")
		if err != nil {
			panic(err)
		}
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
	defer file.Close()
	var data []byte
	data = make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return ""
	}
	return string(data)
}

//Change DHT value
func post(key string, value string) {
	filename := "login/" + key
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	}
	file, err := os.OpenFile(filename, os.O_RDWR, 0777)
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

// Change storage value
func write(hash string, data []byte) {
	filename := "login/" + hash
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		panic(err)
	}
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	_, err = file.Write([]byte(data))
	if err != nil {
		panic(err)
	}
	file.Sync()
}

//Register a new account
func Register(uname string, pword string, Q1 string, Q2 string, Q3 string,
	A1 string, A2 string, A3 string) {
	if stat, _ := os.Stat("login/" + uname); stat != nil {
		return
	}
	priv, pub, err := GenerateUserKeyPair()
	if err != nil {
		panic(err)
	}
	acc := *new(Account)
	acc.PrivKey = priv
	acc.PubKey = pub
	acc.RegistrationDate = time.Now().Unix()
	accpb, err := MarshalAccount(acc)
	if err != nil {
		panic(err)
	}

	kKs := NewSecretKey(defaultSecretKeySize)
	accEnc := EncryptAES(accpb, kKs)
	fKs := store(accEnc)
	salt := NewSecretKey(defaultSaltSize)
	kLi := EncryptPassword([]byte(pword), salt)
	Qs1, Qs2, Qs3 := splitMeThreeTimes(kLi)
	Qsalt1 := NewSecretKey(defaultSaltSize)
	Qsalt2 := NewSecretKey(defaultSaltSize)
	Qsalt3 := NewSecretKey(defaultSaltSize)
	QK1 := EncryptPassword([]byte(A1), Qsalt1)
	QK2 := EncryptPassword([]byte(A2), Qsalt2)
	QK3 := EncryptPassword([]byte(A3), Qsalt3)
	QKenc1 := EncryptAES([]byte(QK1), kLi)
	QKenc2 := EncryptAES([]byte(QK2), kLi)
	QKenc3 := EncryptAES([]byte(QK3), kLi)
	QSenc1 := EncryptAES([]byte(Qs1), QK1)
	QSenc2 := EncryptAES([]byte(Qs2), QK2)
	QSenc3 := EncryptAES([]byte(Qs3), QK3)
	Kw := NewSecretKey(defaultSecretKeySize)

	creds := *new(Credentials)

	creds.File = EncryptAES([]byte(fKs), kLi)
	creds.Password = EncryptAES(kKs, kLi)
	creds.StorageKey = EncryptAES(Kw, kLi)

	login := *new(Login)
	login.Salt = salt
	login.LoginCredentials = creds
	login.Question1 = Q1
	login.Question2 = Q2
	login.Question3 = Q3
	login.QSenc1 = QSenc1
	login.QSenc2 = QSenc2
	login.QSenc3 = QSenc3
	login.QSalt1 = Qsalt1
	login.QSalt2 = Qsalt2
	login.QSalt3 = Qsalt3
	login.QKenc1 = QKenc1
	login.QKenc2 = QKenc2
	login.QKenc3 = QKenc3

	FLi, err := MarshalLogin(login)
	/*
		log := UnMarshalLogin(FLi)
		fmt.Println(log.Salt)
	*/
	if err != nil {

	}
	fli := store(FLi)

	put(uname, fli)

}
func splitMeThreeTimes(data []byte) ([]byte, []byte, []byte) {
	pad := len(data) % 3
	step := len(data) / 3
	step1 := step
	step2 := (step * 2)
	step3 := (step * 3) + pad
	return data[0:step1], data[step1:step2], data[step2:step3]

}

//Login to an Account
func LogOn(uname string, pword string) (Account, error) {
	fli := get(uname)

	Fli := retrieve(fli)
	//fmt.Println(Fli)
	login := UnMarshalLogin(Fli)
	kLi := EncryptPassword([]byte(pword), login.Salt)
	fKs := DecryptAES(login.LoginCredentials.File, kLi)
	kKs := DecryptAES(login.LoginCredentials.Password, kLi)
	accEnc := retrieve(string(fKs))

	acc := DecryptAES(accEnc, kKs)

	account, err := UnMarshalAccount(acc)
	return account, err
}
func ChangePassword(uname string, oldpword string, newpword string) {
	oldfli := get(uname)
	oldFli := retrieve(oldfli)

	oldLogin := UnMarshalLogin(oldFli)

	newSalt := NewSecretKey(defaultSaltSize)
	newkLi := EncryptPassword([]byte(newpword), newSalt)
	newkKs := NewSecretKey(defaultSecretKeySize)
	newKW := NewSecretKey(defaultSecretKeySize)

	oldkLi := EncryptPassword([]byte(oldpword), oldLogin.Salt)
	oldFks := DecryptAES(oldLogin.LoginCredentials.File, oldkLi)
	oldkKs := DecryptAES(oldLogin.LoginCredentials.Password, oldkLi)

	accEnc := retrieve(string(oldFks))

	acc := DecryptAES(accEnc, oldkKs)
	accEnc = EncryptAES(acc, newkKs)

	newfKs := store(accEnc)

	newLogin := new(Login)

	newCreds := *new(Credentials)

	newCreds.File = EncryptAES([]byte(newfKs), newkLi)
	newCreds.Password = EncryptAES(newkKs, newkLi)
	newCreds.StorageKey = EncryptAES(newKW, newkLi)

	Qs1, Qs2, Qs3 := splitMeThreeTimes(newkLi)
	Qsalt1 := NewSecretKey(defaultSaltSize)
	Qsalt2 := NewSecretKey(defaultSaltSize)
	Qsalt3 := NewSecretKey(defaultSaltSize)
	QK1 := DecryptAES(oldLogin.QKenc1, oldkLi)
	QK2 := DecryptAES(oldLogin.QKenc2, oldkLi)
	QK3 := DecryptAES(oldLogin.QKenc3, oldkLi)
	QSenc1 := EncryptAES([]byte(Qs1), QK1)
	QSenc2 := EncryptAES([]byte(Qs2), QK2)
	QSenc3 := EncryptAES([]byte(Qs3), QK3)
	QKenc1 := EncryptAES([]byte(QK1), newkLi)
	QKenc2 := EncryptAES([]byte(QK2), newkLi)
	QKenc3 := EncryptAES([]byte(QK3), newkLi)

	newlogin := new(Login)
	newlogin.Salt = newSalt
	newlogin.LoginCredentials = newCreds
	newlogin.Question1 = oldLogin.Question1
	newlogin.Question2 = oldLogin.Question2
	newlogin.Question3 = oldLogin.Question3
	newlogin.QSenc1 = QSenc1
	newlogin.QSenc2 = QSenc2
	newlogin.QSenc3 = QSenc3
	newlogin.QSalt1 = Qsalt1
	newlogin.QSalt2 = Qsalt2
	newlogin.QSalt3 = Qsalt3
	newlogin.QKenc1 = QKenc1
	newlogin.QKenc2 = QKenc2
	newlogin.QKenc3 = QKenc3

	newFLi, err := MarshalLogin(*newLogin)
	if err != nil {
		panic(err)
	}
	newfli := store(newFLi)
	post(uname, newfli)

}
func UnMarshalLogin(data []byte) Login {
	loginpb := new(pb.Login)
	proto.Marshal(loginpb)
	err := proto.Unmarshal(data, loginpb)
	if err != nil {
		panic(err)
	}
	creds := *new(Credentials)

	//kLi := EncryptPassword([]byte(pword), loginpb.Salt)
	credspb := loginpb.LoginCredentials
	if err != nil {
		panic(err)
	}

	creds.File = credspb.File
	creds.Password = credspb.Password
	creds.StorageKey = credspb.StorageKey

	login := *new(Login)
	login.Salt = loginpb.Salt
	login.LoginCredentials = creds
	login.Question1 = *loginpb.Question1
	login.Question2 = *loginpb.Question2
	login.Question3 = *loginpb.Question3
	login.QSenc1 = loginpb.QSenc1
	login.QSenc2 = loginpb.QSenc2
	login.QSenc3 = loginpb.QSenc3
	login.QSalt1 = loginpb.QSalt1
	login.QSalt2 = loginpb.QSalt2
	login.QSalt3 = loginpb.QSalt3
	login.QKenc1 = loginpb.QKenc1
	login.QKenc2 = loginpb.QKenc2
	login.QKenc3 = loginpb.QKenc3
	return login

}
func MarshalLogin(login Login) ([]byte, error) {
	credspb := new(pb.Credentials)
	creds := login.LoginCredentials
	credspb.File = creds.File
	credspb.Password = creds.Password
	credspb.StorageKey = creds.StorageKey

	loginpb := new(pb.Login)
	loginpb.Salt = login.Salt
	loginpb.LoginCredentials = credspb
	loginpb.Question1 = &login.Question1
	loginpb.Question2 = &login.Question2
	loginpb.Question3 = &login.Question3
	loginpb.QSenc1 = login.QSenc1
	loginpb.QSenc2 = login.QSenc2
	loginpb.QSenc3 = login.QSenc3
	loginpb.QSalt1 = login.QSalt1
	loginpb.QSalt2 = login.QSalt2
	loginpb.QSalt3 = login.QSalt3
	loginpb.QKenc1 = login.QKenc1
	loginpb.QKenc2 = login.QKenc2
	loginpb.QKenc3 = login.QKenc3

	return proto.Marshal(loginpb)
}

//Encode into a protobuf
func MarshalAccount(acc Account) ([]byte, error) {
	accpb := new(pb.Account) // make proto account
	accpb.RegistrationDate = &acc.RegistrationDate
	//Gather up Private key3
	cPrivData := crypto.MarshalRsaPrivateKey(acc.PrivKey.(*crypto.RsaPrivateKey))
	cPrivK := new(keypb.PrivateKey)
	typ := keypb.KeyType_RSA
	cPrivK.Type = &typ
	cPrivK.Data = cPrivData
	accpb.PrivKey = cPrivK // add proto private key
	//Gather up Public key
	cPubData, err2 := crypto.MarshalRsaPublicKey(acc.PubKey.(*crypto.RsaPublicKey))
	if err2 != nil {
		return nil, err2
	}
	cPubK := new(keypb.PublicKey)
	cPubK.Type = &typ
	cPubK.Data = cPubData
	accpb.PubKey = cPubK // add proto public key
	//Do the damn thing
	return proto.Marshal(accpb) //Explosions
}
func UnMarshalAccount(data []byte) (Account, error) {
	accpb := new(pb.Account)            // make proto account
	err := proto.Unmarshal(data, accpb) //Implosions
	acc := new(Account)
	if err != nil {
		return *acc, err
	}
	//Extract Private Key
	var cPrivK crypto.PrivKey
	var err2 error
	switch accpb.PrivKey.GetType() {
	case keypb.KeyType_RSA:
		cPrivK, err = crypto.UnmarshalRsaPrivateKey(accpb.PrivKey.GetData())
		if err2 != nil {
			return *acc, err
		}
	default:
		return *acc, crypto.ErrBadKeyType
	}
	//Extract Public Key
	var cPubK crypto.PubKey
	var err3 error
	switch accpb.PubKey.GetType() {
	case keypb.KeyType_RSA:
		cPubK, err = crypto.UnmarshalRsaPublicKey(accpb.PubKey.GetData())
		if err3 != nil {
			return *acc, err
		}
	default:
		return *acc, crypto.ErrBadKeyType
	}
	acc.PrivKey = cPrivK
	acc.PubKey = cPubK
	acc.RegistrationDate = *accpb.RegistrationDate

	return *acc, nil
}
