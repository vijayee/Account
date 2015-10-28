// Package implements https://www.csc.kth.se/~bgre/pub/KreitzBGRB12_PasswordsP2P.pdf
package account

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	//"encoding/base64"
	"errors"
	"fmt"
	proto "github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipfs/p2p/crypto"
	keypb "github.com/ipfs/go-ipfs/p2p/crypto/internal/pb"
	pb "github.com/vijayee/Account/pb"
	"io"
	"os"
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

type DeviceLogin struct {
	DeviceFile []byte
	DeviceKey  []byte
}

type DeviceRecord struct {
	File     []byte
	Password []byte
}

func (a *Account) String() string {
	return fmt.Sprintf("Public Key: %s\nPrivate Key: %s\n Registration Date: %v", a.PubKey, a.PrivKey, a.RegistrationDate)
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

//Register a new account
func Register(uname string, pword string, Q1 string, Q2 string, Q3 string,
	A1 string, A2 string, A3 string) ([]byte, error) {

	if uname == "" || pword == "" || Q1 == "" || Q2 == "" || Q3 == "" ||
		A1 == "" || A2 == "" || A3 == "" {
		return nil, errors.New("Fields must no be blank.")
	}
	if stat, _ := os.Stat("login/" + uname); stat != nil {
		return nil, errors.New("Login is Already Registered")
	}
	priv, pub, err := GenerateUserKeyPair()
	if err != nil {
		return nil, err
	}
	acc := *new(Account)
	acc.PrivKey = priv
	acc.PubKey = pub
	acc.RegistrationDate = time.Now().Unix()
	accpb, err := MarshalAccount(acc)
	if err != nil {
		return nil, err
	}

	kKs := NewSecretKey(defaultSecretKeySize)
	accEnc := EncryptAES(accpb, kKs)
	fKs, err := accountstore.Store(accEnc)
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
	//Create a device file when host is sent

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
	if err != nil {
		return nil, err

	}
	deviceLogin := *new(DeviceLogin)
	deviceLogin.DeviceKey = NewSecretKey(defaultSecretKeySize)
	deviceRecord := *new(DeviceRecord)
	deviceRecord.Password = EncryptAES(kKs, deviceLogin.DeviceKey)
	deviceRecord.File = EncryptAES([]byte(fKs), deviceLogin.DeviceKey)

	fdl, err := MarshalDeviceRecord(deviceRecord)
	FDL, err := accountstore.Store(fdl)
	if err != nil {
		return nil, err
	}
	deviceLogin.DeviceFile = []byte(FDL)
	dvl, err := MarshalDeviceLogin(deviceLogin)
	if err != nil {
		return nil, err
	}
	fli, err := accountstore.Store(FLi)
	if err != nil {
		return nil, err

	}

	err = accountstore.Put(uname, fli)
	if err != nil {
		return nil, err
	}
	return dvl, nil
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
	if uname == "" || pword == "" {
		return *new(Account), errors.New("Fields must not be blank.")
	}
	fli, err := accountstore.Get(uname)
	if err != nil {
		return *new(Account), err

	}

	Fli, err := accountstore.Retrieve(fli)
	if err != nil {
		return *new(Account), err

	}
	login, err := UnMarshalLogin(Fli)
	if err != nil {
		return *new(Account), err

	}
	kLi := EncryptPassword([]byte(pword), login.Salt)
	fKs := DecryptAES(login.LoginCredentials.File, kLi)
	kKs := DecryptAES(login.LoginCredentials.Password, kLi)
	accEnc, err := accountstore.Retrieve(string(fKs))
	if err != nil {
		return *new(Account), err

	}

	acc := DecryptAES(accEnc, kKs)

	account, err := UnMarshalAccount(acc)
	if err != nil {
		return *new(Account), err

	}
	return account, err
}

//Login to an Account with a DeviceLogin
func DeviceLogOn(dvl []byte) (Account, error) {
	if dvl == nil || len(dvl) == 0 {
		return *new(Account), errors.New("Fields must not be blank.")
	}

	deviceLogin, err := UnMarshalDeviceLogin(dvl)
	if err != nil {
		return *new(Account), err

	}
	FDL, err := accountstore.Retrieve(string(deviceLogin.DeviceFile))
	if err != nil {
		return *new(Account), err

	}
	deviceRecord, err := UnMarshalDeviceRecord(FDL)
	if err != nil {
		return *new(Account), err

	}

	kKs := DecryptAES(deviceRecord.Password, deviceLogin.DeviceKey)
	fKs := DecryptAES(deviceRecord.File, deviceLogin.DeviceKey)

	accEnc, err := accountstore.Retrieve(string(fKs))
	if err != nil {
		return *new(Account), err

	}

	acc := DecryptAES(accEnc, kKs)

	account, err := UnMarshalAccount(acc)
	if err != nil {
		return *new(Account), err

	}
	return account, err
}
func ChangePassword(uname string, oldpword string, newpword string) ([]byte, error) {
	if uname == "" || oldpword == "" || newpword == "" {
		return nil, errors.New("Fields must not be blank.")
	}
	oldfli, err := accountstore.Get(uname)
	if err != nil {
		return nil, err

	}
	oldFli, err := accountstore.Retrieve(oldfli)
	if err != nil {
		return nil, err

	}
	oldLogin, err := UnMarshalLogin(oldFli)
	if err != nil {
		return nil, err

	}

	oldkLi := EncryptPassword([]byte(oldpword), oldLogin.Salt)
	oldFks := DecryptAES(oldLogin.LoginCredentials.File, oldkLi) //there is a joke somewhere in this variable but I didn't make it
	oldkKs := DecryptAES(oldLogin.LoginCredentials.Password, oldkLi)

	accEnc, err := accountstore.Retrieve(string(oldFks)) //joke gets funnier
	if err != nil {
		return nil, err

	}

	newSalt := NewSecretKey(defaultSaltSize)
	newkLi := EncryptPassword([]byte(newpword), newSalt)
	newkKs := NewSecretKey(defaultSecretKeySize)
	newKW := NewSecretKey(defaultSecretKeySize)

	acc := DecryptAES(accEnc, oldkKs)
	accEnc = EncryptAES(acc, newkKs)

	newfKs, err := accountstore.Store(accEnc)
	if err != nil {
		return nil, err

	}
	deviceLogin := *new(DeviceLogin)
	deviceLogin.DeviceKey = NewSecretKey(defaultSecretKeySize)
	deviceRecord := *new(DeviceRecord)
	deviceRecord.Password = EncryptAES(newkKs, deviceLogin.DeviceKey)
	deviceRecord.File = EncryptAES([]byte(newfKs), deviceLogin.DeviceKey)

	fdl, err := MarshalDeviceRecord(deviceRecord)
	FDL, err := accountstore.Store(fdl)
	if err != nil {
		return nil, err
	}
	deviceLogin.DeviceFile = []byte(FDL)
	dvl, err := MarshalDeviceLogin(deviceLogin)

	newCreds := new(Credentials)

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

	newlogin := *new(Login)
	newlogin.Salt = newSalt
	newlogin.LoginCredentials = *newCreds
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

	newFLi, err := MarshalLogin(newlogin)
	if err != nil {
		return nil, err
	}
	newfli, err := accountstore.Store(newFLi)
	if err != nil {
		return nil, err

	}
	accountstore.Post(uname, newfli)
	return dvl, nil
}
func ChangeQuestions(uname string, pword string, Q1 string, Q2 string, Q3 string,
	A1 string, A2 string, A3 string) error {
	if uname == "" || pword == "" || Q1 == "" || Q2 == "" || Q3 == "" ||
		A1 == "" || A2 == "" || A3 == "" {
		return errors.New("Fields must not be blank.")
	}
	oldfli, err := accountstore.Get(uname)
	if err != nil {
		return err
	}
	oldFli, err := accountstore.Retrieve(oldfli)
	oldLogin, err := UnMarshalLogin(oldFli)
	if err != nil {
		return err

	}

	oldkLi := EncryptPassword([]byte(pword), oldLogin.Salt)
	oldFks := DecryptAES(oldLogin.LoginCredentials.File, oldkLi) //there is a joke somewhere in this variable but I didn't make it
	oldkKs := DecryptAES(oldLogin.LoginCredentials.Password, oldkLi)
	oldKW := DecryptAES(oldLogin.LoginCredentials.StorageKey, oldkLi)

	accEnc, err := accountstore.Retrieve(string(oldFks)) //joke gets funnier
	if len(accEnc) < 1 {
		return errors.New("Invalid Password")
	}

	Qs1, Qs2, Qs3 := splitMeThreeTimes(oldkLi)
	Qsalt1 := NewSecretKey(defaultSaltSize)
	Qsalt2 := NewSecretKey(defaultSaltSize)
	Qsalt3 := NewSecretKey(defaultSaltSize)
	QK1 := EncryptPassword([]byte(A1), Qsalt1)
	QK2 := EncryptPassword([]byte(A2), Qsalt2)
	QK3 := EncryptPassword([]byte(A3), Qsalt3)
	QSenc1 := EncryptAES([]byte(Qs1), QK1)
	QSenc2 := EncryptAES([]byte(Qs2), QK2)
	QSenc3 := EncryptAES([]byte(Qs3), QK3)
	QKenc1 := EncryptAES([]byte(QK1), oldkLi)
	QKenc2 := EncryptAES([]byte(QK2), oldkLi)
	QKenc3 := EncryptAES([]byte(QK3), oldkLi)

	newCreds := *new(Credentials)
	newCreds.File = EncryptAES([]byte(oldFks), oldkLi)
	newCreds.Password = EncryptAES(oldkKs, oldkLi)
	newCreds.StorageKey = EncryptAES(oldKW, oldkLi)
	newlogin := *new(Login)
	newlogin.LoginCredentials = newCreds
	newlogin.Question1 = Q1
	newlogin.Question2 = Q2
	newlogin.Question3 = Q3
	newlogin.QSenc1 = QSenc1
	newlogin.QSenc2 = QSenc2
	newlogin.QSenc3 = QSenc3
	newlogin.QSalt1 = Qsalt1
	newlogin.QSalt2 = Qsalt2
	newlogin.QSalt3 = Qsalt3
	newlogin.QKenc1 = QKenc1
	newlogin.QKenc2 = QKenc2
	newlogin.QKenc3 = QKenc3

	newFLi, err := MarshalLogin(newlogin)
	if err != nil {
		return err
	}
	newfli, err := accountstore.Store(newFLi)
	if err != nil {
		return err

	}
	accountstore.Post(uname, newfli)
	return nil
}

func Recover(uname string, newpword string, A1 string, A2 string, A3 string) ([]byte, error) {
	if uname == "" || newpword == "" || A1 == "" || A2 == "" || A3 == "" {
		return nil, errors.New("Fields must not be blank.")
	}
	//Retrieve account information
	fli, err := accountstore.Get(uname)
	if err != nil {
		return nil, err

	}
	Fli, err := accountstore.Retrieve(fli)
	if err != nil {
		return nil, err

	}
	oldLogin, err := UnMarshalLogin(Fli)
	if err != nil {
		return nil, err

	}
	//form arms and legs...
	QK1 := EncryptPassword([]byte(A1), oldLogin.QSalt1)
	QK2 := EncryptPassword([]byte(A2), oldLogin.QSalt2)
	QK3 := EncryptPassword([]byte(A3), oldLogin.QSalt3)
	Qs1 := DecryptAES([]byte(oldLogin.QSenc1), QK1)
	Qs2 := DecryptAES([]byte(oldLogin.QSenc2), QK2)
	Qs3 := DecryptAES([]byte(oldLogin.QSenc3), QK3)
	//form head...which by voltron standards is also a body but hey who's counting
	var oldkLi []byte
	oldkLi = append(oldkLi, Qs1...)
	oldkLi = append(oldkLi, Qs2...)
	oldkLi = append(oldkLi, Qs3...)

	oldFks := DecryptAES(oldLogin.LoginCredentials.File, oldkLi) //there is a joke somewhere in this variable but I didn't make it
	oldkKs := DecryptAES(oldLogin.LoginCredentials.Password, oldkLi)

	accEnc, err := accountstore.Retrieve(string(oldFks)) //joke gets funnier
	if err != nil {
		return nil, err

	}
	if len(accEnc) < 1 {
		return nil, errors.New("Invalid Answers")
	}

	newSalt := NewSecretKey(defaultSaltSize)
	newkLi := EncryptPassword([]byte(newpword), newSalt)
	newkKs := NewSecretKey(defaultSecretKeySize)
	newKW := NewSecretKey(defaultSecretKeySize)

	acc := DecryptAES(accEnc, oldkKs)
	accEnc = EncryptAES(acc, newkKs)

	newfKs, err := accountstore.Store(accEnc)
	if err != nil {
		return nil, err
	}

	deviceLogin := *new(DeviceLogin)
	deviceLogin.DeviceKey = NewSecretKey(defaultSecretKeySize)
	deviceRecord := *new(DeviceRecord)
	deviceRecord.Password = EncryptAES(newkKs, deviceLogin.DeviceKey)
	deviceRecord.File = EncryptAES([]byte(newfKs), deviceLogin.DeviceKey)

	fdl, err := MarshalDeviceRecord(deviceRecord)
	FDL, err := accountstore.Store(fdl)
	if err != nil {
		return nil, err
	}

	deviceLogin.DeviceFile = []byte(FDL)
	dvl, err := MarshalDeviceLogin(deviceLogin)
	if err != nil {
		return nil, err
	}

	newCreds := new(Credentials)

	newCreds.File = EncryptAES([]byte(newfKs), newkLi)
	newCreds.Password = EncryptAES(newkKs, newkLi)
	newCreds.StorageKey = EncryptAES(newKW, newkLi)

	Qs1, Qs2, Qs3 = splitMeThreeTimes(newkLi)
	Qsalt1 := NewSecretKey(defaultSaltSize)
	Qsalt2 := NewSecretKey(defaultSaltSize)
	Qsalt3 := NewSecretKey(defaultSaltSize)
	QSenc1 := EncryptAES([]byte(Qs1), QK1)
	QSenc2 := EncryptAES([]byte(Qs2), QK2)
	QSenc3 := EncryptAES([]byte(Qs3), QK3)
	QKenc1 := EncryptAES([]byte(QK1), newkLi)
	QKenc2 := EncryptAES([]byte(QK2), newkLi)
	QKenc3 := EncryptAES([]byte(QK3), newkLi)

	newlogin := *new(Login)
	newlogin.Salt = newSalt
	newlogin.LoginCredentials = *newCreds
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

	newFLi, err := MarshalLogin(newlogin)
	if err != nil {
		return nil, err
	}
	newfli, err := accountstore.Store(newFLi)
	if err != nil {
		return nil, err

	}
	accountstore.Post(uname, newfli)
	return dvl, nil

}

func UnMarshalLogin(data []byte) (Login, error) {
	loginpb := new(pb.Login)
	err := proto.Unmarshal(data, loginpb)
	if err != nil {
		return *new(Login), err
	}
	creds := *new(Credentials)
	//kLi := EncryptPassword([]byte(pword), loginpb.Salt)
	credspb := loginpb.LoginCredentials

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
	return login, nil

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
func MarshalDeviceLogin(dl DeviceLogin) ([]byte, error) {
	dlpb := new(pb.DeviceLogin)
	dlpb.DeviceFile = dl.DeviceFile
	dlpb.DeviceKey = dl.DeviceKey
	return proto.Marshal(dlpb)
}
func UnMarshalDeviceLogin(data []byte) (DeviceLogin, error) {
	dl := new(DeviceLogin)
	dlpb := new(pb.DeviceLogin)
	proto.Unmarshal(data, dlpb)
	dl.DeviceFile = dlpb.DeviceFile
	dl.DeviceKey = dlpb.DeviceKey
	return *dl, nil
}
func MarshalDeviceRecord(dr DeviceRecord) ([]byte, error) {
	drpb := new(pb.DeviceRecord)
	drpb.File = dr.File
	drpb.Password = dr.Password
	return proto.Marshal(drpb)
}
func UnMarshalDeviceRecord(data []byte) (DeviceRecord, error) {
	dr := new(DeviceRecord)
	drpb := new(pb.DeviceRecord)
	proto.Unmarshal(data, drpb)
	dr.File = drpb.File
	dr.Password = drpb.Password
	return *dr, nil
}
