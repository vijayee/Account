package account

import (
	"encoding/hex"
	"errors"
	multihash "github.com/jbenet/go-multihash"
	"os"
)

type Storage interface {
	Store(data []byte) (string, error)
	Retrieve(hash string) ([]byte, error)
	Put(key string, value string) error
	Post(key string, value string) error
	Write(hash string, data []byte) error
	Get(key string) (string, error)
}
type localStorage struct{}

var accountstore Storage

func InitLocalStorage() {
	accountstore = new(localStorage)
}

func SetStorage(store Storage) {
	accountstore = store
}

func (l *localStorage) Store(data []byte) (string, error) {
	var ch []byte
	var err error
	if len(data) > 120 {
		ch, err = multihash.EncodeName(data[:120], "sha1")
		if err != nil {
			return "", err
		}
	} else {
		ch, err = multihash.EncodeName(data, "sha1")
		if err != nil {
			return "", err
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
			return "", err
		}
		defer file.Close()
		_, err = file.Write(data)
		if err != nil {
			return "", err
		}

		file.Sync()
		return can, nil
	} else {
		return "", errors.New("File Exists")
	}

	return "", nil
}
func (l *localStorage) Retrieve(hash string) ([]byte, error) {
	filename := "login/" + hash
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var data []byte
	data = make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (l *localStorage) Put(key string, value string) error {
	if _, err := os.Stat("login"); os.IsNotExist(err) {
		os.Mkdir("login", 0777)
	}
	filename := "login/" + key
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = file.Write([]byte(value))
		if err != nil {
			return err
		}
		file.Sync()
	}
	return nil
}
func (l *localStorage) Get(key string) (string, error) {
	filename := "login/" + key
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return "", err
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var data []byte
	data = make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

//Change DHT value
func (l *localStorage) Post(key string, value string) error {
	filename := "login/" + key
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(filename, os.O_RDWR, 0777)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write([]byte(value))
	if err != nil {
		return err
	}
	file.Sync()
	return nil
}

// Change storage value
func (l *localStorage) Write(hash string, data []byte) error {
	filename := "login/" + hash
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return err
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	_, err = file.Write([]byte(data))
	if err != nil {
		return err
	}
	file.Sync()
	return nil
}
