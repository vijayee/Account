package account

import (
	random "github.com/Pallinder/go-randomdata"
	"os"
	"testing"
)

type user struct {
	username  string
	password  string
	question1 string
	question2 string
	question3 string
	answer1   string
	answer2   string
	answer3   string
}

var singleUser user
var device []byte

func TestMain(m *testing.M) {
	singleUser = *new(user)
	singleUser.username = random.Email()
	singleUser.password = random.Adjective() + random.Noun()
	singleUser.question1 = random.Adjective()
	singleUser.answer1 = random.Noun()
	singleUser.question2 = random.Adjective()
	singleUser.answer2 = random.Noun()
	singleUser.question3 = random.Adjective()
	singleUser.answer3 = random.Noun()
	InitLocalStorage()
	os.Exit(m.Run())

}
func TestRegistration(t *testing.T) {
	var err error
	device, err = Register(singleUser.username, singleUser.password, singleUser.question1,
		singleUser.question2, singleUser.question3, singleUser.answer1,
		singleUser.answer2, singleUser.answer3)
	if err != nil {
		t.Errorf("Registration Failed: %s\n", err)
	}
	if len(device) == 0 {
		t.Errorf("Device File Creation Failed: %s\n", err)
	}
	t.Logf("Device File: %s\n", device)

}

func TestLogon(t *testing.T) {
	account, err := LogOn(singleUser.username, singleUser.password)
	if err != nil {
		t.Errorf("Logon Failed: %s\n", err)
	}
	t.Logf("Logged into Account: %s\n", account)
}

func TestDeviceLogon(t *testing.T) {

	account, err := DeviceLogOn(device)

	if err != nil {
		t.Errorf("Device Logon Failed: %s\n", err)
	}
	t.Logf("Logged into Account: %s\n", account)
}

func TestChangePassword(t *testing.T) {
	var err error
	newPassword := random.Adjective() + random.Noun()
	device, err = ChangePassword(singleUser.username, singleUser.password, newPassword)
	singleUser.password = newPassword
	if err != nil {
		t.Errorf("Password Change Failed: %s\n", err)
	}
	if len(device) == 0 {
		t.Errorf("Device File Creation Failed: %s\n", err)
	}
	t.Logf("Device File: %s\n", device)
}

func TestChangeQuestions(t *testing.T) {
	singleUser.question1 = random.Adjective()
	singleUser.answer1 = random.Noun()
	singleUser.question2 = random.Adjective()
	singleUser.answer2 = random.Noun()
	singleUser.question3 = random.Adjective()
	singleUser.answer3 = random.Noun()
	err := ChangeQuestions(singleUser.username, singleUser.password, singleUser.question1,
		singleUser.question2, singleUser.question3, singleUser.answer1,
		singleUser.answer2, singleUser.answer3)
	if err != nil {
		t.Errorf("Question Change Failed: %s\n", err)
	}

}

func TestRecover(t *testing.T) {
	var err error
	newPassword := random.Adjective() + random.Noun()
	device, err = Recover(singleUser.username, newPassword, singleUser.answer1,
		singleUser.answer2, singleUser.answer3)
	if err != nil {
		t.Errorf("Recovery Failed: %s\n", err)
	}
	if len(device) == 0 {
		t.Errorf("Device File Creation Failed: %s\n", err)
	}
	t.Logf("Device File: %s\n", device)
	singleUser.password = newPassword
}
