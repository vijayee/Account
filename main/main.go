package main

import (
	"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {

	err := account.Register("me@you.com", "golem", "What Color is the sky?", "What Color is the grass?", "What color is the moon?", "blue", "green", "white")
	if err != nil {
		fmt.Println(err)
	}
	err = account.ChangeQuestions("me@you.com", "golem", "What Color is the moon?", "What Color is the sky?", "What color is the grass?", "white", "blue", "green")
	if err != nil {
		fmt.Println(err)
	}
	err = account.Recover("me@you.com", "blowfish", "white", "blue", "green")
	if err != nil {
		fmt.Println(err)
	}
	acc, err := account.LogOn("me@you.com", "blowfish")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(acc.PrivKey, acc.PubKey, acc.RegistrationDate, err)

}
