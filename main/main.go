package main

import (
	"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {

	account.Register("me@you.com", "golem", "What Color is the sky?", "What Color is the grass?", "What color is the moon?", "blue", "green", "white")
	account.Recover("me@you.com", "blowfish", "blue", "g2reen", "white")
	acc, err := account.LogOn("me@you.com", "blowfish")
	fmt.Println(acc.PrivKey, acc.PubKey, acc.RegistrationDate, err)

	/*
		key := account.NewSecretKey(18)
		fmt.Println(key)
		fmt.Println(account.SplitMeThreeTimes(key))
	*/
}
