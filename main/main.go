package main

import (
	"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {

	account.Register("me@you.com", "golem", "What Color is the sky?", "What Color is the grass?", "What color is the moon?", "blue", "green", "white")
	acc, err := account.LogOn("me@you.com", "golem")
	fmt.Println(acc.PrivKey, acc.PubKey, acc.RegistrationDate, err)
	/*
		account.ChangePassword("me@you.com", "golem", "blowfish")
		priv2, pub2, reg2 := account.Login("me@you.com", "blowfish")
		fmt.Printf("Pub1: %s, Priv: %s, Reg1: %s\nPub2: %s, Priv2: %s, Reg2: %s\n", priv1, pub1, reg1, priv2, pub2, reg2)
	*/
	/*
		key := account.NewSecretKey(18)
		fmt.Println(key)
		fmt.Println(account.SplitMeThreeTimes(key))
	*/
}
