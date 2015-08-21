package main

import (
	"fmt"
	account "github.com/vijayee/Account"
	"time"
)

func main() {

	private, public, err4 := account.GenerateUserKeyPair()
	if err4 != nil {
		return
	}

	now := time.Now()
	unow := now.Unix()
	buf, err5 := account.MarshalAccount(private, public, unow)
	if err5 != nil {
		return
	}
	fmt.Println(buf)
	private, public, unow, err5 = account.UnMarshalAccount(buf)
	fmt.Println(private, public, unow, err5)
}
