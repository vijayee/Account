package main

import (
	"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {
	account.Register("me@you.com", "golem")
	priv1, pub1, reg1 := account.Login("me@you.com", "golem")
	account.ChangePassword("me@you.com", "golem", "blowfish")
	priv2, pub2, reg2 := account.Login("me@you.com", "blowfish")
	fmt.Printf("Pub1: %s, Priv: %s, Reg1: %s\nPub2: %s, Priv2: %s, Reg2: %s\n", priv1, pub1, reg1, priv2, pub2, reg2)

}
