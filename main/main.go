package main

import (
	//	"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {

	account.Register("me@you.com", "golem")
	account.Login("me@you.com", "golem")
}
