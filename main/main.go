package main

import (
	//"fmt"
	account "github.com/vijayee/Account"
	//"time"
)

func main() {
	account.Register("me@you.com", "golem")
	account.Login("me@you.com", "golem")
	/*
		key := []byte("1234567812345678")
		bite := []byte("encrypt me again#@$#$@!@#$EFDGFDSGVFDGBSFDHBFGHSFHFDSGFGERWST RETSRGT#E@$#@$ EDFSDFE$@#%#@ T%RW$RGTEFDRGBSHY$%#^$%YHFGNJFDH ")
		encrypted := account.EncryptAES(bite, key)
		decrypted := account.DecryptAES(encrypted, key)
		fmt.Println(string(bite))
		fmt.Println(string(decrypted))
		fmt.Println(string(bite) == string(decrypted))
	*/

}
