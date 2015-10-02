package main

import (
	"fmt"
	//account "github.com/vijayee/Account"
	"flag"
	ipfs "github.com/vijayee/Account/IPFSService"
	"os"
	"sync"
)

var host bool
var peerid string

func main() {
	flag.BoolVar(&host, "host", false, "host ipfs service")
	flag.StringVar(&peerid, "peerid", "", "peer id to connect to")
	flag.Parse()
	service, err := ipfs.NewService("/app/account", "/data/ipfs")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var wg sync.WaitGroup

	if host {
		fmt.Println("This Node Is Hosting")
		wg.Add(1)
		go func() {
			err := service.Listen()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			go func() {

			}()
			wg.Done()
		}()
	}

	if peerid != "" {
		fmt.Printf("This Node Is Connecting to %s\n", peerid)
		service.Connect(peerid)
	}
	wg.Wait()
}
