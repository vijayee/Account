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
	err := ipfs.InitiateNode()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var wg sync.WaitGroup
	if host {
		fmt.Println("This Node Is Hosting")
		wg.Add(1)
		go func() {
			err := ipfs.Listen()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			wg.Done()
		}()
	}

	if peerid != "" {
		fmt.Printf("This Node Is Connecting to %s\n", peerid)
		ipfs.Connect(peerid)
	}
	wg.Wait()
}
