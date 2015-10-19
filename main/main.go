package main

import (
	"flag"
	"fmt"
	"github.com/emicklei/go-restful"
	account "github.com/vijayee/Account"
	ipfs "github.com/vijayee/Account/IPFSService"
	"net/http"
	"os"
	"sync"
)

var host bool
var peerid string

func main() {
	flag.BoolVar(&host, "host", false, "host ipfs service")
	flag.StringVar(&peerid, "peerid", "", "peer id to connect to")
	flag.Parse()
	service, err := ipfs.NewService("/app/account", "~/.ipfs")
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

			wg.Done()
		}()
		go func() {
			for {
				if !service.IsListening() {
					continue
				}
				if !service.IsConnected() {
					continue
				}
				service.Broadcast([]byte("Looking for a deep connection"))
				break
			}
		}()
	}

	if peerid != "" {
		fmt.Printf("This Node Is Connecting to %s\n", peerid)
		service.Connect(peerid)
		wg.Add(1)
		go func() {
			for {
				if !service.IsListening() {
					continue
				}
				if !service.IsConnected() {
					continue
				}
				message := service.ReceiveAny()
				fmt.Printf("Received from Server: %s\n", message)
				break
			}
			wg.Done()
		}()
	}
	wg.Wait()

	wsContainer := restful.NewContainer()
	wsContainer.Add(account.NewAPI())

	cors := restful.CrossOriginResourceSharing{
		ExposeHeaders:  []string{"X-My-Header"},
		AllowedHeaders: []string{"Content-Type", "Accept"},
		CookiesAllowed: false,
		Container:      wsContainer}
	wsContainer.Filter(cors.Filter)

	wsContainer.Filter(wsContainer.OPTIONSFilter)
	fmt.Printf("start listening on localhost:8080\n")
	server := &http.Server{Addr: ":8080", Handler: wsContainer}
	server.ListenAndServe()
}
