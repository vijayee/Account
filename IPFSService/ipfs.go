package ipfsservice

import (
	"fmt"

	"code.google.com/p/go.net/context"
	core "github.com/ipfs/go-ipfs/core"
	corenet "github.com/ipfs/go-ipfs/core/corenet"
	net "github.com/ipfs/go-ipfs/p2p/net"
	peer "github.com/ipfs/go-ipfs/p2p/peer"
	fsrepo "github.com/ipfs/go-ipfs/repo/fsrepo"
	"sync"
)

/*
var nodeBuilder core.NodeBuilder
var node *core.IpfsNode
var cancel context.CancelFunc
var ctx context.Context
var connections map[string]net.Stream
*/

const (
	defaultBufSize = 4096
)

type Service struct {
	name        string
	node        *core.IpfsNode
	cancel      context.CancelFunc
	ctx         context.Context
	connections map[string]connection
	stop        chan bool
	isListening bool
}
type connection struct {
	conn   net.Stream
	mu     *sync.RWMutex
	output chan []byte
	input  chan []byte
	end    chan bool
}

// create a new Service
func NewService(name string, location string) (Service, error) {
	// Basic ipfsnode setup
	repo, err := fsrepo.Open(location)
	if err != nil {
		return Service{}, err
	}
	nodeBuilder := core.NewNodeBuilder().Online()
	nodeBuilder.SetRepo(repo)

	ctx, cancel := context.WithCancel(context.Background())

	node, err := nodeBuilder.Build(ctx)
	if err != nil {
		return Service{}, err
	}
	return Service{name, node, cancel, ctx, nil, make(chan bool), false}, nil
}
func (s *Service) Connected() bool {
	return s.connections != nil && len(s.connections) > 0
}

//Listen for connections from other peers
func (s *Service) Listen() error {
	list, err := corenet.Listen(s.node, s.name)
	if err != nil {
		return err
	}
	fmt.Printf("I am peer: %s\n", s.node.Identity.Pretty())
	defer s.cancel()

	//node.Routing.PutValue()
	// Loop of +1 listening
	s.isListening = true
	for {
		select {
		case <-s.stop:
			s.isListening = false
			return nil
		default:
			con, err := list.Accept()
			if err != nil {
				return err
			}
			if s.connections == nil {
				s.connections = make(map[string]connection)
			}
			key := con.Conn().RemotePeer().Pretty()
			s.connections[key] = connection{con, &sync.RWMutex{}, make(chan []byte), make(chan []byte), make(chan bool)}
			go s.handleCon(s.connections[key])
			defer func() {
				delete(s.connections, key)
				con.Close()
			}()
			//fmt.Fprintln(con, "Hello! This is whyrusleepings awesome ipfs service")
			//		con.Conn().NewStream().
			fmt.Printf("Connection from: %s\n", key)
		}

	}

}

//Connect to a peer at an address and add the connection
func (s *Service) Connect(address string) {

	target, err := peer.IDB58Decode(address)
	if err != nil {
		fmt.Printf("IDB58 error: %s\n ", err)
		return
	}
	fmt.Printf("I am peer %s dialing %s\n", s.node.Identity.Pretty(), target.Pretty())

	con, err := corenet.Dial(s.node, target, "/app/whyrusleeping")
	if err != nil {
		fmt.Println(err)
		return
	}
	if s.connections == nil {
		s.connections = make(map[string]connection)
	}
	key := con.Conn().RemotePeer().Pretty()
	s.connections[key] = connection{con, &sync.RWMutex{}, make(chan []byte), make(chan []byte), make(chan bool)}
	go s.handleCon(s.connections[key])
	defer func() {
		delete(s.connections, key)
		con.Close()
	}()
}
func (s *Service) handleCon(con connection) {
	stream := con.conn
	defer stream.Close()
	//Loop for reading from connection
	go func() {
		for {
			// read loop
			// ignores errors
			// ignores useless bytes
			// sends if someone cares
			buffer := make([]byte, defaultBufSize)
			l, err := stream.Read(buffer)
			switch {
			case err != nil:
				continue
			case l < 1:
				continue
			default:
				select {
				case con.output <- buffer[:l]:
					continue
				default:
					//clearly no one gives a shit
					continue
				}

			}

		}
	}()
	//loop for Writing to Connection
	go func() {
		for {
			//block
			buffer := <-con.input
			//and lock
			con.mu.Lock()
			l, err := stream.Write(buffer)
			con.mu.Unlock()
			switch {
			case err != nil:
				continue
			case l < 1:
				continue
			default:
				continue
			}
		}
	}()
	//Ends the connection when signal received
	if stop := <-con.end; stop == true {
		delete(s.connections, con.conn.Conn().RemotePeer().Pretty())
		return
	}

}

//Broadcast Message to all peers
func (s *Service) Broadcast(message []byte) {
	for _, con := range s.connections {
		con.input <- message
	}
}

//Close all connections
func (s *Service) CloseConnections() {
	for _, con := range s.connections {
		con.end <- true
	}
}

//Close a connection to a specific peer
func (s *Service) CloseConnection(peer string) {
	if s.IsConnectedTo(peer) {
		s.connections[peer].end <- true
	}
}

//Send message to a specific peer
func (s *Service) Send(peer string, message []byte) {
	if s.IsConnectedTo(peer) {
		s.connections[peer].input <- message
	}
}

//Receive Message from as specific peer
func (s *Service) Receive(peer string) []byte {
	if s.IsConnectedTo(peer) {
		return <-s.connections[peer].output
	}
	return nil
}

//Receive any message from any connected  Peer. This is a blocking method
func (s *Service) ReceiveAny() []byte {
	msg := make(chan []byte)
	for _, con := range s.connections {
		go func() {
			select {
			case msg <- <-con.output:
			}
		}()
	}
	return <-msg
}

//Is the service connected to anyone?
func (s *Service) IsConnectedTo(peer string) bool {
	_, ok := s.connections[peer]
	return ok
}

//Is the listner running
func (s *Service) IsListening() bool {
	return s.isListening
}

//Stops the listner
func (s *Service) StopListening() {
	select {
	case s.stop <- true:
	default:
		return
	}
}
