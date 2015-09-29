package ipfsservice

import (
	"fmt"

	"code.google.com/p/go.net/context"
	core "github.com/ipfs/go-ipfs/core"
	corenet "github.com/ipfs/go-ipfs/core/corenet"
	peer "github.com/ipfs/go-ipfs/p2p/peer"
	fsrepo "github.com/ipfs/go-ipfs/repo/fsrepo"
)

var repo fsrepo.FSRepo
var nodeBuilder core.NodeBuilder
var node *core.IpfsNode
var cancel context.CancelFunc
var ctx context.Context

func InitiateNode() error {
	// Basic ipfsnode setup
	repo, err := fsrepo.Open("/data/ipfs")
	if err != nil {
		return err
	}

	nodeBuilder := core.NewNodeBuilder().Online()
	nodeBuilder.SetRepo(repo)

	ctx, cancel = context.WithCancel(context.Background())

	node, err = nodeBuilder.Build(ctx)
	if err != nil {
		return err
	}
	return nil
}

func Listen() error {
	list, err := corenet.Listen(node, "/app/account")
	if err != nil {
		return err
	}
	fmt.Printf("I am peer: %s\n", node.Identity.Pretty())
	defer cancel()
	for {
		con, err := list.Accept()
		if err != nil {
			return err
		}
		defer con.Close()
		fmt.Fprintln(con, "Hello! This is whyrusleepings awesome ipfs service")
		fmt.Printf("Connection from: %s\n", con.Conn().RemotePeer())
	}

}
func Connect(address string) {

	target, err := peer.IDB58Decode(address)
	if err != nil {
		fmt.Printf("IDB58 error: %s\n ", err)
		return
	}
	fmt.Printf("I am peer %s dialing %s\n", node.Identity.Pretty(), target.Pretty())

	_, err = corenet.Dial(node, target, "/app/whyrusleeping")
	if err != nil {
		fmt.Println(err)
		return
	}
}
