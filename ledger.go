package Account
import(
	multihash "github.com/jbenet/go-multihash"
	"time"
)
const (
	negotiations = iota
	fulfilment= iota
	completed= iota
	canceled= iota
)

const (
	public = iota
	private= iota
)

struct Transaction{	
    Creditor string
    Debtor string
    Status int
    Privacy int
    Amount float32
    Products []multihash 
	InitiationDate int64 
	CompletionDate int64  
}
TransactionNode{
	
}