// Code generated by protoc-gen-gogo.
// source: account.proto
// DO NOT EDIT!

/*
Package account is a generated protocol buffer package.

It is generated from these files:
	account.proto

It has these top-level messages:
	Transaction
	Account
*/
package account

import proto "github.com/gogo/protobuf/proto"
import math "math"
import crypto_pb "crypto_pb"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = math.Inf

type Transaction_TransactionStatus int32

const (
	Transaction_Negotiations Transaction_TransactionStatus = 0
	Transaction_Fulfilment   Transaction_TransactionStatus = 1
	Transaction_Completed    Transaction_TransactionStatus = 2
	Transaction_Canceled     Transaction_TransactionStatus = 3
)

var Transaction_TransactionStatus_name = map[int32]string{
	0: "Negotiations",
	1: "Fulfilment",
	2: "Completed",
	3: "Canceled",
}
var Transaction_TransactionStatus_value = map[string]int32{
	"Negotiations": 0,
	"Fulfilment":   1,
	"Completed":    2,
	"Canceled":     3,
}

func (x Transaction_TransactionStatus) Enum() *Transaction_TransactionStatus {
	p := new(Transaction_TransactionStatus)
	*p = x
	return p
}
func (x Transaction_TransactionStatus) String() string {
	return proto.EnumName(Transaction_TransactionStatus_name, int32(x))
}
func (x *Transaction_TransactionStatus) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(Transaction_TransactionStatus_value, data, "Transaction_TransactionStatus")
	if err != nil {
		return err
	}
	*x = Transaction_TransactionStatus(value)
	return nil
}

type Transaction_TransactionPrivacy int32

const (
	Transaction_Public  Transaction_TransactionPrivacy = 0
	Transaction_Private Transaction_TransactionPrivacy = 1
)

var Transaction_TransactionPrivacy_name = map[int32]string{
	0: "Public",
	1: "Private",
}
var Transaction_TransactionPrivacy_value = map[string]int32{
	"Public":  0,
	"Private": 1,
}

func (x Transaction_TransactionPrivacy) Enum() *Transaction_TransactionPrivacy {
	p := new(Transaction_TransactionPrivacy)
	*p = x
	return p
}
func (x Transaction_TransactionPrivacy) String() string {
	return proto.EnumName(Transaction_TransactionPrivacy_name, int32(x))
}
func (x *Transaction_TransactionPrivacy) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(Transaction_TransactionPrivacy_value, data, "Transaction_TransactionPrivacy")
	if err != nil {
		return err
	}
	*x = Transaction_TransactionPrivacy(value)
	return nil
}

// Account Transaction
type Transaction struct {
	// Creditor Identifier
	Creditor []byte `protobuf:"bytes,1,opt" json:"Creditor,omitempty"`
	// Debitor Identifier
	Debitor []byte `protobuf:"bytes,2,opt" json:"Debitor,omitempty"`
	// Transaction Status
	Status *uint64 `protobuf:"varint,3,req" json:"Status,omitempty"`
	// Privacy Setting
	Privacy *uint64  `protobuf:"varint,4,req" json:"Privacy,omitempty"`
	Amount  *float32 `protobuf:"fixed32,5,opt" json:"Amount,omitempty"`
	// multihash of the Products purchased
	Products [][]byte `protobuf:"bytes,6,rep" json:"Products,omitempty"`
	// Epoch Times of Transaction
	InitiationDate   *uint64 `protobuf:"varint,7,opt" json:"InitiationDate,omitempty"`
	CompletionDate   *uint64 `protobuf:"varint,8,opt" json:"CompletionDate,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Transaction) Reset()         { *m = Transaction{} }
func (m *Transaction) String() string { return proto.CompactTextString(m) }
func (*Transaction) ProtoMessage()    {}

func (m *Transaction) GetCreditor() []byte {
	if m != nil {
		return m.Creditor
	}
	return nil
}

func (m *Transaction) GetDebitor() []byte {
	if m != nil {
		return m.Debitor
	}
	return nil
}

func (m *Transaction) GetStatus() uint64 {
	if m != nil && m.Status != nil {
		return *m.Status
	}
	return 0
}

func (m *Transaction) GetPrivacy() uint64 {
	if m != nil && m.Privacy != nil {
		return *m.Privacy
	}
	return 0
}

func (m *Transaction) GetAmount() float32 {
	if m != nil && m.Amount != nil {
		return *m.Amount
	}
	return 0
}

func (m *Transaction) GetProducts() [][]byte {
	if m != nil {
		return m.Products
	}
	return nil
}

func (m *Transaction) GetInitiationDate() uint64 {
	if m != nil && m.InitiationDate != nil {
		return *m.InitiationDate
	}
	return 0
}

func (m *Transaction) GetCompletionDate() uint64 {
	if m != nil && m.CompletionDate != nil {
		return *m.CompletionDate
	}
	return 0
}

type Account struct {
	// Public Account Key
	PubKey *crypto_pb.PublicKey `protobuf:"bytes,1,opt" json:"PubKey,omitempty"`
	// Private Account ke
	Privkey *crypto_pb.PrivateKey `protobuf:"bytes,2,opt" json:"Privkey,omitempty"`
	// Epoch Times of Creation Date
	RegistrationDate *uint64 `protobuf:"varint,3,opt" json:"RegistrationDate,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Account) Reset()         { *m = Account{} }
func (m *Account) String() string { return proto.CompactTextString(m) }
func (*Account) ProtoMessage()    {}

func (m *Account) GetPubKey() *crypto_pb.PublicKey {
	if m != nil {
		return m.PubKey
	}
	return nil
}

func (m *Account) GetPrivkey() *crypto_pb.PrivateKey {
	if m != nil {
		return m.Privkey
	}
	return nil
}

func (m *Account) GetRegistrationDate() uint64 {
	if m != nil && m.RegistrationDate != nil {
		return *m.RegistrationDate
	}
	return 0
}

func init() {
	proto.RegisterEnum("account.Transaction_TransactionStatus", Transaction_TransactionStatus_name, Transaction_TransactionStatus_value)
	proto.RegisterEnum("account.Transaction_TransactionPrivacy", Transaction_TransactionPrivacy_name, Transaction_TransactionPrivacy_value)
}