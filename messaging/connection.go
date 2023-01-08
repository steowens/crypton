package messaging

import (
	"encoding/hex"
	"fmt"

	"github.com/steowens/crypton"
)

type ConnectionDecision int64

const (
	Accepted ConnectionDecision = iota
	Rejected
	Blocked
)

type ConnectionState int64

const (
	PendingSharedSecret ConnectionState = iota
	Ready
)

type ConnectionRequest struct {
	ConnectTo crypton.PublicProfile
	Requester crypton.Registration
	Signature string
}

func (req *ConnectionRequest) Hashable() (hashable string) {
	hashable = fmt.Sprintf("ConnectionRequest[%s(%s)::%s]", req.Requester.Profile.Hashable(), req.Requester.Signature, req.ConnectTo.Hashable())
	return
}

func (req *ConnectionRequest) sign(key *crypton.SigningKey) (err error) {
	message := []byte(req.Hashable())
	signature, err := key.Sign(message)
	if err == nil {
		req.Signature = hex.EncodeToString(signature)
	}
	return
}

type ConnectionResponse struct {
	Request   ConnectionRequest
	Decision  ConnectionDecision
	Time      int64
	Signature string
}

func (resp *ConnectionResponse) Hashable() (hashable string) {
	hashable = fmt.Sprintf("ConnectionResponse[%s(%s)::%d::%d]", resp.Request.Hashable(), resp.Request.Signature, resp.Decision, resp.Time)
	return
}

type SignedConnectionResponse struct {
	Response  *ConnectionResponse
	Signature string
}

func (resp *ConnectionResponse) Sign(key *crypton.SigningKey) (err error) {
	message := []byte(resp.Hashable())
	signature, err := key.Sign(message)
	if err == nil {
		resp.Signature = hex.EncodeToString(signature)
	}
	return
}

type KeyAgreementRequest struct {
	RequesterKaKey string
	Requester      crypton.Registration
	Signature      string
}

func (kagReq *KeyAgreementRequest) Hashable() string {
	return fmt.Sprintf("KeyAgreementRequest[%s(%s)::%s]", kagReq.Requester.Profile.Hashable(), kagReq.Requester.Signature, kagReq.RequesterKaKey)
}

func (kagReq *KeyAgreementRequest) Sign(key *crypton.SigningKey) (err error) {
	message := []byte(kagReq.Hashable())
	signature, err := key.Sign(message)
	if err == nil {
		kagReq.Signature = hex.EncodeToString(signature)
	}
	return
}

type KeyAgreementResponse struct {
	Request        KeyAgreementRequest
	ResponderKaKey string
	Signature      string
}

func (kagResp *KeyAgreementResponse) Hashable() string {
	return fmt.Sprintf("KeyAgreementResponse[%s(%s)::%s]", kagResp.Request.Hashable(), kagResp.Request.Signature, kagResp.ResponderKaKey)
}

func (kagResp *KeyAgreementResponse) Sign(key *crypton.SigningKey) (err error) {
	message := []byte(kagResp.Hashable())
	signature, err := key.Sign(message)
	if err == nil {
		kagResp.Signature = hex.EncodeToString(signature)
	}
}

type Connection struct {
	State       ConnectionState
	WithParty   crypton.Registration
	KagResponse *KeyAgreementResponse
}
