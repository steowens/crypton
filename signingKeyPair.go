package crypton

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	gcrypt "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

type SigningKey struct {
	privateKey *ecdsa.PrivateKey
	locked     bool
	PrivateKey *PasswordEncryptedValue
}

func NewSigningKey(password string) (unlocked *SigningKey, err error) {
	privateKey, err := gcrypt.GenerateKey()
	if err != nil {
		log.Error(err)
		return
	}
	pkBytes := gcrypt.FromECDSA(privateKey)
	pev, err := myCrypton.EncryptWithPassword(password, pkBytes)
	if err != nil {
		log.Error(err)
		return
	}
	unlocked = &SigningKey{
		privateKey: privateKey,
		locked:     false,
		PrivateKey: pev,
	}
	return
}

func (sk *SigningKey) Unlock(password string) (unlocked *SigningKey, err error) {
	if sk.locked == true {
		plainTextBytes, e := myCrypton.DecryptWithPassword(password, sk.PrivateKey)
		if e != nil {
			log.Error(e)
			return nil, e
		}
		privateKey, e := gcrypt.ToECDSA(plainTextBytes)
		if e != nil {
			log.Error(e)
			return nil, e
		}
		return &SigningKey{
			privateKey: privateKey,
			locked:     false,
			PrivateKey: &PasswordEncryptedValue{
				Salt:       sk.PrivateKey.Salt,
				CipherText: sk.PrivateKey.CipherText,
			},
		}, nil
	} else {
		unlocked = &SigningKey{
			privateKey: sk.privateKey,
			locked:     false,
			PrivateKey: &PasswordEncryptedValue{
				Salt:       sk.PrivateKey.Salt,
				CipherText: sk.PrivateKey.CipherText,
			},
		}
	}
	return
}

func (sk *SigningKey) Sign(message []byte) (signature []byte, err error) {
	if sk.locked == true {
		err = fmt.Errorf("Signing key is still locked.")
		return
	}
	theHash := crypto.Keccak512(message)
	signature, err = crypto.Sign(theHash, sk.privateKey)
	return
}
