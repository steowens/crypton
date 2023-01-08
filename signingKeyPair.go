/*
github.com/steowens/crypton - Core classes for crypton identity and message system.

Copyright (C) 2023 Stephen Owens

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package crypton

import (
	"crypto/ecdsa"
	"fmt"

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
	digest := gcrypt.Keccak256(message)
	signature, err = gcrypt.Sign(digest, sk.privateKey)
	return
}

func (sk *SigningKey) GetAddress() (address string, err error) {
	if sk.locked == true {
		err = fmt.Errorf("Signing key is locked")
		return
	}
	addr := gcrypt.PubkeyToAddress(sk.privateKey.PublicKey)
	address = addr.String()
	return
}

func GetPublicKeyFromSignature(hashable string, signature []byte) (pubKey *ecdsa.PublicKey, err error) {
	message := []byte(hashable)
	digest := gcrypt.Keccak256(message)
	pubKey, err = gcrypt.SigToPub(digest, signature)
	return
}

func GetAddressFromPublicKey(pubKey *ecdsa.PublicKey) string {
	addr := gcrypt.PubkeyToAddress(*pubKey)
	return addr.String()
}
