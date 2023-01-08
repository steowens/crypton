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
	ecdsa "crypto/ecdsa"
	elliptic "crypto/elliptic"
	rand "crypto/rand"
	sha256 "crypto/sha256"
	x509 "crypto/x509"
	pem "encoding/pem"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

type KeyAgreementKey struct {
	privateKey *ecdsa.PrivateKey
	Unlocked   bool
	PrivateKey *PasswordEncryptedValue
	PublicKey  string
	SeqNum     int64
	ActiveFrom int64
	ActiveTo   int64
}

func NewKeyAgreementKey() (key *KeyAgreementKey, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error(err)
		return
	}
	pubKeyB, err := encodePubkey(&priv.PublicKey)
	if err != nil {
		log.Error(err)
		return
	}
	key = &KeyAgreementKey{
		privateKey: priv,
		Unlocked:   true,
		PrivateKey: nil,
		PublicKey:  string(pubKeyB),
		SeqNum:     time.Now().UnixMilli(),
		ActiveFrom: 0,
		ActiveTo:   0,
	}
	return
}

func (key *KeyAgreementKey) _computeSharedSecret(pub *ecdsa.PublicKey) (secret [32]byte, err error) {
	if !key.Unlocked {
		err = fmt.Errorf("key needs to be unlocked first")
		return
	}
	a, _ := pub.Curve.ScalarMult(pub.X, pub.Y, key.privateKey.D.Bytes())
	secret = sha256.Sum256(a.Bytes())
	return
}

func (key *KeyAgreementKey) Lock(password string) (locked *KeyAgreementKey, err error) {
	if key.privateKey == nil {
		err = fmt.Errorf("Key cannot be locked, missing privateKey field.")
		log.Error(err)
		return
	}
	encoded, err := encodePrivkey(key.privateKey)
	if err != nil {
		log.Error(err)
		return
	}
	pev, err := myCrypton.EncryptWithPassword(password, encoded)
	if err != nil {
		log.Error(err)
		return
	}
	locked = &KeyAgreementKey{
		privateKey: nil,
		Unlocked:   false,
		PrivateKey: pev,
		PublicKey:  key.PublicKey,
		SeqNum:     key.SeqNum,
		ActiveFrom: key.ActiveFrom,
		ActiveTo:   key.ActiveTo,
	}
	return
}

func (key *KeyAgreementKey) Unlock(password string) (unlocked *KeyAgreementKey, err error) {
	if key.PrivateKey == nil {
		err = fmt.Errorf("Key has no PrivateKey field, is it locked?")
		return
	}
	plainText, err := myCrypton.DecryptWithPassword(password, key.PrivateKey)
	if err != nil {
		log.Error(err)
		return
	}
	privateKey, err := decodePrivateKey(plainText)
	unlocked = &KeyAgreementKey{
		privateKey: privateKey,
		Unlocked:   true,
		PrivateKey: nil,
		PublicKey:  key.PublicKey,
		SeqNum:     key.SeqNum,
		ActiveFrom: key.ActiveFrom,
		ActiveTo:   key.ActiveTo,
	}
	return
}

func encodePubkey(publicKey *ecdsa.PublicKey) (encoded []byte, err error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Error(err)
		return
	}
	encoded = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return
}

func encodePrivkey(privateKey *ecdsa.PrivateKey) (encoded []byte, err error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Error(err)
		return
	}
	encoded = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return
}

func decodePrivateKey(pemEncoded []byte) (privateKey *ecdsa.PrivateKey, err error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	return
}

func decodePublicKey(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		log.Error(err)
		return
	}
	publicKey = genericPublicKey.(*ecdsa.PublicKey)
	return
}
