package crypton

import (
	"encoding/hex"
	"fmt"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type Identity struct {
	ID         string
	PublicName string
	Domain     string
	SigKey     SigningKey
}

type PublicProfile struct {
	ID         string
	PublicName string
	Domain     string
}

func (profile *PublicProfile) Hashable() (hashable string) {
	hashable = fmt.Sprintf("%s@%s:%s", profile.PublicName, profile.Domain, profile.ID)
	return
}

type Registration struct {
	Profile   PublicProfile
	Signature string
}

func NewIdentity(publicName string, domain string, url string, port int16, password string) (ident *Identity, err error) {
	signingKey, err := NewSigningKey(password)
	if err != nil {
		log.Error(err)
		return
	}
	uUid := uuid.NewV4()
	ident = &Identity{
		ID:         uUid.String(),
		PublicName: publicName,
		Domain:     domain,
		SigKey:     *signingKey,
	}
	return
}

func (identity *Identity) Unlock(password string) error {
	if identity.SigKey.locked == true {
		sigKey, err := identity.SigKey.Unlock(password)
		if err != nil {
			log.Error(err)
			return err
		}
		identity.SigKey.privateKey = sigKey.privateKey
	}
	return nil
}

func (identity *Identity) ToRegistration() (registration *Registration, err error) {
	profile := PublicProfile{
		ID:         identity.ID,
		PublicName: identity.PublicName,
		Domain:     identity.Domain,
	}
	hashable := profile.Hashable()
	signature, err := identity.SigKey.Sign([]byte(hashable))
	if err != nil {
		log.Error(err)
		return
	}
	registration = &Registration{
		Profile:   profile,
		Signature: hex.EncodeToString(signature),
	}
	return
}
