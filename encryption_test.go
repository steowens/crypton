package crypton

import (
	"testing"
)

func TestEncryptWithPassword(t *testing.T) {

	someSecret := "This is a secret! Whatever you do don't tell anyone OK?"
	password := "YouCantKnowThis"
	pwEncVal, err := myCrypton.EncryptWithPassword(password, []byte(someSecret))
	if err != nil {
		t.Fatalf("Encryption failed: %s", err.Error())
		return
	}
	ptBytes, err := myCrypton.DecryptWithPassword(password, pwEncVal)
	if err != nil {
		t.Fatalf("Decryption failed: %s", err.Error())
		return
	}
	decryptedSecret := string(ptBytes)
	if someSecret != decryptedSecret {
		t.Fatalf("Input secret '%s' does not match decrypted secret '%s'", someSecret, decryptedSecret)
	}
}
