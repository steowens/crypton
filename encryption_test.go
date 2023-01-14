package crypton

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"testing"
)

func TestEncryptWithPassword(t *testing.T) {

	someSecret := "This is a secret! Whatever you do don't tell anyone OK?"
	password := "YouCantKnowThis"
	err := testSingleEncryptDecryptCycle([]byte(someSecret), password, t)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	for x := 0; x < 100; x++ {
		szByte, err := rand.Int(rand.Reader, big.NewInt(2048))
		if err != nil {
			t.Fatalf("Unable to generate random number: %s", err.Error())
		}
		randBytes := make([]byte, szByte.Int64())
		_, err = rand.Reader.Read(randBytes)
		if err != nil {
			t.Fatalf("Unable to read random bytes from random reader: %s", err.Error())
		}
		testSingleEncryptDecryptCycle(randBytes, password, t)
	}
}

func testSingleEncryptDecryptCycle(someSecret []byte, password string, t *testing.T) (err error) {
	pwEncVal, err := myCrypton.EncryptWithPassword(password, []byte(someSecret))
	if err != nil {
		err = fmt.Errorf("Encryption failed: %s", err.Error())
		return
	}
	decryptedSecret, err := myCrypton.DecryptWithPassword(password, pwEncVal)
	if err != nil {
		err = fmt.Errorf("Decryption failed: %s", err.Error())
		return
	}
	comp := bytes.Compare(someSecret, decryptedSecret)
	if comp != 0 {
		err = fmt.Errorf("Input secret '%s' does not match decrypted secret '%s'", hex.EncodeToString(someSecret), hex.EncodeToString(decryptedSecret))
	}
	return
}

func TestGeneratePassword(t *testing.T) {
	for quartets := 1; quartets < 10; quartets++ {
		password, err := myCrypton.GeneratePassword(quartets)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Generated password: %s", password)
		pattern := fmt.Sprintf("(([a-zA-Z2-9]{4,4})-){%d,%d}([a-zA-Z2-9]{4,4})", quartets-1, quartets-1)
		match, err := regexp.MatchString(pattern, password)
		if err != nil {
			t.Fatalf("Unable to match pattern: %s to %s due to error: %s", pattern, password, err.Error())
		}
		if !match {
			t.Fatalf("Unable to match pattern: %s to %s .", pattern, password)
		}
	}
}
