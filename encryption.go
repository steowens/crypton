package crypton

import (
	"crypto/aes"
	"crypto/rand"
	"log"
	"math/big"

	"golang.org/x/crypto/argon2"
)

type Crypton struct {
}

var myCrypton = Crypton{}

type PasswordEncryptedValue struct {
	Salt       []byte
	CipherText []byte
}

func (c *Crypton) EncryptWithPassword(password string, plainTextBytes []byte) (*PasswordEncryptedValue, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	bPass := []byte(password)
	aesKey := argon2.Key(bPass, salt, 2, 64, 1, 32)
	cipherText, err := encryptAES(aesKey, plainTextBytes)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return &PasswordEncryptedValue{
		Salt:       salt,
		CipherText: cipherText,
	}, nil
}

func (c *Crypton) DecryptWithPassword(password string, value *PasswordEncryptedValue) (plainTextBytes []byte, err error) {
	bPass := []byte(password)
	aesKey := argon2.Key(bPass, value.Salt, 2, 64, 1, 32)
	plainTextBytes, err = decryptAES(aesKey, value.CipherText)
	return nil, nil
}

func encryptAES(key []byte, plainTextBytes []byte) (cipherText []byte, err error) {
	// create cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		return
	}

	// allocate space for ciphered data
	cipherText = make([]byte, len(plainTextBytes))

	// encrypt
	c.Encrypt(cipherText, plainTextBytes)
	return
}

func decryptAES(key []byte, ciphertext []byte) (plainTextBytes []byte, err error) {
	ct := ciphertext

	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		return
	}

	plainTextBytes = make([]byte, len(ciphertext))
	cipher.Decrypt(plainTextBytes, ct)
	return
}

func (c *Crypton) GeneratePassword() (string, error) {
	alphabet := make([]byte, 0, 34)
	var ch byte
	for ch = 'A'; ch <= 'Z'; ch++ {
		alphabet = append(alphabet, ch)
	}
	for ch = '2'; ch <= '9'; ch++ {
		alphabet = append(alphabet, ch)
	}

	passwdCh := make([]byte, 25)
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			r, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				log.Fatal(err)
				return "", err
			}
			passwdCh = append(passwdCh, alphabet[r.Int64()])
		}
	}
	return string(passwdCh), nil
}

// Inserts ' ' in password every 5 characters for readability
func (c *Crypton) FormatPassword(password string) string {
	size := int(len(password) + len(password)/5)
	bResult := make([]byte, size)
	bPassword := []byte(password)
	for x := 0; x < len(bPassword); x++ {
		if x > 0 && x%5 == 0 {
			bResult = append(bResult, ' ')
		}
		bResult = append(bResult, bPassword[x])
	}
	return string(bResult)
}

// Strips ' ' chars from input string
func (c *Crypton) DeformatPassword(input string) string {
	bResult := make([]byte, len(input))
	bInput := []byte(input)
	for x := 0; x < len(bInput); x++ {
		if bInput[x] != ' ' {
			bResult = append(bResult, bInput[x])
		}
	}
	return string(bResult)
}
