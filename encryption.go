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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/argon2"
)

type Crypton struct {
}

var myCrypton = Crypton{}

type PasswordEncryptedValue struct {
	Salt       []byte
	IV         []byte
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
	cipherText := make([]byte, len(plainTextBytes))
	iv, err := encryptAES(aesKey, plainTextBytes, cipherText)
	if err != nil && err != io.EOF {
		log.Fatal(err)
		return nil, err
	}
	return &PasswordEncryptedValue{
		Salt:       salt,
		IV:         iv,
		CipherText: cipherText,
	}, nil
}

func (c *Crypton) DecryptWithPassword(password string, value *PasswordEncryptedValue) (plainTextBytes []byte, err error) {
	bPass := []byte(password)
	aesKey := argon2.Key(bPass, value.Salt, 2, 64, 1, 32)
	plainTextBytes = make([]byte, len(value.CipherText))
	err = decryptAES(aesKey, value.IV, value.CipherText, plainTextBytes)
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

func maxOrEnd(start int, max int, buffer []byte) (readCount int) {
	n := len(buffer) - start
	if max < n {
		readCount = max
	} else {
		readCount = n
	}
	return
}

// using the given key, take the plaintext and encrypt it into
// the cipherText buffer.
func encryptAES(key []byte, plainText []byte, cipherText []byte) (iv []byte, err error) {
	if len(cipherText) != len(plainText) {
		err = fmt.Errorf("The plainText and cipherText buffers are not the same length")
		return
	}
	plainTextReader := bytes.NewReader(plainText)
	encryptionStream, err := NewAESEncryptionStream(key, plainTextReader)
	if err != nil {
		return
	}
	consumed := 0
	max := 512
	toRead := maxOrEnd(consumed, max, cipherText)
	n, err := encryptionStream.Read(cipherText[consumed:toRead])
	for ; err == nil; n, err = encryptionStream.Read(cipherText[consumed:toRead]) {
		toRead = maxOrEnd(consumed, max, cipherText)
		consumed += n
	}
	iv = encryptionStream.IV
	if err == io.EOF {
		err = nil
	}
	return
}

type AESEncryptionStream struct {
	IV           []byte
	key          []byte
	plainText    io.Reader
	blockCipher  cipher.Block
	streamCipher cipher.Stream
}

func (stream *AESEncryptionStream) Read(chunk []byte) (n int, err error) {
	// Reads plaintext from the input stream into chunk
	n, err = stream.plainText.Read(chunk)
	if n > 0 {
		// Encrypts the bytes read into chunk
		stream.streamCipher.XORKeyStream(chunk[:n], chunk[:n])
	}
	return
}

func NewAESEncryptionStream(key []byte, plainTextReader io.Reader) (stream *AESEncryptionStream, err error) {
	// create cipher
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		return
	}

	iv := make([]byte, blockCipher.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	streamCipher := cipher.NewCTR(blockCipher, iv)

	stream = &AESEncryptionStream{
		IV:           iv,
		key:          key,
		plainText:    plainTextReader,
		blockCipher:  blockCipher,
		streamCipher: streamCipher,
	}
	return
}

func decryptAES(key []byte, iv []byte, cipherText []byte, plainText []byte) (err error) {
	if len(cipherText) != len(plainText) {
		err = fmt.Errorf("The plainText and cipherText buffers are not the same length")
		return
	}
	cipherTextReader := bytes.NewReader(cipherText)
	decryptionStream, err := NewAESDecryptionStream(key, iv, cipherTextReader)
	if err != nil {
		return
	}
	consumed := 0
	max := 512
	toRead := maxOrEnd(consumed, max, plainText)
	n, err := decryptionStream.Read(plainText[consumed:toRead])
	for ; err == nil; n, err = decryptionStream.Read(plainText[consumed:toRead]) {
		toRead = maxOrEnd(consumed, max, cipherText)
		consumed += n
	}
	if err == io.EOF {
		err = nil
	}
	return
}

type AESDecrptionStream struct {
	IV           []byte
	key          []byte
	cipherText   io.Reader
	blockCipher  cipher.Block
	streamCipher cipher.Stream
}

func (stream *AESDecrptionStream) Read(chunk []byte) (n int, err error) {
	// Reads ciphertext from stream into chunk
	n, err = stream.cipherText.Read(chunk)
	if n > 0 {
		// Does an in-place decryption on the ciphertext in chunk
		stream.streamCipher.XORKeyStream(chunk[:n], chunk[:n])
	}
	return
}

func NewAESDecryptionStream(key []byte, iv []byte, cipherTextReader io.Reader) (stream *AESDecrptionStream, err error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	streamCipher := cipher.NewCTR(blockCipher, iv)
	stream = &AESDecrptionStream{
		IV:           iv,
		key:          key,
		cipherText:   cipherTextReader,
		blockCipher:  blockCipher,
		streamCipher: streamCipher,
	}
	return
}
