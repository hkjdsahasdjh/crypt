package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"bytes"
	"encoding/gob"

	"github.com/atotto/clipboard"
	"github.com/seehuhn/password"
	"golang.org/x/crypto/nacl/secretbox"
)

func main() {
	flag.Parse()
	command := flag.Arg(0)
	filename := flag.Arg(1)
	if command == "en" {
		if err := encrypt(filename); err != nil {
			fmt.Println("Error:", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	if command == "de" {
		if err := decrypt(filename); err != nil {
			fmt.Println("Error:", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	if command == "cp" {
		if err := declip(filename); err != nil {
			fmt.Println("Error:", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	fmt.Println("usage: crypt [en|de|cp] [filename]")
}

func encrypt(filename string) error {
	encryptedFilename := filename + ".crypt"
	if _, err := os.Stat(encryptedFilename); os.IsExist(err) {
		return fmt.Errorf("Encrypted file already exists.")
	}
	pwd, err := password.Read("Encryption password...")
	if err != nil {
		return err
	}
	pwdCheck, err := password.Read("Repeat encryption password...")
	if err != nil {
		return err
	}
	if string(pwd) != string(pwdCheck) {
		return fmt.Errorf("Passwords don't match.")
	}
	key := sha(pwd)
	var nonce [24]byte
	rand.Reader.Read(nonce[:])

	plainBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var encryptedRawBytes []byte
	encryptedRawBytes = secretbox.Seal(encryptedRawBytes[:0], plainBytes, &nonce, &key)

	ef := &EncryptedFile{
		Data:  encryptedRawBytes,
		Nonce: nonce,
	}

	buf := new(bytes.Buffer)
	if gob.NewEncoder(buf).Encode(ef); err != nil {
		return err
	}
	encryptedFileBytes := buf.Bytes()

	if err := ioutil.WriteFile(encryptedFilename, encryptedFileBytes, 0644); err != nil {
		return err
	}
	return nil
}

func decryptToBytes(filename string) ([]byte, error) {
	if !strings.HasSuffix(filename, ".crypt") {
		return nil, fmt.Errorf("file musy have crypt extension.")
	}

	encryptedFileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(encryptedFileBytes) == 0 {
		return nil, fmt.Errorf("encrypted file is zero length.")
	}

	var ef EncryptedFile
	buf := bytes.NewBuffer(encryptedFileBytes)
	if err := gob.NewDecoder(buf).Decode(&ef); err != nil {
		return nil, err
	}
	if len(ef.Data) == 0 {
		return nil, fmt.Errorf("encrypted file has no contents.")
	}

	fmt.Println("Encryption password...")
	pwd, err := password.Read("")
	if err != nil {
		return nil, err
	}

	key := sha(pwd)
	var opened []byte
	opened, ok := secretbox.Open(opened, ef.Data, &ef.Nonce, &key)
	if !ok {
		return nil, fmt.Errorf("decryption failed.")
	}
	return opened, nil
}

func declip(filename string) error {

	opened, err := decryptToBytes(filename)
	if err != nil {
		return err
	}

	if err := clipboard.WriteAll(string(opened)); err != nil {
		return err
	}
	return nil
}

func decrypt(filename string) error {

	plainFilename := strings.TrimSuffix(filename, ".crypt")

	if _, err := os.Stat(plainFilename); !os.IsNotExist(err) {
		return fmt.Errorf("decrypted file %s already exists", plainFilename)
	}

	opened, err := decryptToBytes(filename)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(plainFilename, opened, 0644); err != nil {
		return err
	}

	return nil
}

func sha(b []byte) [32]byte {
	h := sha256.New()
	h.Write(b)
	slice := h.Sum(nil)
	var arr [32]byte
	copy(arr[:], slice[:])
	return arr
}

type EncryptedFile struct {
	Data  []byte
	Nonce [24]byte
}
