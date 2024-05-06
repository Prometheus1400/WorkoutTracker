package encryption

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	Default = "default"	
	NoOp = "noop"
)

type Encryptor interface {
	Encrypt(s string) (string, error)
	CompareHashAndActual(hashed string, actual string) bool
}

// Default encryption
type DefaultEncryptor struct {
}

func NewDefaultEncryptor() DefaultEncryptor {
	return DefaultEncryptor{}
}
func (e DefaultEncryptor) Encrypt(s string) (string, error) {
	bArr, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	return string(bArr), err
}
func (e DefaultEncryptor) CompareHashAndActual(hashed string, actual string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(actual))
	return err == nil
}

// NoOp encryptor
type NoOpEncryptor struct {
}

func NewNoOpEncryptor() NoOpEncryptor {
	return NoOpEncryptor{}
}
func (e NoOpEncryptor) Encrypt(s string) (string, error) {
	return s, nil
}
func (e NoOpEncryptor) CompareHashAndActual(hashed string, actual string) bool {
	return hashed == actual
}

// factory method for getting right encyptor instance
func GetEncryptor(s string) (Encryptor, error) {
	switch(s) {
	case Default:
		return NewDefaultEncryptor(), nil
	case NoOp:
		return NewNoOpEncryptor(), nil
	default:
		return nil, fmt.Errorf("%s encyptor is not implemented", s)
	}
}