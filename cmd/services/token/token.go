package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	Authorization = "authorization"
	Refresh       = "refresh"
)

type Claims struct {
	UserID  uint   `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	Exp     int64  `json:"exp"`  // Expiration time (unix timestamp)
	Type    string `json:"type"` // used to check access or refresh
}

func (c Claims) Valid() error {
	if until := time.Until(time.Unix(c.Exp, 0)); until <= 0 {
		return fmt.Errorf("jwt token expired")
	}
	return nil
}

func CreateToken(userId uint, isAdmin bool, tokenType string, life time.Duration, secretKey string) (string, error) {
	// Set claims
	claims := Claims{
		UserID: userId,
		IsAdmin: isAdmin,
		Exp:    time.Now().Add(life).Unix(),
		Type:   tokenType,
	}
	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the token with the secret key
	return token.SignedString([]byte(secretKey))
}
