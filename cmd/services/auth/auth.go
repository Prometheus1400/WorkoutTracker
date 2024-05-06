package auth

import (
	"time"

	"example.com/m/v2/cmd/services/token"
	"github.com/golang-jwt/jwt"
)

type AuthManager interface {
	ParseToken(token string) (*jwt.Token, error)
	ParseTokenWithClaims(sToken string) (*jwt.Token, *token.Claims, error)
	NewAuthorizationToken(userId uint, isAdmin bool) (string, error)
	NewRefreshToken(userId uint, isAdmin bool) (string, error)
}

type DefaultAuthManager struct {
	SecretKey              string
	AuthorizationTokenLife time.Duration
	RefreshTokenLife       time.Duration
}

func NewDefaultAuthManager(secretKey string, authorizationTokenLife time.Duration, refreshTokenLife time.Duration) DefaultAuthManager {
	return DefaultAuthManager{
		SecretKey:              secretKey,
		AuthorizationTokenLife: authorizationTokenLife,
		RefreshTokenLife:       refreshTokenLife,
	}
}
func (a DefaultAuthManager) ParseToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.SecretKey), nil
	})
}
func (a DefaultAuthManager) ParseTokenWithClaims(sToken string) (*jwt.Token, *token.Claims, error) {
	claim := token.Claims{}
	tok, err := jwt.ParseWithClaims(sToken, &claim, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.SecretKey), nil
	})
	return tok, &claim, err
}
func (a DefaultAuthManager) NewAuthorizationToken(userId uint, isAdmin bool) (string, error) {
	return token.CreateToken(userId, isAdmin, token.Authorization, a.AuthorizationTokenLife, a.SecretKey)
}
func (a DefaultAuthManager) NewRefreshToken(userId uint, isAdmin bool) (string, error) {
	return token.CreateToken(userId, isAdmin, token.Refresh, a.RefreshTokenLife, a.SecretKey)
}
