package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"example.com/m/v2/cmd/handlers/requests"
	"example.com/m/v2/cmd/services/auth"
	"example.com/m/v2/cmd/services/database/models"
	"example.com/m/v2/cmd/services/encryption"
	"example.com/m/v2/cmd/services/token"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

func SignUp(db *gorm.DB, encryptor encryption.Encryptor) gin.HandlerFunc {
	return func(context *gin.Context) {
		var userInfo models.User
		if err := context.BindJSON(&userInfo); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if userInfo.Email == "" || userInfo.Username == "" || userInfo.Password == "" {
			context.JSON(http.StatusBadRequest, gin.H{"error": errors.New("missing essential information in the sign-up request")})
			return
		}

		hashedPassword, err := encryptor.Encrypt(userInfo.Password)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		userInfo.Password = hashedPassword

		res := db.Create(&userInfo)
		err = res.Error

		if err == gorm.ErrDuplicatedKey {
			context.JSON(http.StatusBadRequest, errors.New("account with that email address is already created"))
			return
		}
		if err != nil {
			context.JSON(http.StatusInternalServerError, err.Error())
			return
		}
	}
}

func Login(db *gorm.DB, encryptor encryption.Encryptor, authManager auth.AuthManager) gin.HandlerFunc {
	return func(context *gin.Context) {
		var loginUser models.User
		var savedUser models.User
		if err := context.BindJSON(&loginUser); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := db.First(&savedUser, "email = ?", loginUser.Email).Error
		if err == gorm.ErrRecordNotFound {
			context.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		loggedIn := encryptor.CompareHashAndActual(savedUser.Password, loginUser.Password)
		if loggedIn {
			aToken, err := authManager.NewAuthorizationToken(savedUser.ID, savedUser.IsAdmin)
			if err != nil {
				context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			rToken, err := authManager.NewRefreshToken(savedUser.ID, savedUser.IsAdmin)
			if err != nil {
				context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			context.JSON(http.StatusOK, gin.H{"authorization-token": aToken, "refresh-token": rToken})
			return
		} else {
			context.JSON(http.StatusUnauthorized, gin.H{"error": errors.New("incorrect username/password combo")})
			return
		}
	}
}

func Logout(db *gorm.DB, authManager auth.AuthManager) gin.HandlerFunc {
	return func(context *gin.Context) {
		var logoutRequest requests.LogoutRequest
		if err := context.BindJSON(&logoutRequest); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, claims := getTokenAndClaims(context)
		blacklistedToken := models.BlacklistToken{
			UserId: claims.UserID,
			Token:  logoutRequest.RefreshToken,
		}
		// only need to blacklist the refresh token
		res := db.Create(&blacklistedToken)
		if res.Error != nil {
			context.JSON(http.StatusInternalServerError, res.Error.Error())
			return
		}
		context.JSON(http.StatusOK, "user logged out")
	}
}

func RefreshToken(db *gorm.DB, authManager auth.AuthManager) gin.HandlerFunc {
	return func(context *gin.Context) {
		// blindly get token since it has passed the auth middleware
		tok, claims := getTokenAndClaims(context)

		// make sure refresh is not blacklisted
		var blacklistedToken models.BlacklistToken
		res := db.First(&blacklistedToken, "token = ?", tok.Raw)
		if res.Error == nil {
			context.JSON(http.StatusUnauthorized, fmt.Errorf("refresh token has been blacklisted"))
			return
		}

		authorizationToken, err := authManager.NewAuthorizationToken(claims.UserID, claims.IsAdmin)
		if err != nil {
			context.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		context.JSON(http.StatusOK, gin.H{"authorization-token": authorizationToken})
	}
}

func getTokenAndClaims(context *gin.Context) (*jwt.Token, *token.Claims) {
	tokObject, _ := context.Get("token")
	tok := tokObject.(*jwt.Token)
	claimsObject, _ := context.Get("claims")
	claims := claimsObject.(*token.Claims)

	return tok, claims
}
