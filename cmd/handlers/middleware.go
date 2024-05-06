package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"example.com/m/v2/cmd/services/auth"
	"example.com/m/v2/cmd/services/token"
	"github.com/gin-gonic/gin"
)

func Authorize(authManager auth.AuthManager) gin.HandlerFunc {
	return flaggedAuthorize(authManager, token.Authorization)
}

func RefreshAuthorize(authManager auth.AuthManager) gin.HandlerFunc {
	return flaggedAuthorize(authManager, token.Refresh)
}

func flaggedAuthorize(authManager auth.AuthManager, tokenType string) gin.HandlerFunc {
	return func(context *gin.Context) {
		authHeader := context.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			context.JSON(http.StatusBadRequest, fmt.Errorf("missing or invalid format auth header"))
			return
		}
		authorizationToken := strings.TrimPrefix(authHeader, "Bearer ")

		tok, claims, err := authManager.ParseTokenWithClaims(authorizationToken)

		if err != nil || claims.Type != tokenType {
			context.JSON(http.StatusUnauthorized, fmt.Errorf("invalid or expired authorization token"))
			return
		}

		// validation passed can continue to the next method
		context.Set("token", tok)
		context.Set("claims", claims)
		context.Next()
	}
}