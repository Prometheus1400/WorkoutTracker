package routes

import (
	"example.com/m/v2/cmd/handlers"
	"example.com/m/v2/cmd/services/auth"
	"example.com/m/v2/cmd/services/encryption"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RegisterRoutes(router *gin.Engine, db *gorm.DB, encryptor encryption.Encryptor, authManager auth.AuthManager) {
	// app level related routes
	router.GET("/health", handlers.Health)

	// api level related routes
	// unprotected routes
	router.POST("/api/v1/sign-up", handlers.SignUp(db, encryptor))
	router.POST("/api/v1/login", handlers.Login(db, encryptor, authManager))
	// protected routes
	router.GET("/api/v1/logout", handlers.Authorize(authManager), handlers.Logout(db, authManager))
	router.GET("/api/v1/token/refresh", handlers.RefreshAuthorize(authManager), handlers.RefreshToken(db, authManager))
}
