package handlers_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"example.com/m/v2/cmd/handlers"
	"example.com/m/v2/cmd/services/auth"
	"example.com/m/v2/cmd/services/database"
	"example.com/m/v2/cmd/services/database/models"
	"example.com/m/v2/cmd/services/encryption"
	"example.com/m/v2/config"
	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestSignUp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	encryptor, _ := encryption.GetEncryptor(encryption.NoOp)
	defer os.Remove("test_db.db")

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/sign-up", strings.NewReader(`{"username" : "test","email" : "test@test.com","password" : "123"}`))

	handler := handlers.SignUp(db, encryptor)
	handler(c)

	var user models.User
	db.First(&user, "username = ?", "test")
	assert.Equal(t, "test@test.com", user.Email)
	assert.Equal(t, "123", user.Password)
}

func TestAlreadyInUseSignUp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	encryptor, _ := encryption.GetEncryptor(encryption.NoOp)
	defer os.Remove("test_db.db")

	testCases := []struct {
		method string
		path   string
		body   *strings.Reader // optional request body
		code   int             // expected response code
	}{
		{"POST", "/api/v1/sign-up", strings.NewReader(`{"username" : "test", "email" : "test@test.com", "password" : "123"}`), http.StatusOK},
		{"POST", "/api/v1/sign-up", strings.NewReader(`{"username" : "test", "email" : "test@test.com", "password" : "123"}`), http.StatusBadRequest},
	}

	handler := handlers.SignUp(db, encryptor)
	for i, tc := range testCases {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(tc.method, tc.path, tc.body)

		handler(c)

		switch i {
		case 0:
			assert.Equal(t, http.StatusOK, recorder.Code)
		case 1:
			assert.Equal(t, http.StatusBadRequest, recorder.Code)
		}
	}
}

func TestValidLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	encryptor, _ := encryption.GetEncryptor(encryption.Default)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	defer os.Remove("test_db.db")

	email := "test@test.com"
	password := "123"
	hashedPassword, _ := encryptor.Encrypt(password)

	userInfo := models.User{
		Email:    email,
		Password: hashedPassword,
		Username: "AwesomeUser",
	}

	db.Create(&userInfo)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(fmt.Sprintf(`{"email":"%s", "password":"%s"}`, email, password)))

	handler := handlers.Login(db, encryptor, authManager)
	handler(c)

	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestUnautherizedLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	encryptor, _ := encryption.GetEncryptor(encryption.Default)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	defer os.Remove("test_db.db")

	email := "test@test.com"
	password := "123"
	hashedPassword, _ := encryptor.Encrypt(password)

	userInfo := models.User{
		Email:    email,
		Password: hashedPassword,
		Username: "AwesomeUser",
	}

	db.Create(&userInfo)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(fmt.Sprintf(`{"email":"%s", "password":"%s"}`, email, "56456")))

	handler := handlers.Login(db, encryptor, authManager)
	handler(c)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestUserNotSignedUpLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	encryptor, _ := encryption.GetEncryptor(encryption.Default)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	defer os.Remove("test_db.db")

	email := "test@test.com"
	password := "123"

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(fmt.Sprintf(`{"email":"%s", "password":"%s"}`, email, password)))

	handler := handlers.Login(db, encryptor, authManager)
	handler(c)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestAuthorizationMiddlewareValid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)

	user := models.User{
		Model: gorm.Model{
			ID: 20,
		},
		Email: "TestAuthorizationMiddlewareValid@test.com",
	}

	authorizationToken, _ := authManager.NewAuthorizationToken(user.ID, user.IsAdmin)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/random-number", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authorizationToken))

	handler := handlers.Authorize(authManager)
	handler(c)

	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestAuthorizationMiddlewareInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)

	user := models.User{
		Model: gorm.Model{
			ID: 20,
		},
		Email: "TestAuthorizationMiddlewareInvalid@test.com",
	}

	authorizationToken, _ := authManager.NewAuthorizationToken(user.ID, user.IsAdmin)
	authorizationToken = authorizationToken + "random garbage"

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/random-number", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authorizationToken))

	handler := handlers.Authorize(authManager)
	handler(c)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAuthorizationMiddlewareInvalidHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/random-number", nil)
	c.Request.Header.Set("Authorization", "gdfgasd")

	handler := handlers.Authorize(authManager)
	handler(c)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestAuthorizationMiddlewareExpired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var config config.Config
	envconfig.Process("", &config)
	life := time.Second
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, life, config.Server.Jwt.RefreshTokenLife)

	user := models.User{
		Model: gorm.Model{
			ID: 20,
		},
		Email: "TestAuthorizationMiddlewareInvalid@test.com",
	}

	authorizationToken, _ := authManager.NewAuthorizationToken(user.ID, user.IsAdmin)
	time.Sleep(life * 2)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/random-number", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authorizationToken))

	handler := handlers.Authorize(authManager)
	handler(c)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestRefreshTokenValid(t *testing.T) {
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	defer os.Remove("test_db.db")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/token/refresh", handlers.RefreshAuthorize(authManager), handlers.RefreshToken(db, authManager))
	// put user info into the database
	user := models.User{
		Email:    "TestRefreshTokenValid@test.com",
		Password: "123",
	}
	db.Create(&user)

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/token/refresh", nil)
	refreshToken, _ := authManager.NewRefreshToken(user.ID, user.IsAdmin)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", refreshToken))

	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	type TestResponse struct {
		AuthorizationToken string `json:"authorization-token"`
	}
	resp := TestResponse{}
	json.Unmarshal(recorder.Body.Bytes(), &resp)
	assert.NotEmpty(t, resp.AuthorizationToken)
}

func TestRefreshTokenBlacklisted(t *testing.T) {
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	defer os.Remove("test_db.db")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/token/refresh", handlers.RefreshAuthorize(authManager), handlers.RefreshToken(db, authManager))
	// put user info into the database
	user := models.User{
		Email:    "TestRefreshTokenValid@test.com",
		Password: "123",
	}
	db.Create(&user)
	refreshToken, _ := authManager.NewRefreshToken(user.ID, user.IsAdmin)
	receivedToken, _ := authManager.ParseToken(refreshToken)
	blacklistedToken := models.BlacklistToken{
		UserId: user.ID,
		Token:  receivedToken.Raw,
	}
	db.Create(&blacklistedToken)

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/token/refresh", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", refreshToken))

	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestLoggingOutBlacklistsRefreshToken(t *testing.T) {
	var config config.Config
	envconfig.Process("", &config)
	authManager := auth.NewDefaultAuthManager(config.Server.Jwt.SecretKey, config.Server.Jwt.AuthorizationTokenLife, config.Server.Jwt.RefreshTokenLife)
	db, _ := database.NewGormDatabase("sqlite3", "test_db.db", false)
	defer os.Remove("test_db.db")

	userId := rand.Int()
	isAdmin := false
	aToken, _ := authManager.NewAuthorizationToken(uint(userId), isAdmin)
	rToken, _ := authManager.NewRefreshToken(uint(userId), isAdmin)

	recorder := httptest.NewRecorder()
	endpoint := "/api/v1/logout"
	request := httptest.NewRequest(http.MethodGet, endpoint, strings.NewReader(fmt.Sprintf(`{"refresh_token":"%s"}`, rToken)))
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", aToken))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(endpoint, handlers.Authorize(authManager), handlers.Logout(db, authManager))
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var blacklistedToken models.BlacklistToken
	res := db.Where("token = ?", rToken).Find(&blacklistedToken)
	assert.Nil(t, res.Error)
	assert.NotEmpty(t, blacklistedToken.Token)
}
