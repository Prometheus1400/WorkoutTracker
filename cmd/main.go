package main

import (
	"fmt"
	"strings"

	"example.com/m/v2/cmd/routes"
	"example.com/m/v2/cmd/services/auth"
	"example.com/m/v2/cmd/services/database"
	"example.com/m/v2/cmd/services/encryption"
	"example.com/m/v2/config"
	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
)

func main() {
	// get configs
	var conf config.Config
	err := envconfig.Process("", &conf)
	if err != nil {
		panic(err)
	}
	conf.ApplyOverrides()

	// get database connection
	db, err := database.NewGormDatabase(conf.Database.Driver, conf.Database.ConnectionString, conf.Database.Log)
	if err != nil {
		panic(err)
	}

	// setup encryptor used for passwords
	encryptor, err := encryption.GetEncryptor(conf.Server.Encryptor)
	if err != nil {
		panic(err)
	}

	// setup auth manager used for generating and validating JWTs
	authManager := auth.NewDefaultAuthManager(conf.Server.Jwt.SecretKey, conf.Server.Jwt.AuthorizationTokenLife, conf.Server.Jwt.RefreshTokenLife)

	// a gin router to handle requests
	gin.SetMode(conf.Server.GinMode)
	var router *gin.Engine = gin.Default()
	if conf.AppMode == config.RELEASE {
		proxyString := conf.Server.TrustedProxies
		if proxyString == "" {
			panic(fmt.Errorf("server is running in %s mode and does not have any proxies trusted", config.RELEASE))
		}
		router.SetTrustedProxies(strings.Split(proxyString, ","))
	}
	routes.RegisterRoutes(router, db, encryptor, authManager)
	router.Run(fmt.Sprintf(":%s", conf.Server.Port))
}
