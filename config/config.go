package config

import "time"

const (
	DEV     = "dev"
	RELEASE = "release"
)

type Config struct {
	AppMode string `envconfig:"APP_MODE" default:"dev"`
	Server  struct {
		GinMode        string `envconfig:"GIN_MODE" default:"debug"`
		Port           string `envconfig:"SERVER_PORT" default:"8080"`
		TrustedProxies string `envconfig:"TRUSTED_PROXIES"`
		Encryptor      string `envconfig:"SERVER_ENCRYPTOR" default:"default"`
		Jwt            struct {
			SecretKey              string        `envconfig:"JWT_SECRET_KEY" default:"8f4b52d0-22f9-4903-9fea-2cd3a1982356"`
			AuthorizationTokenLife time.Duration `envconfig:"JWT_AUTHORIZATION_TOKEN_LIFE" default:"1h"`
			RefreshTokenLife       time.Duration `envconfig:"JWT_REFRESH_TOKEN_LIFE" default:"2160h"` // 90 days
		}
	}
	Database struct {
		Driver           string `envconfig:"DATABASE_DRIVER" default:"sqlite3"`
		ConnectionString string `envconfig:"DATABASE_CONNECTION_STRING" default:"local_db.db"`
		Log              bool   `envconfig:"DATABASE_LOG" default:"false"`
	}
}

func (c Config) ApplyOverrides() {
	if c.AppMode == RELEASE {
		c.Server.GinMode = RELEASE
	}
}
