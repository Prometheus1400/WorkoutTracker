package database

import (
	"fmt"
	"log"
	"reflect"

	"example.com/m/v2/cmd/services/database/models"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewService creates a new database service instance
func NewGormDatabase(driver string, connectionString string, logTransactions bool) (*gorm.DB, error) {
	var logLevel logger.LogLevel
	if logTransactions {
		logLevel = logger.Info
	} else {
		logLevel = logger.Silent
	}

	cfg := &gorm.Config{
		TranslateError: true,
		Logger:         logger.Default.LogMode(logLevel),
	}

  var dialector gorm.Dialector
	switch driver {
	case "sqlite3":
    dialector = sqlite.Open(connectionString)
	case "mysql":
		dialector = mysql.Open(connectionString)
	case "postgresql":
		dialector = postgres.Open(connectionString)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}

  db, err := gorm.Open(dialector, cfg)

	if err != nil {
		return nil, err
	}

	// register new schemas in database by default
	migrateSchemasFor := []interface{}{
		models.User{},
		models.BlacklistToken{},
	}
	for _, table := range migrateSchemasFor {
		typ := reflect.TypeOf(table)
		needsToMigrate := false
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Type == reflect.TypeOf(gorm.Model{}) {
				continue
			}
			jsonName := field.Tag.Get("json")
			if !db.Migrator().HasColumn(&table, jsonName) {
				needsToMigrate = true
			}
		}
		if needsToMigrate {
			if logTransactions {
				log.Printf("migrating table %s\n", typ.Name())
			}
			db.AutoMigrate(&table)
		}
	}

	return db, nil
}
