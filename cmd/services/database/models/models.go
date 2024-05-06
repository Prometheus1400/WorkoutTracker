package models

import "gorm.io/gorm"


type User struct {
	gorm.Model
	Username string `json:"username"`
	Email string `json:"email" gorm:"unique"`
	Password string `json:"password"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	IsAdmin bool `json:"is_admin" gorm:"default:false"`
	BlacklistTokens []BlacklistToken `json:"blacklist_tokens"`
}

type BlacklistToken struct {
	gorm.Model
	Token string `json:"token" gorm:"index"`
	UserId uint `json:"user_id"`
}