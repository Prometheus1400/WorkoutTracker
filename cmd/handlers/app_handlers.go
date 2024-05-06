package handlers

import (
	"github.com/gin-gonic/gin"
)

func Health(context *gin.Context) {
	context.JSON(200, "Everything is looking good!")
}
