package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func tokenSuccessResponseConstructor(c *gin.Context, newToken TokenInfo) {
	c.JSON(httpStatusOk, gin.H{
		"access_token":  newToken.AccessToken,
		"expires_in":    int(newToken.AccessTokenExpireAt.Sub(time.Now()).Seconds()),
		"token_type":    TokenType,
		"scope":         nil,
		"refresh_token": newToken.RefreshToken,
	})
}

func failedResponseConstructor(c *gin.Context, err string) {
	c.JSON(httpStatusErrReq, gin.H{
		"error":             ErrInvalidReq,
		"error_description": err,
	})
}

func resourceSuccessResponseConstructor(c *gin.Context, tokenInfo TokenInfo, userInfo User) {
	c.JSON(httpStatusOk, gin.H{
		"access_token":  tokenInfo.AccessToken,
		"client_id":     tokenInfo.ClientId,
		"user_id":       userInfo.Username,
		"full_name":     userInfo.Fullname,
		"npm":           userInfo.Npm,
		"expires":       nil,
		"refresh_token": tokenInfo.RefreshToken,
	})
}
