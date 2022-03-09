package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

// @Title TM1 LAW: OAuth Service
// @BasePath /tm1/oauth

// @Summary get access token and refresh token
// @Schemes
// @Description This function will create new access_token and refresh_token if existing user does not have both. It will return current access_token and refresh_token if user's access_token or refresh_token is not expired yet.
// @Tags Token
// @Accept x-www-form-urlencoded
// @Produce json
// @Param username formData string true "Please insert username" minlength(1)
// @Param password formData string true "Please insert password" minlength(1)
// @Param grant_type formData string true "Please insert grant_type" minlength(1)
// @Param client_id formData string true "Please insert client_id" minlength(1)
// @Param client_secret formData string true "Please insert client_secret" minlength(1)
// @Success 200 {object} TokenInfoResponse
// @Failure 401 {object} FailedResponse
// @Router /token [post]
func createTokenHandler(c *gin.Context) {
	newRequest, err := validateTokenHandler(c)
	if err != nil {
		failedResponseConstructor(c, err.Error())
		return
	}

	user, err := getUserByUsername(newRequest.Username)
	if err != nil {
		failedResponseConstructor(c, ErrUserNotFound)
		return
	}

	errPass := secretValidator(user.Password, newRequest.Password)
	if errPass != nil {
		failedResponseConstructor(c, ErrInvalidUserPass)
		return
	}

	errClientId := clientCredentialValidator(user.ClientId, newRequest.ClientId)
	if errClientId != nil {
		failedResponseConstructor(c, errClientId.Error())
		return
	}

	errClientSecret := secretValidator(user.ClientSecret, newRequest.ClientSecret)
	if errClientSecret != nil {
		failedResponseConstructor(c, ErrInvalidClientCreds)
		return
	}

	if user.AccessToken != "" {
		existedToken, err := getTokenInfoByAccessToken(user.AccessToken)
		if err != nil {
			newToken, err := refreshToken(c, user.RefreshToken)
			if err != nil {
				failedResponseConstructor(c, err.Error())
				return
			}
			tokenSuccessResponseConstructor(c, *newToken)
			return
		}
		if existedToken.AccessTokenExpireAt.After(time.Now()) || existedToken.RefreshTokenExpireAt.After(time.Now()) {
			tokenSuccessResponseConstructor(c, *existedToken)
			return
		} else {
			newToken, err := refreshToken(c, user.RefreshToken)
			if err != nil {
				failedResponseConstructor(c, err.Error())
				return
			}
			tokenSuccessResponseConstructor(c, *newToken)
			return
		}
	} else {
		newToken, errToken := createToken(newRequest.ClientId, newRequest.ClientSecret, newRequest.Username)
		if errToken != nil {
			failedResponseConstructor(c, errToken.Error())
			return
		}
		tokenSuccessResponseConstructor(c, *newToken)
		return
	}
}

// @Summary get resource if authorized
// @Schemes
// @Description This function will return the resource if user is authorized
// @Tags Resource
// @Accept x-www-form-urlencoded
// @Produce json
// @Param Authorization header string false "Please insert access_token"
// @Success 200 {object} TokenInfoResponse
// @Failure 401 {object} FailedResponse
// @Router /resource [post]
func getResourceHandler(c *gin.Context) {
	tokenInfo, userInfo, err := validateResourceHandler(c)
	if err != nil {
		failedResponseConstructor(c, err.Error())
		return
	}
	resourceSuccessResponseConstructor(c, *tokenInfo, *userInfo)
}

// @Summary will create new access_token and refresh_token if refresh_token is valid
// @Schemes
// @Description This function will create new access_token and refresh_token if refresh_token is still valid. If new tokens are created then old tokens will be deleted
// @Tags Token
// @Accept x-www-form-urlencoded
// @Produce json
// @Param refresh_token formData string true "Please insert refresh_token" minlength(1)
// @Success 200 {object} TokenInfoResponse
// @Failure 401 {object} FailedResponse
// @Router /token/refresh [post]
func refreshTokenHandler(c *gin.Context) {
	oldRefreshToken := c.PostForm("refresh_token")

	newToken, err := refreshToken(c, oldRefreshToken)
	if err != nil {
		failedResponseConstructor(c, err.Error())
		return
	}
	tokenSuccessResponseConstructor(c, *newToken)
}

// @Summary register new user and get access token with refresh token
// @Schemes
// @Description This function will create a new user if does not exist. It will also create user's access_token with refresh_token
// @Tags User
// @Accept x-www-form-urlencoded
// @Produce json
// @Param username formData string true "Please insert username" minlength(1)
// @Param password formData string true "Please insert password" minlength(1)
// @Param full_name formData string true "Please insert full_name" minlength(1)
// @Param npm formData string true "Please insert npm" minlength(1)
// @Param client_id formData string true "Please insert client_id" minlength(1)
// @Param client_secret formData string true "Please insert client_secret" minlength(1)
// @Success 200 {object} TokenInfoResponse
// @Failure 401 {object} FailedResponse
// @Router /user/register [post]
func createUserHandler(c *gin.Context) {
	userReq, err := validateUserHandler(c)
	if err != nil {
		failedResponseConstructor(c, err.Error())
		return
	}

	user, _ := getUserByUsername(userReq.Username)
	if user != nil {
		failedResponseConstructor(c, ErrUserExisted)
		return
	}

	newUser, err := createUser(*userReq)
	if err != nil {
		failedResponseConstructor(c, err.Error())
		return
	}

	newToken, errToken := createToken(userReq.ClientId, userReq.ClientSecret, newUser.Username)
	if errToken != nil {
		failedResponseConstructor(c, errToken.Error())
		return
	}
	tokenSuccessResponseConstructor(c, *newToken)
}
