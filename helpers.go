package main

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func hashPassword(password string) string {
	pwd := []byte(password)
	hashedPwd, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	return string(hashedPwd)
}

func secretValidator(secret string, secret2 string) error {
	errPass := bcrypt.CompareHashAndPassword([]byte(secret), []byte(secret2))
	return errPass
}

func clientCredentialValidator(cred string, reqCred string) error {
	if cred != reqCred {
		return errors.New(ErrInvalidClientCreds)
	}
	return nil
}

func getUserByUsername(username string) (*User, error) {
	user, err := userDB.Get(username).Result()
	if err != nil {
		return nil, err
	}

	userInfo := User{}
	err = json.Unmarshal([]byte(user), &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func getTokenInfoByAccessToken(accessToken string) (*TokenInfo, error) {
	token, err := tokenDB.Get(accessToken).Result()
	if err != nil {
		return nil, err
	}

	tokenInfo := TokenInfo{}
	err = json.Unmarshal([]byte(token), &tokenInfo)
	if err != nil {
		return nil, err
	}
	return &tokenInfo, nil
}

func getRefreshTokenInfoByRefreshToken(refreshToken string) (*RefreshTokenInfo, error) {
	token, err := tokenDB.Get(refreshToken).Result()
	if err != nil {
		return nil, err
	}

	tokenInfo := RefreshTokenInfo{}
	err = json.Unmarshal([]byte(token), &tokenInfo)
	if err != nil {
		return nil, err
	}
	return &tokenInfo, nil
}

func validateRequestHeader(c *gin.Context) error {
	if c.Request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return errors.New(ErrUnsupportedContentType)
	}
	return nil
}

func validateTokenHandler(c *gin.Context) (*createTokenRequest, error) {
	err := validateRequestHeader(c)
	if err != nil {
		return nil, err
	}
	username := c.PostForm("username")
	if username == "" {
		err := errors.New(ErrInvalidUserPass)
		return nil, err
	}

	password := c.PostForm("password")
	if password == "" {
		err := errors.New(ErrInvalidUserPass)
		return nil, err
	}

	grantType := c.PostForm("grant_type")
	if grantType == "" {
		err := errors.New(ErrInvalidGrantType)
		return nil, err
	}

	clientId := c.PostForm("client_id")
	if clientId == "" {
		err := errors.New(ErrInvalidClientID)
		return nil, err
	}

	clientSecret := c.PostForm("client_secret")
	if clientSecret == "" {
		err := errors.New(ErrInvalidClientSecret)
		return nil, err
	}

	newRequest := createTokenRequest{
		Username:     username,
		Password:     password,
		GrantType:    grantType,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	return &newRequest, nil
}

func createToken(clientId string, clientSecret string, username string) (*TokenInfo, error) {
	accessToken := tokenGenerator()
	refreshToken := tokenGenerator()
	startTime := time.Now()

	newToken := TokenInfo{
		ClientId:             clientId,
		ClientSecret:         clientSecret,
		Username:             username,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpireAt:  startTime.Add(time.Second * time.Duration(AccessTokenExpire)),
		RefreshTokenExpireAt: startTime.Add(time.Second * time.Duration(RefreshTokenExpire)),
	}
	token, err := json.Marshal(newToken)
	if err != nil {
		return nil, err
	}

	err = tokenDB.Set(newToken.AccessToken, token, time.Second*time.Duration(AccessTokenExpire)).Err()
	if err != nil {
		return nil, err
	}

	newRefreshToken := RefreshTokenInfo{
		Username:     username,
		AccessToken:  accessToken,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	refreshTokenByte, err := json.Marshal(newRefreshToken)
	if err != nil {
		return nil, err
	}

	err = tokenDB.Set(refreshToken, refreshTokenByte, time.Second*time.Duration(RefreshTokenExpire)).Err()
	if err != nil {
		return nil, err
	}

	userInfo, err := getUserByUsername(username)
	if err != nil {
		return nil, err
	}
	userInfo.AccessToken = accessToken
	userInfo.RefreshToken = refreshToken

	updatedUser, err := json.Marshal(userInfo)
	if err != nil {
		return nil, err
	}

	err = userDB.Set(username, updatedUser, time.Duration(UserExpire)).Err()
	if err != nil {
		return nil, err
	}
	return &newToken, nil
}

func validateResourceHandler(c *gin.Context) (*TokenInfo, *User, error) {
	err := validateRequestHeader(c)
	if err != nil {
		return nil, nil, err
	}

	auth := c.Request.Header["Authorization"]

	if len(auth) != 1 {
		err := errors.New(ErrNoAccessToken)
		return nil, nil, err
	}

	if len(auth[0]) != len(TokenType)+1+TokenLength {
		err := errors.New(ErrNoAccessToken)
		return nil, nil, err
	}

	accessToken := strings.Split(auth[0], " ")[1]
	if len(accessToken) != TokenLength {
		err := errors.New(ErrNoAccessToken)
		return nil, nil, err
	}

	tokenInfo, err := getTokenInfoByAccessToken(accessToken)
	if err != nil {
		err := errors.New(ErrAccessTokenUnregistered)
		return nil, nil, err
	}

	refreshTokenInfo, _ := getRefreshTokenInfoByRefreshToken(accessToken)
	thisRefreshTokenInfo, _ := getTokenInfoByAccessToken(refreshTokenInfo.AccessToken)

	if thisRefreshTokenInfo.RefreshToken == accessToken {
		err := errors.New(ErrAccessTokenUnregistered)
		return nil, nil, err
	}

	if time.Now().After(tokenInfo.AccessTokenExpireAt) {
		err := errors.New(ErrAccessTokenExpired)
		return nil, nil, err
	}

	userInfo, err := getUserByUsername(tokenInfo.Username)
	if err != nil {
		err := errors.New(ErrUserNotFound)
		return nil, nil, err
	}
	return tokenInfo, userInfo, nil
}

func refreshToken(c *gin.Context, refreshToken string) (tokenInfo *TokenInfo, err error) {
	oldRefreshToken, err := getRefreshTokenInfoByRefreshToken(refreshToken)
	if err != nil {
		err := errors.New(RefreshTokenNotFound)
		return nil, err
	}

	if oldRefreshToken.AccessToken == refreshToken {
		err := errors.New(RefreshTokenNotFound)
		return nil, err
	}

	oldToken, _ := getTokenInfoByAccessToken(oldRefreshToken.AccessToken)
	if oldToken != nil {
		err = tokenDB.Del(oldToken.AccessToken).Err()
		if err != nil {
			err := errors.New(ErrCannotDeleteOldAccessToken)
			return nil, err
		}
	}

	err = tokenDB.Del(refreshToken).Err()
	if err != nil {
		err := errors.New(ErrCannotDeleteOldRefreshToken)
		return nil, err
	}

	newToken, errToken := createToken(oldRefreshToken.ClientId, oldRefreshToken.ClientSecret, oldRefreshToken.Username)
	if errToken != nil {
		err := errors.New(errToken.Error())
		return nil, err
	}
	return newToken, nil
}

func validateUserHandler(c *gin.Context) (*createUserRequest, error) {
	username := c.PostForm("username")
	if username == "" {
		err := errors.New(ErrInvalidUserPass)
		return nil, err
	}

	password := c.PostForm("password")
	if password == "" {
		err := errors.New(ErrInvalidUserPass)
		return nil, err
	}

	fullname := c.PostForm("full_name")
	if fullname == "" {
		err := errors.New(ErrInvalidFullName)
		return nil, err
	}

	npm := c.PostForm("npm")
	if npm == "" {
		err := errors.New(ErrInvalidNpm)
		return nil, err
	}

	clientId := c.PostForm("client_id")
	if clientId == "" {
		err := errors.New(ErrInvalidClientID)
		return nil, err
	}

	clientSecret := c.PostForm("client_secret")
	if clientSecret == "" {
		err := errors.New(ErrInvalidClientSecret)
		return nil, err
	}

	newRequest := createUserRequest{
		Username:     username,
		Password:     password,
		Fullname:     fullname,
		Npm:          npm,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	return &newRequest, nil
}

func createUser(userReq createUserRequest) (*User, error) {
	newUserPwd := hashPassword(userReq.Password)
	newUserClientSecret := hashPassword(userReq.ClientSecret)

	newUser := User{
		Username:     userReq.Username,
		Password:     newUserPwd,
		Fullname:     userReq.Fullname,
		Npm:          userReq.Npm,
		ClientId:     userReq.ClientId,
		ClientSecret: newUserClientSecret,
	}

	user, err := json.Marshal(newUser)
	if err != nil {
		return nil, err
	}

	err = userDB.Set(newUser.Username, user, time.Duration(UserExpire)).Err()
	if err != nil {
		return nil, err
	}

	return &newUser, nil
}
