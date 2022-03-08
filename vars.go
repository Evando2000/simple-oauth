package main

var httpStatusOk = 200
var httpStatusErrReq = 401

var ErrInvalidReq = "invalid_request"
var ErrInvalidToken = "invalid_token"
var ErrInvalidTokenDesc = "your token is invalid"
var ErrInvalidUserPass = "username or password invalid"
var ErrInvalidGrantType = "grant_type invalid"
var ErrInvalidClientID = "client_id invalid"
var ErrInvalidClientSecret = "client_secret invalid"
var ErrInvalidFullName = "full_name invalid"
var ErrInvalidNpm = "npm invalid"
var ErrInvalidClientCreds = "client credentials invalid"

var ErrUserNotFound = "user not found"
var ErrUserExisted = "user already existed"
var ErrNoAccessToken = "there is no access_token"
var ErrAccessTokenUnregistered = "your access_token is unregistered"
var ErrAccessTokenExpired = "your access_token is expired"
var RefreshTokenNotFound = "refresh_token not found"
var ErrCannotDeleteOldAccessToken = "old access_token can not be deleted"
var ErrCannotDeleteOldRefreshToken = "old refresh_token can not be deleted"
var ErrCannotCreateToken = "can not create new token"

var OneMinute = 60
var AccessTokenExpire = 5 * OneMinute
var RefreshTokenExpire = 30 * OneMinute

var TokenType = "Bearer"
var TokenLength = 40
var UserExpire = 0
